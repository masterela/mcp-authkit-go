package middleware_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/masterela/mcp-authkit-go/middleware"
)

const serverBaseURL = "https://mcp.example.com"

func newWellKnownMux(t *testing.T, issuerURL string) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()
	middleware.RegisterWellKnownRoutes(mux, middleware.WellKnownOptions{
		ServerBaseURL: serverBaseURL,
		IssuerURL:     issuerURL,
		ClientID:      "test-client-id",
	})
	return mux
}

// TestProtectedResourceMetadata_AuthorizationServersListsOwnBaseURL is a
// regression test for a real historical bug in the Python original: this
// field must list the MCP SERVER's own base URL, not the upstream OIDC
// issuer. Getting this wrong breaks MCP-client-driven discovery even
// though token validation itself still works — see routes.go's doc
// comment on writeProtectedResourceMetadata for the full history.
func TestProtectedResourceMetadata_AuthorizationServersListsOwnBaseURL(t *testing.T) {
	mux := newWellKnownMux(t, "https://issuer.example.com/realms/test")

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var body map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))

	authServers, ok := body["authorization_servers"].([]any)
	require.True(t, ok)
	require.Equal(t, []any{serverBaseURL}, authServers)
	require.NotContains(t, authServers, "https://issuer.example.com/realms/test")
	require.Equal(t, serverBaseURL+"/mcp", body["resource"])
}

func TestAuthorizationServerMetadata_FallsBackToKeycloakPathsOnFetchFailure(t *testing.T) {
	// An unreachable issuer URL forces the fallback path.
	mux := newWellKnownMux(t, "http://127.0.0.1:1")

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var body map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))

	require.Equal(t, serverBaseURL, body["issuer"])
	require.Equal(t, "http://127.0.0.1:1/protocol/openid-connect/auth", body["authorization_endpoint"])
	require.Equal(t, "http://127.0.0.1:1/protocol/openid-connect/token", body["token_endpoint"])
	require.Equal(t, serverBaseURL+"/register", body["registration_endpoint"])
}

func TestAuthorizationServerMetadata_RepublishesRealIssuerEndpoints(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"authorization_endpoint": "https://real-idp.example.com/auth",
			"token_endpoint":         "https://real-idp.example.com/token",
			"jwks_uri":               "https://real-idp.example.com/jwks",
		})
	}))
	t.Cleanup(upstream.Close)

	mux := newWellKnownMux(t, upstream.URL)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var body map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	require.Equal(t, serverBaseURL, body["issuer"], "issuer must be republished as this server's own base URL, not the upstream's")
	require.Equal(t, "https://real-idp.example.com/auth", body["authorization_endpoint"])
	require.Equal(t, "https://real-idp.example.com/token", body["token_endpoint"])
}

func TestRegister_AlwaysEchoesPreRegisteredClientID(t *testing.T) {
	mux := newWellKnownMux(t, "https://issuer.example.com")

	body := `{"client_name":"some-mcp-client","redirect_uris":["https://client.example.com/callback"]}`
	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	require.Equal(t, http.StatusCreated, rec.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.Equal(t, "test-client-id", resp["client_id"])
	require.Equal(t, "none", resp["token_endpoint_auth_method"])
}
