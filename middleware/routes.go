package middleware

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"
)

// WellKnownOptions configures [RegisterWellKnownRoutes].
type WellKnownOptions struct {
	// ServerBaseURL is this MCP server's own public base URL.
	ServerBaseURL string
	// IssuerURL is the OIDC issuer whose discovery document is
	// republished under this server's own issuer name.
	IssuerURL string
	// ClientID is echoed back verbatim by the /register façade.
	ClientID string
}

// RegisterWellKnownRoutes registers the OAuth/MCP well-known discovery
// endpoints and a Dynamic Client Registration (DCR) façade on mux —
// mirrors Python mcp-authkit's oauth_meta_router factory.
func RegisterWellKnownRoutes(mux *http.ServeMux, opts WellKnownOptions) {
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", func(w http.ResponseWriter, r *http.Request) {
		writeProtectedResourceMetadata(w, opts.ServerBaseURL)
	})
	mux.HandleFunc("GET /.well-known/oauth-protected-resource/{path...}", func(w http.ResponseWriter, r *http.Request) {
		writeProtectedResourceMetadata(w, opts.ServerBaseURL)
	})

	mux.HandleFunc("GET /.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		writeAuthorizationServerMetadata(r.Context(), w, opts)
	})

	mux.HandleFunc("POST /register", func(w http.ResponseWriter, r *http.Request) {
		handleRegister(w, r, opts.ClientID)
	})
}

// writeProtectedResourceMetadata publishes RFC 9728's protected-resource
// metadata document. authorization_servers MUST list this MCP server's
// OWN base URL, not the upstream OIDC issuer — the Python original
// regressed this once (listing the issuer instead) and had to revert it;
// see the port's ARCHITECTURE.md for the full history. Getting this wrong
// breaks MCP-client-driven discovery even though token validation itself
// still works, so it's easy to miss in manual testing.
func writeProtectedResourceMetadata(w http.ResponseWriter, serverBaseURL string) {
	writeJSON(w, http.StatusOK, map[string]any{
		"resource":                 serverBaseURL + "/mcp",
		"authorization_servers":    []string{serverBaseURL},
		"bearer_methods_supported": []string{"header"},
		"scopes_supported":         []string{"openid", "profile", "email"},
	})
}

type oidcDiscoveryDoc struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// writeAuthorizationServerMetadata fetches the real IdP's own discovery
// document (best-effort, short timeout) and republishes it under this
// server's own issuer name, pointing registration_endpoint at the local
// DCR façade. Falls back to Keycloak-shaped default paths if the fetch
// fails — mirrors the Python original's behavior exactly.
func writeAuthorizationServerMetadata(ctx context.Context, w http.ResponseWriter, opts WellKnownOptions) {
	doc := fetchUpstreamDiscovery(ctx, opts.IssuerURL)

	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                opts.ServerBaseURL,
		"authorization_endpoint":                doc.AuthorizationEndpoint,
		"token_endpoint":                        doc.TokenEndpoint,
		"jwks_uri":                              doc.JWKSURI,
		"registration_endpoint":                 opts.ServerBaseURL + "/register",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none"},
	})
}

func fetchUpstreamDiscovery(ctx context.Context, issuerURL string) oidcDiscoveryDoc {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, issuerURL+"/.well-known/openid-configuration", nil)
	if err == nil {
		if resp, err := http.DefaultClient.Do(req); err == nil {
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode == http.StatusOK {
				var doc oidcDiscoveryDoc
				if json.NewDecoder(resp.Body).Decode(&doc) == nil {
					return doc
				}
			}
		}
	}

	slog.WarnContext(ctx, "middleware: upstream OIDC discovery fetch failed, falling back to Keycloak-shaped default paths", "issuer_url", issuerURL)
	return oidcDiscoveryDoc{
		AuthorizationEndpoint: issuerURL + "/protocol/openid-connect/auth",
		TokenEndpoint:         issuerURL + "/protocol/openid-connect/token",
		JWKSURI:               issuerURL + "/protocol/openid-connect/certs",
	}
}

// handleRegister is a Dynamic Client Registration (RFC 7591) façade: it
// accepts any registration request and always echoes back the
// pre-registered clientID passed into RegisterWellKnownRoutes — mirrors
// the Python original, which never actually registers a new client, it
// just satisfies MCP clients that expect a DCR round-trip to succeed.
func handleRegister(w http.ResponseWriter, r *http.Request, clientID string) {
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body) // logged fields only, decode failure is non-fatal
	slog.InfoContext(r.Context(), "middleware: DCR registration request received",
		"client_name", body["client_name"], "redirect_uris", body["redirect_uris"])

	writeJSON(w, http.StatusCreated, map[string]any{
		"client_id":                  clientID,
		"client_id_issued_at":        time.Now().Unix(),
		"grant_types":                []string{"authorization_code"},
		"token_endpoint_auth_method": "none",
	})
}
