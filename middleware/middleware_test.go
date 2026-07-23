package middleware_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/require"

	"github.com/masterela/mcp-authkit-go/jwtvalidator"
	"github.com/masterela/mcp-authkit-go/middleware"
)

type testIdP struct {
	server     *httptest.Server
	privateKey *rsa.PrivateKey
	kid        string
}

func newTestIdP(t *testing.T) *testIdP {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	idp := &testIdP{privateKey: privateKey, kid: "test-key-1"}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":   "http://" + r.Host,
			"jwks_uri": "http://" + r.Host + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		pubKey, err := jwk.PublicKeyOf(idp.privateKey)
		require.NoError(t, err)
		require.NoError(t, pubKey.Set(jwk.KeyIDKey, idp.kid))
		require.NoError(t, pubKey.Set(jwk.AlgorithmKey, jwa.RS256()))
		set := jwk.NewSet()
		require.NoError(t, set.AddKey(pubKey))
		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(set))
	})

	idp.server = httptest.NewServer(mux)
	t.Cleanup(idp.server.Close)
	return idp
}

func (idp *testIdP) issuerURL() string { return idp.server.URL }

func (idp *testIdP) mintToken(t *testing.T, claims map[string]any, expiresIn time.Duration) string {
	t.Helper()
	builder := jwt.NewBuilder().Issuer(idp.issuerURL()).IssuedAt(time.Now()).Expiration(time.Now().Add(expiresIn))
	for k, v := range claims {
		builder = builder.Claim(k, v)
	}
	tok, err := builder.Build()
	require.NoError(t, err)
	privKey, err := jwk.Import(idp.privateKey)
	require.NoError(t, err)
	require.NoError(t, privKey.Set(jwk.KeyIDKey, idp.kid))
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256(), privKey))
	require.NoError(t, err)
	return string(signed)
}

func newTestMiddleware(t *testing.T, idp *testIdP, openPaths ...string) func(http.Handler) http.Handler {
	t.Helper()
	ctx := context.Background()
	v, err := jwtvalidator.New(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = v.Shutdown(ctx) })

	return middleware.New(middleware.Options{
		Validator:     v,
		IssuerURL:     idp.issuerURL(),
		ServerBaseURL: "https://mcp.example.com",
		OpenPaths:     openPaths,
	})
}

func TestMiddleware_MissingAuthHeader_Returns401(t *testing.T) {
	idp := newTestIdP(t)
	mw := newTestMiddleware(t, idp)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not be called")
	}))

	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusUnauthorized, rec.Code)
	require.Contains(t, rec.Header().Get("WWW-Authenticate"), "Bearer")
}

func TestMiddleware_ValidToken_CallsNextWithUserInContext(t *testing.T) {
	idp := newTestIdP(t)
	mw := newTestMiddleware(t, idp)
	token := idp.mintToken(t, map[string]any{"sub": "user-1", "preferred_username": "bob"}, time.Hour)

	var gotUser middleware.User
	var gotOK bool
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUser, gotOK = middleware.UserFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.True(t, gotOK)
	require.Equal(t, "user-1", gotUser.Sub)
	require.Equal(t, "bob", gotUser.PreferredUsername)
}

func TestMiddleware_ExpiredToken_Returns401WithInvalidTokenError(t *testing.T) {
	idp := newTestIdP(t)
	mw := newTestMiddleware(t, idp)
	token := idp.mintToken(t, map[string]any{"sub": "user-1"}, -time.Hour)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not be called")
	}))

	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusUnauthorized, rec.Code)
	require.Contains(t, rec.Header().Get("WWW-Authenticate"), "invalid_token")
}

func TestMiddleware_OpenPath_BypassesAuth(t *testing.T) {
	idp := newTestIdP(t)
	mw := newTestMiddleware(t, idp, "/.well-known", "/health")

	called := false
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.True(t, called)
}

func TestMiddleware_OptionsRequest_BypassesAuth(t *testing.T) {
	idp := newTestIdP(t)
	mw := newTestMiddleware(t, idp)

	called := false
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodOptions, "/mcp", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.True(t, called)
}

func TestMiddleware_MalformedAuthHeader_Returns401(t *testing.T) {
	idp := newTestIdP(t)
	mw := newTestMiddleware(t, idp)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not be called")
	}))

	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	req.Header.Set("Authorization", "NotBearer sometoken")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusUnauthorized, rec.Code)
}
