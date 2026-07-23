package jwtvalidator_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/require"

	"github.com/masterela/mcp-authkit-go/jwtvalidator"
)

// testIdP spins up a fake OIDC issuer (discovery doc + JWKS endpoint)
// backed by a single RSA keypair, used to mint and verify test tokens
// without any real network dependency.
type testIdP struct {
	server     *httptest.Server
	privateKey *rsa.PrivateKey
	kid        string
}

func newTestIdP(t *testing.T, issuerOverride string) *testIdP {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	idp := &testIdP{privateKey: privateKey, kid: "test-key-1"}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		issuer := issuerOverride
		if issuer == "" {
			issuer = "http://" + r.Host
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":   issuer,
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

func (idp *testIdP) issuerURL() string {
	return idp.server.URL
}

func (idp *testIdP) mintToken(t *testing.T, claims map[string]any, expiresIn time.Duration) string {
	t.Helper()

	builder := jwt.NewBuilder().
		Issuer(idp.issuerURL()).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(expiresIn))
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

func TestValidate_Success(t *testing.T) {
	ctx := context.Background()
	idp := newTestIdP(t, "")

	v, err := jwtvalidator.New(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = v.Shutdown(ctx) })

	token := idp.mintToken(t, map[string]any{"sub": "user-123", "preferred_username": "alice"}, time.Hour)

	claims, reason, err := v.Validate(ctx, token, idp.issuerURL())
	require.NoError(t, err)
	require.Equal(t, jwtvalidator.FailReason(0), reason)
	require.Equal(t, "user-123", claims["sub"])
	require.Equal(t, "alice", claims["preferred_username"])
}

func TestValidate_ExpiredToken(t *testing.T) {
	ctx := context.Background()
	idp := newTestIdP(t, "")

	v, err := jwtvalidator.New(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = v.Shutdown(ctx) })

	token := idp.mintToken(t, map[string]any{"sub": "user-123"}, -time.Hour)

	_, reason, err := v.Validate(ctx, token, idp.issuerURL())
	require.Error(t, err)
	require.Equal(t, jwtvalidator.FailReasonExpired, reason)
}

func TestValidate_WrongIssuerInDiscoveryDoc(t *testing.T) {
	ctx := context.Background()
	// The discovery doc declares a different issuer than the one the
	// server is actually reachable at — must be rejected.
	idp := newTestIdP(t, "https://not-the-real-issuer.example.com")

	v, err := jwtvalidator.New(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = v.Shutdown(ctx) })

	token := idp.mintToken(t, map[string]any{"sub": "user-123"}, time.Hour)

	_, reason, err := v.Validate(ctx, token, idp.issuerURL())
	require.Error(t, err)
	require.Equal(t, jwtvalidator.FailReasonInvalid, reason)
}

func TestValidate_TamperedSignature(t *testing.T) {
	ctx := context.Background()
	idp := newTestIdP(t, "")

	v, err := jwtvalidator.New(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = v.Shutdown(ctx) })

	token := idp.mintToken(t, map[string]any{"sub": "user-123"}, time.Hour)
	tampered := token[:len(token)-4] + "abcd"

	_, reason, err := v.Validate(ctx, tampered, idp.issuerURL())
	require.Error(t, err)
	require.Equal(t, jwtvalidator.FailReasonInvalid, reason)
}

func TestValidate_RejectsNoneAlgorithm(t *testing.T) {
	ctx := context.Background()
	idp := newTestIdP(t, "")

	v, err := jwtvalidator.New(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = v.Shutdown(ctx) })

	// Hand-build an unsigned "alg: none" token — the classic JWT bypass.
	unsignedHeader := `{"alg":"none","typ":"JWT"}`
	unsignedPayload := fmt.Sprintf(`{"sub":"attacker","iss":%q,"exp":%d}`, idp.issuerURL(), time.Now().Add(time.Hour).Unix())
	enc := base64.RawURLEncoding.EncodeToString
	noneToken := enc([]byte(unsignedHeader)) + "." + enc([]byte(unsignedPayload)) + "."

	_, reason, err := v.Validate(ctx, noneToken, idp.issuerURL())
	require.Error(t, err)
	require.Equal(t, jwtvalidator.FailReasonInvalid, reason)
}
