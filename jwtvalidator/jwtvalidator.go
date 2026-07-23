// Package jwtvalidator implements stateless OIDC/JWKS-based JWT
// verification for MCP server session auth ("Leg 1"). It fetches and
// caches an issuer's OpenID Connect discovery document and JWKS via
// [jwk.Cache], then verifies bearer tokens against the cached key set.
//
// This mirrors the Python mcp-authkit's mcpauthkit.jwt_validator module:
// same two-step discovery-then-JWKS-fetch flow, same issuer-claim check,
// same restricted signing-algorithm allow-list. Unlike the Python
// original (which hand-rolls a TTL cache keyed by issuer/JWKS URL), this
// package delegates caching to jwx's own [jwk.Cache], which handles
// refresh-on-expiry and backoff internally.
package jwtvalidator

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// FailReason classifies why token validation failed, so callers (e.g. the
// middleware) can choose the right WWW-Authenticate response — mirrors
// Python's JwtFailReason enum.
type FailReason int

const (
	// FailReasonInvalid covers any verification failure other than expiry:
	// bad signature, malformed token, disallowed algorithm, issuer mismatch.
	FailReasonInvalid FailReason = iota
	// FailReasonExpired indicates the token's exp claim is in the past.
	FailReasonExpired
)

// allowedAlgorithms mirrors the Python validator's _ALLOWED_ALGORITHMS
// allow-list: only asymmetric signing algorithms suitable for a
// third-party-issued bearer token are accepted.
var allowedAlgorithms = map[string]bool{
	"RS256": true, "RS384": true, "RS512": true,
	"PS256": true, "PS384": true, "PS512": true,
	"ES256": true, "ES384": true, "ES512": true,
	"EdDSA": true,
}

type oidcConfig struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
}

// Validator fetches and caches an issuer's OIDC discovery document and
// JWKS, verifying bearer tokens against them. A Validator is safe for
// concurrent use and should be constructed once per issuer and reused —
// it owns a [jwk.Cache] with its own background refresh goroutine.
type Validator struct {
	httpClient *http.Client
	cache      *jwk.Cache

	mu          sync.Mutex
	oidcConfigs map[string]oidcConfig // issuerURL -> discovery doc, fetched once per issuer
}

// Option configures a [Validator].
type Option func(*Validator)

// WithHTTPClient overrides the http.Client used for OIDC discovery and
// JWKS fetches (e.g. to inject a custom TLS config for a corporate MITM
// proxy, mirroring the Python original's http_verify parameter).
func WithHTTPClient(client *http.Client) Option {
	return func(v *Validator) { v.httpClient = client }
}

// WithTLSConfig is a convenience wrapper around WithHTTPClient for the
// common case of only needing to override the TLS config.
func WithTLSConfig(cfg *tls.Config) Option {
	return func(v *Validator) {
		v.httpClient = &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
	}
}

// New constructs a Validator. The returned Validator's background JWKS
// refresh loop runs for the lifetime of ctx — callers should pass a
// long-lived context (e.g. the server's own lifecycle context), not a
// short-lived per-request one.
func New(ctx context.Context, opts ...Option) (*Validator, error) {
	v := &Validator{
		httpClient:  http.DefaultClient,
		oidcConfigs: make(map[string]oidcConfig),
	}
	for _, opt := range opts {
		opt(v)
	}

	// jwk.NewCache requires an unstarted httprc.Client — it starts it
	// internally and owns its lifecycle from here on.
	httprcClient := httprc.NewClient(httprc.WithHTTPClient(v.httpClient))
	cache, err := jwk.NewCache(ctx, httprcClient)
	if err != nil {
		return nil, fmt.Errorf("jwtvalidator: creating JWKS cache: %w", err)
	}
	v.cache = cache
	return v, nil
}

// getOIDCConfig fetches and caches (in-process, for the lifetime of the
// Validator) the issuer's /.well-known/openid-configuration document.
func (v *Validator) getOIDCConfig(ctx context.Context, issuerURL string) (oidcConfig, error) {
	v.mu.Lock()
	if cfg, ok := v.oidcConfigs[issuerURL]; ok {
		v.mu.Unlock()
		return cfg, nil
	}
	v.mu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, issuerURL+"/.well-known/openid-configuration", nil)
	if err != nil {
		return oidcConfig{}, err
	}
	resp, err := v.httpClient.Do(req)
	if err != nil {
		return oidcConfig{}, fmt.Errorf("jwtvalidator: fetching OIDC config: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return oidcConfig{}, fmt.Errorf("jwtvalidator: OIDC discovery returned status %d", resp.StatusCode)
	}

	var cfg oidcConfig
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		return oidcConfig{}, fmt.Errorf("jwtvalidator: decoding OIDC config: %w", err)
	}
	if cfg.JWKSURI == "" {
		return oidcConfig{}, fmt.Errorf("jwtvalidator: OIDC config has no jwks_uri")
	}

	v.mu.Lock()
	v.oidcConfigs[issuerURL] = cfg
	v.mu.Unlock()
	return cfg, nil
}

// ensureRegistered registers the JWKS URL with the cache on first use.
// jwk.Cache.Register is idempotent-safe to call repeatedly (it's a no-op
// if already registered), so no separate "have we registered" tracking
// is needed beyond what the cache itself does.
func (v *Validator) ensureRegistered(ctx context.Context, jwksURI string) error {
	if v.cache.IsRegistered(ctx, jwksURI) {
		return nil
	}
	return v.cache.Register(ctx, jwksURI)
}

// Validate verifies a bearer token's signature against the issuer's JWKS
// and checks the "iss" claim matches the issuer's own discovery document
// (only when that document declares a non-empty issuer, matching the
// Python original's lenient behavior). Returns the token's claims as a
// map on success.
func (v *Validator) Validate(ctx context.Context, token string, issuerURL string) (map[string]any, FailReason, error) {
	// Checked before any verification, so a disallowed algorithm (notably
	// "none") is rejected outright rather than reaching the verifier —
	// mirrors the Python original's allow-list check on the unverified
	// header, done first as defense-in-depth.
	if err := checkAlgorithm(token); err != nil {
		return nil, FailReasonInvalid, err
	}

	cfg, err := v.getOIDCConfig(ctx, issuerURL)
	if err != nil {
		return nil, FailReasonInvalid, err
	}

	if err := v.ensureRegistered(ctx, cfg.JWKSURI); err != nil {
		return nil, FailReasonInvalid, fmt.Errorf("jwtvalidator: registering JWKS: %w", err)
	}
	keySet, err := v.cache.Lookup(ctx, cfg.JWKSURI)
	if err != nil {
		return nil, FailReasonInvalid, fmt.Errorf("jwtvalidator: fetching JWKS: %w", err)
	}

	parsed, err := jwt.Parse([]byte(token), jwt.WithKeySet(keySet), jwt.WithValidate(true))
	if err != nil {
		if errors.Is(err, jwt.TokenExpiredError()) {
			return nil, FailReasonExpired, err
		}
		return nil, FailReasonInvalid, fmt.Errorf("jwtvalidator: verifying token: %w", err)
	}

	// Audience is intentionally not verified here, matching the Python
	// original — callers that need audience checks apply them themselves
	// against the returned claims map.
	if cfg.Issuer != "" {
		if iss, _ := parsed.Issuer(); iss != cfg.Issuer {
			return nil, FailReasonInvalid, fmt.Errorf("jwtvalidator: issuer mismatch: token has %q, expected %q", iss, cfg.Issuer)
		}
	}

	claims, err := tokenToMap(parsed)
	if err != nil {
		return nil, FailReasonInvalid, err
	}
	return claims, 0, nil
}

// checkAlgorithm inspects the token's unverified protected header and
// rejects any signing algorithm not in allowedAlgorithms — in particular
// this rejects the "none" algorithm before any verification is attempted.
func checkAlgorithm(token string) error {
	msg, err := jws.Parse([]byte(token))
	if err != nil {
		return fmt.Errorf("jwtvalidator: parsing token header: %w", err)
	}
	sigs := msg.Signatures()
	if len(sigs) == 0 {
		return fmt.Errorf("jwtvalidator: token has no signatures")
	}
	alg, ok := sigs[0].ProtectedHeaders().Algorithm()
	if !ok {
		return fmt.Errorf("jwtvalidator: token header has no alg")
	}
	if !allowedAlgorithms[alg.String()] {
		return fmt.Errorf("jwtvalidator: disallowed signing algorithm %q", alg.String())
	}
	return nil
}

// tokenToMap flattens a parsed jwt.Token into a plain map, mirroring the
// fixed-shape dict the Python original extracts from python-jose's
// decode() result — callers read out "sub", "preferred_username", etc.
// via plain map indexing rather than jwx's typed getters.
func tokenToMap(tok jwt.Token) (map[string]any, error) {
	claims := make(map[string]any, len(tok.Keys()))
	for _, key := range tok.Keys() {
		var v any
		if err := tok.Get(key, &v); err != nil {
			return nil, fmt.Errorf("jwtvalidator: reading claim %q: %w", key, err)
		}
		claims[key] = v
	}
	return claims, nil
}

// Shutdown stops the Validator's background JWKS refresh loop. Call this
// when the Validator is no longer needed (e.g. server shutdown).
func (v *Validator) Shutdown(ctx context.Context) error {
	return v.cache.Shutdown(ctx)
}
