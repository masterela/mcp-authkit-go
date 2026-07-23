// Package middleware implements MCP server session auth ("Leg 1"): an
// http.Handler-wrapping middleware that validates a Bearer JWT on every
// request (except explicitly open paths) via a [jwtvalidator.Validator],
// and the OIDC/MCP well-known endpoints an MCP client needs to discover
// how to authenticate.
//
// This mirrors Python mcp-authkit's mcpauthkit.auth_middleware and
// mcpauthkit.auth_routes modules.
package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/masterela/mcp-authkit-go/jwtvalidator"
)

type contextKey struct{}

var userContextKey = contextKey{}

// User is the fixed-shape claims value the middleware writes into the
// request context on successful validation — mirrors the Python
// original's fixed-shape dict written into its ContextVar.
type User struct {
	Sub               string
	PreferredUsername string
	Email             string
	Name              string
	Issuer            string
	Claims            map[string]any // full claim set, for anything not covered by the named fields above
}

// UserFromContext returns the validated user for the current request, and
// whether one was present (false if the request never passed through the
// middleware, or the middleware treated the path as open).
func UserFromContext(ctx context.Context) (User, bool) {
	u, ok := ctx.Value(userContextKey).(User)
	return u, ok
}

// WithUser returns a copy of ctx carrying u, retrievable via
// [UserFromContext]. Exported for other mcp-authkit-go packages (and
// tests, both within this module and downstream) that need to construct
// a context as if it had already passed through this middleware — e.g.
// oauthprovider/credentialsprovider tests exercising RequireToken/
// RequireCredentials without standing up a full HTTP + JWT round-trip.
func WithUser(ctx context.Context, u User) context.Context {
	return context.WithValue(ctx, userContextKey, u)
}

// Options configures [New].
type Options struct {
	// Validator performs the actual JWT/JWKS verification.
	Validator *jwtvalidator.Validator
	// IssuerURL is the OIDC issuer to validate tokens against.
	IssuerURL string
	// ServerBaseURL is this MCP server's own public base URL — used in
	// the WWW-Authenticate challenge's resource_metadata pointer.
	ServerBaseURL string
	// OpenPaths lists path prefixes exempt from auth (e.g.
	// "/.well-known", "/health", "/register"). Matched via
	// strings.HasPrefix, mirroring the Python original's _is_open.
	OpenPaths []string
}

// New returns middleware that validates a Bearer JWT on every request
// except OPTIONS requests and paths matching one of opts.OpenPaths.
func New(opts Options) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodOptions || isOpenPath(r.URL.Path, opts.OpenPaths) {
				next.ServeHTTP(w, r)
				return
			}

			token, ok := extractBearerToken(r)
			if !ok {
				writeUnauthorized(w, opts.ServerBaseURL, "")
				return
			}

			claims, reason, err := opts.Validator.Validate(r.Context(), token, opts.IssuerURL)
			if err != nil {
				if reason == jwtvalidator.FailReasonExpired {
					writeTokenExpired(w, opts.ServerBaseURL)
				} else {
					writeUnauthorized(w, opts.ServerBaseURL, "invalid_token")
				}
				return
			}

			user := userFromClaims(claims)
			ctx := context.WithValue(r.Context(), userContextKey, user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func isOpenPath(path string, openPaths []string) bool {
	for _, prefix := range openPaths {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func extractBearerToken(r *http.Request) (string, bool) {
	header := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return "", false
	}
	token := strings.TrimPrefix(header, prefix)
	if token == "" {
		return "", false
	}
	return token, true
}

func userFromClaims(claims map[string]any) User {
	sub, _ := claims["sub"].(string)
	preferredUsername, _ := claims["preferred_username"].(string)
	if sub == "" {
		if preferredUsername != "" {
			sub = preferredUsername
		} else {
			sub = "unknown"
		}
	}
	email, _ := claims["email"].(string)
	name, _ := claims["name"].(string)
	issuer, _ := claims["iss"].(string)
	return User{
		Sub:               sub,
		PreferredUsername: preferredUsername,
		Email:             email,
		Name:              name,
		Issuer:            issuer,
		Claims:            claims,
	}
}

func writeUnauthorized(w http.ResponseWriter, serverBaseURL string, errorCode string) {
	challenge := fmt.Sprintf(`Bearer realm=%q, resource_metadata=%q`,
		serverBaseURL+"/mcp", serverBaseURL+"/.well-known/oauth-protected-resource")
	if errorCode != "" {
		challenge += fmt.Sprintf(`, error=%q`, errorCode)
	}
	w.Header().Set("WWW-Authenticate", challenge)
	w.WriteHeader(http.StatusUnauthorized)
}

func writeTokenExpired(w http.ResponseWriter, serverBaseURL string) {
	// RFC 6750 §3.1-style challenge: error + error_description alongside
	// the same realm/resource_metadata pointer used for a generic
	// unauthorized response — mirrors the Python original's
	// _token_expired().
	challenge := fmt.Sprintf(
		`Bearer realm=%q, resource_metadata=%q, error="invalid_token", error_description="The access token expired"`,
		serverBaseURL+"/mcp", serverBaseURL+"/.well-known/oauth-protected-resource")
	w.Header().Set("WWW-Authenticate", challenge)
	w.WriteHeader(http.StatusUnauthorized)
}

// writeJSON is a small shared helper used by the well-known routes in
// routes.go.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
