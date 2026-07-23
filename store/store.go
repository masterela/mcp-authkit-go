// Package store defines the pluggable persistence abstraction used by
// the oauthprovider and credentialsprovider packages ("Leg 2"): a
// [TokenStore] for long-lived, encrypted-at-rest tokens/credentials
// keyed by OIDC subject, and a [PendingStore] for short-lived,
// encrypted, TTL-bound in-flight-flow state with a signal/wait pair used
// to synchronize a blocked tool call with an out-of-band HTTP callback.
//
// This mirrors Python mcp-authkit's mcpauthkit.store package. Three
// backends are provided: Memory, File, and Redis — see memory.go,
// file.go, and redis.go.
package store

import "context"

// TokenStore is a persistent, encrypted store for user tokens and
// credentials, keyed by OIDC "sub". It has no built-in TTL concept —
// expiry (when relevant) is caller-managed via an "expires_at" field
// inside the stored value, matching the Python original.
type TokenStore interface {
	Get(ctx context.Context, sub string) (map[string]any, error) // returns (nil, nil) if not found
	Set(ctx context.Context, sub string, value map[string]any) error
	Delete(ctx context.Context, sub string) error
}

// PendingStore is an ephemeral, encrypted store for in-flight elicitation
// state, keyed by an OAuth "state" parameter or a credentials-entry
// token. Unlike TokenStore, entries have a real TTL, and the store also
// provides a SetResult/WaitForResult signal-and-block pair — functionally
// a cross-process future-with-timeout used to synchronize a blocked tool
// call (waiting in WaitForResult) with an out-of-band HTTP callback
// (which calls SetResult once it has an outcome).
type PendingStore interface {
	Create(ctx context.Context, key string, metadata map[string]any, ttl int) error
	Get(ctx context.Context, key string) (map[string]any, error) // returns (nil, nil) if not found/expired
	Pop(ctx context.Context, key string) (map[string]any, error) // atomic get+delete
	SetResult(ctx context.Context, key string, result map[string]any, ttl int) error
	// WaitForResult blocks until SetResult is called for key or timeoutSeconds
	// elapses, whichever comes first. On success, the result is consumed
	// (removed from the store) before returning — a second call for the
	// same key will not observe it again. Returns (nil, nil) on timeout.
	WaitForResult(ctx context.Context, key string, timeoutSeconds float64) (map[string]any, error)
}
