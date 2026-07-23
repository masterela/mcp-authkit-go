package store

import (
	"fmt"
	"os"

	"github.com/redis/go-redis/v9"
)

// FactoryOptions configures [CreateStores]. Any zero-value field falls
// back to the corresponding environment variable, matching the Python
// original's env-var-driven defaults exactly.
type FactoryOptions struct {
	// Mode selects the backend: "memory" (default), "file", or "redis".
	// Falls back to the TOKEN_STORAGE_MODE env var.
	Mode string
	// FilePath is the root directory for the file backend. Falls back
	// to the FILE_STORAGE_PATH env var, default "/tmp/mcp-auth-store".
	FilePath string
	// RedisURL connects the redis backend. Falls back to the REDIS_URL
	// env var, default "redis://localhost:6379/0".
	RedisURL string
	// RedisPrefix namespaces all Redis keys. Falls back to the
	// REDIS_KEY_PREFIX env var, default "mcp:auth:".
	RedisPrefix string
	// Namespace isolates this provider's entries from others sharing
	// the same backend (e.g. multiple OAuthProvider instances) — for
	// file mode becomes a subdirectory under tokens/, for redis mode is
	// appended to the prefix.
	Namespace string
}

func envOrDefault(value, envKey, fallback string) string {
	if value != "" {
		return value
	}
	if v := os.Getenv(envKey); v != "" {
		return v
	}
	return fallback
}

// CreateStores builds a (TokenStore, PendingStore) pair for the
// configured backend. Both providers (OAuthProvider, CredentialsProvider)
// call this internally with Namespace set to their own name when not
// given explicit stores — this is the mechanism providing namespace
// isolation between multiple providers sharing the same backend.
func CreateStores(opts FactoryOptions) (TokenStore, PendingStore, error) {
	mode := envOrDefault(opts.Mode, "TOKEN_STORAGE_MODE", "memory")

	switch mode {
	case "memory":
		return NewMemoryTokenStore(), NewMemoryPendingStore(), nil

	case "file":
		cipher, err := requireEncryptionKey("file")
		if err != nil {
			return nil, nil, err
		}
		filePath := envOrDefault(opts.FilePath, "FILE_STORAGE_PATH", "/tmp/mcp-auth-store")
		tokenStore, err := NewFileTokenStore(filePath, opts.Namespace, cipher)
		if err != nil {
			return nil, nil, err
		}
		pendingStore, err := NewFilePendingStore(filePath, cipher)
		if err != nil {
			return nil, nil, err
		}
		return tokenStore, pendingStore, nil

	case "redis":
		cipher, err := requireEncryptionKey("redis")
		if err != nil {
			return nil, nil, err
		}
		redisURL := envOrDefault(opts.RedisURL, "REDIS_URL", "redis://localhost:6379/0")
		redisPrefix := envOrDefault(opts.RedisPrefix, "REDIS_KEY_PREFIX", defaultRedisKeyPrefix)

		redisOpts, err := redis.ParseURL(redisURL)
		if err != nil {
			return nil, nil, fmt.Errorf("store: parsing REDIS_URL: %w", err)
		}
		client := redis.NewClient(redisOpts)

		tokenStore := NewRedisTokenStore(client, redisPrefix, opts.Namespace, cipher)
		pendingStore := NewRedisPendingStore(client, redisPrefix, cipher)
		return tokenStore, pendingStore, nil

	default:
		return nil, nil, fmt.Errorf("store: unknown TOKEN_STORAGE_MODE %q (want memory, file, or redis)", mode)
	}
}

// requireEncryptionKey mirrors the Python original's explicit check:
// file/redis modes must have a real encryption key configured — a
// memory-mode-only ephemeral key would silently make every persisted
// value unreadable across restarts, which is exactly the failure mode
// this check exists to prevent.
func requireEncryptionKey(mode string) (*Cipher, error) {
	if os.Getenv("STORAGE_ENCRYPTION_KEY") == "" && os.Getenv("STORAGE_ENCRYPTION_KEY_PATH") == "" {
		return nil, fmt.Errorf(
			"store: TOKEN_STORAGE_MODE=%s requires STORAGE_ENCRYPTION_KEY or STORAGE_ENCRYPTION_KEY_PATH "+
				"to be set in the process environment (not just a .env file loaded by a settings library, "+
				"which some frameworks do not propagate into os.Environ-equivalent lookups)", mode)
	}
	return NewCipherFromEnv()
}
