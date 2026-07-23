package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// defaultRedisKeyPrefix mirrors the Python original's default
// REDIS_KEY_PREFIX.
const defaultRedisKeyPrefix = "mcp:auth:"

func redisTokenKey(prefix, sub string) string   { return prefix + "token:" + safeName(sub) }
func redisPendingKey(prefix, key string) string { return prefix + "pending:" + safeName(key) }
func redisDoneKey(prefix, key string) string    { return prefix + "done:" + safeName(key) }

// RedisTokenStore is a TokenStore backed by Redis, encrypted at rest.
// No Redis-native TTL on token keys — expiry (when relevant) is
// caller-managed via an "expires_at" field in the stored value, exactly
// like the Memory/File backends, matching the Python original.
type RedisTokenStore struct {
	client *redis.Client
	prefix string
	cipher *Cipher
}

// NewRedisTokenStore constructs a RedisTokenStore. prefix defaults to
// "mcp:auth:" if empty; namespace, if non-empty, is appended to it.
func NewRedisTokenStore(client *redis.Client, prefix string, namespace string, cipher *Cipher) *RedisTokenStore {
	if prefix == "" {
		prefix = defaultRedisKeyPrefix
	}
	if namespace != "" {
		prefix = trimSuffixColon(prefix) + ":" + namespace + ":"
	}
	return &RedisTokenStore{client: client, prefix: prefix, cipher: cipher}
}

func trimSuffixColon(s string) string {
	for len(s) > 0 && s[len(s)-1] == ':' {
		s = s[:len(s)-1]
	}
	return s
}

// Get implements [store.TokenStore].
func (s *RedisTokenStore) Get(ctx context.Context, sub string) (map[string]any, error) {
	data, err := s.client.Get(ctx, redisTokenKey(s.prefix, sub)).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store: redis GET: %w", err)
	}
	v, err := s.cipher.Decrypt(data)
	if err != nil {
		// Self-heal, matching FileTokenStore: an entry we can no longer
		// decrypt is unusable, not a transient error.
		_ = s.client.Del(ctx, redisTokenKey(s.prefix, sub)).Err()
		return nil, nil
	}
	return v, nil
}

// Set implements [store.TokenStore].
func (s *RedisTokenStore) Set(ctx context.Context, sub string, value map[string]any) error {
	data, err := s.cipher.Encrypt(value)
	if err != nil {
		return err
	}
	return s.client.Set(ctx, redisTokenKey(s.prefix, sub), data, 0).Err()
}

// Delete implements [store.TokenStore].
func (s *RedisTokenStore) Delete(ctx context.Context, sub string) error {
	return s.client.Del(ctx, redisTokenKey(s.prefix, sub)).Err()
}

// RedisPendingStore is a PendingStore backed by Redis, encrypted at
// rest, using native Redis key expiry (SET ... EX) for TTL enforcement.
// WaitForResult polls every 500ms (Redis has no built-in blocking
// key-wait primitive suited to this one-shot signal pattern) and
// consumes the result via a pipelined GET+DEL, matching the Python
// original's atomicity guarantee against two concurrent waiters both
// observing the same result.
type RedisPendingStore struct {
	client *redis.Client
	prefix string
	cipher *Cipher
}

// NewRedisPendingStore constructs a RedisPendingStore. prefix defaults
// to "mcp:auth:" if empty.
func NewRedisPendingStore(client *redis.Client, prefix string, cipher *Cipher) *RedisPendingStore {
	if prefix == "" {
		prefix = defaultRedisKeyPrefix
	}
	return &RedisPendingStore{client: client, prefix: prefix, cipher: cipher}
}

// Create implements [store.PendingStore].
func (s *RedisPendingStore) Create(ctx context.Context, key string, metadata map[string]any, ttl int) error {
	data, err := s.cipher.Encrypt(metadata)
	if err != nil {
		return err
	}
	return s.client.Set(ctx, redisPendingKey(s.prefix, key), data, time.Duration(ttl)*time.Second).Err()
}

// Get implements [store.PendingStore].
func (s *RedisPendingStore) Get(ctx context.Context, key string) (map[string]any, error) {
	return s.getAndDecrypt(ctx, redisPendingKey(s.prefix, key))
}

func (s *RedisPendingStore) getAndDecrypt(ctx context.Context, redisKey string) (map[string]any, error) {
	data, err := s.client.Get(ctx, redisKey).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store: redis GET: %w", err)
	}
	v, err := s.cipher.Decrypt(data)
	if err != nil {
		_ = s.client.Del(ctx, redisKey).Err()
		return nil, nil
	}
	return v, nil
}

// atomicPop performs a pipelined GET+DEL: whichever caller's pipeline
// executes first observes the value and deletes it; a second concurrent
// caller's GET (within the same pipeline round-trip) returns redis.Nil
// because the key no longer has a value by the time Redis processes the
// GET, so it's the "already consumed" case — mirrors the Python
// original's race-check in wait_for_result.
func (s *RedisPendingStore) atomicPop(ctx context.Context, redisKey string) (map[string]any, error) {
	pipe := s.client.TxPipeline()
	getCmd := pipe.Get(ctx, redisKey)
	pipe.Del(ctx, redisKey)
	_, err := pipe.Exec(ctx)
	if err != nil && !errors.Is(err, redis.Nil) {
		return nil, fmt.Errorf("store: redis pipelined pop: %w", err)
	}

	data, err := getCmd.Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store: redis GET in pop: %w", err)
	}
	v, err := s.cipher.Decrypt(data)
	if err != nil {
		return nil, nil
	}
	return v, nil
}

// Pop implements [store.PendingStore].
func (s *RedisPendingStore) Pop(ctx context.Context, key string) (map[string]any, error) {
	return s.atomicPop(ctx, redisPendingKey(s.prefix, key))
}

// SetResult implements [store.PendingStore].
func (s *RedisPendingStore) SetResult(ctx context.Context, key string, result map[string]any, ttl int) error {
	data, err := s.cipher.Encrypt(result)
	if err != nil {
		return err
	}
	if ttl <= 0 {
		ttl = 120 // matches the Python original's set_result default
	}
	return s.client.Set(ctx, redisDoneKey(s.prefix, key), data, time.Duration(ttl)*time.Second).Err()
}

// WaitForResult implements [store.PendingStore].
func (s *RedisPendingStore) WaitForResult(ctx context.Context, key string, timeoutSeconds float64) (map[string]any, error) {
	deadline := time.Now().Add(time.Duration(timeoutSeconds * float64(time.Second)))
	redisKey := redisDoneKey(s.prefix, key)

	for {
		if exists, err := s.client.Exists(ctx, redisKey).Result(); err == nil && exists > 0 {
			result, err := s.atomicPop(ctx, redisKey)
			if err != nil {
				return nil, err
			}
			if result != nil {
				return result, nil
			}
			// Another waiter already consumed it in the race window
			// between Exists and atomicPop — treat as timeout, matching
			// the Python original's "someone else already consumed it"
			// handling.
			return nil, nil
		}
		if time.Now().After(deadline) {
			return nil, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(filePollInterval):
		}
	}
}
