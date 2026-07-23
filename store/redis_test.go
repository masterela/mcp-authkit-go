package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	"github.com/masterela/mcp-authkit-go/store"
)

// newTestRedisClient spins up an in-process fake Redis (miniredis) — no
// real Redis server required, mirroring the Python original's use of
// fakeredis for these same tests.
func newTestRedisClient(t *testing.T) *redis.Client {
	t.Helper()
	mr, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mr.Close)

	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func TestRedisTokenStore_SetGetDelete(t *testing.T) {
	ctx := context.Background()
	client := newTestRedisClient(t)
	s := store.NewRedisTokenStore(client, "", "", newTestCipher(t))

	v, err := s.Get(ctx, "user-1")
	require.NoError(t, err)
	require.Nil(t, v)

	require.NoError(t, s.Set(ctx, "user-1", map[string]any{"access_token": "abc"}))
	v, err = s.Get(ctx, "user-1")
	require.NoError(t, err)
	require.Equal(t, "abc", v["access_token"])

	require.NoError(t, s.Delete(ctx, "user-1"))
	v, err = s.Get(ctx, "user-1")
	require.NoError(t, err)
	require.Nil(t, v)
}

func TestRedisTokenStore_NamespaceIsolation(t *testing.T) {
	ctx := context.Background()
	client := newTestRedisClient(t)
	cipher := newTestCipher(t)

	sA := store.NewRedisTokenStore(client, "", "provider-a", cipher)
	sB := store.NewRedisTokenStore(client, "", "provider-b", cipher)

	require.NoError(t, sA.Set(ctx, "user-1", map[string]any{"token": "for-a"}))
	require.NoError(t, sB.Set(ctx, "user-1", map[string]any{"token": "for-b"}))

	vA, err := sA.Get(ctx, "user-1")
	require.NoError(t, err)
	require.Equal(t, "for-a", vA["token"])

	vB, err := sB.Get(ctx, "user-1")
	require.NoError(t, err)
	require.Equal(t, "for-b", vB["token"])
}

func TestRedisTokenStore_SelfHealsOnDecryptFailure(t *testing.T) {
	ctx := context.Background()
	client := newTestRedisClient(t)

	s1 := store.NewRedisTokenStore(client, "", "", newTestCipher(t))
	require.NoError(t, s1.Set(ctx, "user-1", map[string]any{"token": "abc"}))

	s2 := store.NewRedisTokenStore(client, "", "", newTestCipher(t)) // different key
	v, err := s2.Get(ctx, "user-1")
	require.NoError(t, err)
	require.Nil(t, v)
}

func TestRedisPendingStore_CreateGetPop(t *testing.T) {
	ctx := context.Background()
	client := newTestRedisClient(t)
	s := store.NewRedisPendingStore(client, "", newTestCipher(t))

	require.NoError(t, s.Create(ctx, "state-1", map[string]any{"sub": "user-1"}, 60))

	v, err := s.Get(ctx, "state-1")
	require.NoError(t, err)
	require.Equal(t, "user-1", v["sub"])

	v, err = s.Pop(ctx, "state-1")
	require.NoError(t, err)
	require.Equal(t, "user-1", v["sub"])

	v, err = s.Get(ctx, "state-1")
	require.NoError(t, err)
	require.Nil(t, v)
}

func TestRedisPendingStore_WaitForResult_PollsUntilSetResult(t *testing.T) {
	ctx := context.Background()
	client := newTestRedisClient(t)
	s := store.NewRedisPendingStore(client, "", newTestCipher(t))

	resultCh := make(chan map[string]any, 1)
	go func() {
		result, err := s.WaitForResult(ctx, "state-1", 5)
		require.NoError(t, err)
		resultCh <- result
	}()

	time.Sleep(50 * time.Millisecond)
	require.NoError(t, s.SetResult(ctx, "state-1", map[string]any{"sub": "user-1"}, 120))

	select {
	case result := <-resultCh:
		require.Equal(t, "user-1", result["sub"])
	case <-time.After(3 * time.Second):
		t.Fatal("WaitForResult did not return after SetResult")
	}
}

func TestRedisPendingStore_WaitForResult_TimesOut(t *testing.T) {
	ctx := context.Background()
	client := newTestRedisClient(t)
	s := store.NewRedisPendingStore(client, "", newTestCipher(t))

	result, err := s.WaitForResult(ctx, "never-set", 0.1)
	require.NoError(t, err)
	require.Nil(t, result)
}

func TestRedisPendingStore_WaitForResult_ConsumesResult(t *testing.T) {
	ctx := context.Background()
	client := newTestRedisClient(t)
	s := store.NewRedisPendingStore(client, "", newTestCipher(t))

	require.NoError(t, s.SetResult(ctx, "state-1", map[string]any{"sub": "user-1"}, 120))

	first, err := s.WaitForResult(ctx, "state-1", 1)
	require.NoError(t, err)
	require.NotNil(t, first)

	second, err := s.WaitForResult(ctx, "state-1", 0.1)
	require.NoError(t, err)
	require.Nil(t, second, "a second wait for the same key must not observe the already-consumed result")
}
