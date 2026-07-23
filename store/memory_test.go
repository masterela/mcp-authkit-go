package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/masterela/mcp-authkit-go/store"
)

func TestMemoryTokenStore_SetGetDelete(t *testing.T) {
	ctx := context.Background()
	s := store.NewMemoryTokenStore()

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

func TestMemoryPendingStore_CreateGetPop(t *testing.T) {
	ctx := context.Background()
	s := store.NewMemoryPendingStore()

	require.NoError(t, s.Create(ctx, "state-1", map[string]any{"sub": "user-1"}, 60))

	v, err := s.Get(ctx, "state-1")
	require.NoError(t, err)
	require.Equal(t, "user-1", v["sub"])

	v, err = s.Pop(ctx, "state-1")
	require.NoError(t, err)
	require.Equal(t, "user-1", v["sub"])

	// popped — a second Get must return nil, not the stale entry.
	v, err = s.Get(ctx, "state-1")
	require.NoError(t, err)
	require.Nil(t, v)
}

func TestMemoryPendingStore_ExpiredEntryIsNotReturned(t *testing.T) {
	ctx := context.Background()
	s := store.NewMemoryPendingStore()

	require.NoError(t, s.Create(ctx, "state-1", map[string]any{"sub": "user-1"}, 0))
	time.Sleep(10 * time.Millisecond)

	v, err := s.Get(ctx, "state-1")
	require.NoError(t, err)
	require.Nil(t, v)
}

func TestMemoryPendingStore_WaitForResult_SignaledBeforeWait(t *testing.T) {
	ctx := context.Background()
	s := store.NewMemoryPendingStore()

	require.NoError(t, s.SetResult(ctx, "state-1", map[string]any{"sub": "user-1"}, 120))

	result, err := s.WaitForResult(ctx, "state-1", 1)
	require.NoError(t, err)
	require.Equal(t, "user-1", result["sub"])
}

func TestMemoryPendingStore_WaitForResult_SignaledAfterWaitStarts(t *testing.T) {
	ctx := context.Background()
	s := store.NewMemoryPendingStore()

	resultCh := make(chan map[string]any, 1)
	go func() {
		result, err := s.WaitForResult(ctx, "state-1", 5)
		require.NoError(t, err)
		resultCh <- result
	}()

	time.Sleep(20 * time.Millisecond) // ensure WaitForResult is actually blocked before signaling
	require.NoError(t, s.SetResult(ctx, "state-1", map[string]any{"sub": "user-1"}, 120))

	select {
	case result := <-resultCh:
		require.Equal(t, "user-1", result["sub"])
	case <-time.After(2 * time.Second):
		t.Fatal("WaitForResult did not return after SetResult")
	}
}

func TestMemoryPendingStore_WaitForResult_TimesOut(t *testing.T) {
	ctx := context.Background()
	s := store.NewMemoryPendingStore()

	start := time.Now()
	result, err := s.WaitForResult(ctx, "never-set", 0.05)
	require.NoError(t, err)
	require.Nil(t, result)
	require.Less(t, time.Since(start), time.Second)
}

func TestMemoryPendingStore_WaitForResult_ConsumesResult(t *testing.T) {
	ctx := context.Background()
	s := store.NewMemoryPendingStore()

	require.NoError(t, s.SetResult(ctx, "state-1", map[string]any{"sub": "user-1"}, 120))

	first, err := s.WaitForResult(ctx, "state-1", 1)
	require.NoError(t, err)
	require.NotNil(t, first)

	second, err := s.WaitForResult(ctx, "state-1", 0.05)
	require.NoError(t, err)
	require.Nil(t, second, "a second wait for the same key must not observe the already-consumed result")
}
