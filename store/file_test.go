package store_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/masterela/mcp-authkit-go/store"
)

func newTestCipher(t *testing.T) *store.Cipher {
	t.Helper()
	c, err := store.NewCipher(randomKey(t))
	require.NoError(t, err)
	return c
}

func TestFileTokenStore_SetGetDelete(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := store.NewFileTokenStore(dir, "", newTestCipher(t))
	require.NoError(t, err)

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

func TestFileTokenStore_NamespaceIsolation(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	cipher := newTestCipher(t)

	sA, err := store.NewFileTokenStore(dir, "provider-a", cipher)
	require.NoError(t, err)
	sB, err := store.NewFileTokenStore(dir, "provider-b", cipher)
	require.NoError(t, err)

	require.NoError(t, sA.Set(ctx, "user-1", map[string]any{"token": "for-a"}))
	require.NoError(t, sB.Set(ctx, "user-1", map[string]any{"token": "for-b"}))

	vA, err := sA.Get(ctx, "user-1")
	require.NoError(t, err)
	require.Equal(t, "for-a", vA["token"])

	vB, err := sB.Get(ctx, "user-1")
	require.NoError(t, err)
	require.Equal(t, "for-b", vB["token"])
}

func TestFileTokenStore_SelfHealsOnDecryptFailure(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	cipher1 := newTestCipher(t)
	cipher2 := newTestCipher(t)

	s1, err := store.NewFileTokenStore(dir, "", cipher1)
	require.NoError(t, err)
	require.NoError(t, s1.Set(ctx, "user-1", map[string]any{"token": "abc"}))

	// Reopen with a DIFFERENT key — the on-disk file can no longer be
	// decrypted. Get must self-heal (delete + report not-found), not error.
	s2, err := store.NewFileTokenStore(dir, "", cipher2)
	require.NoError(t, err)
	v, err := s2.Get(ctx, "user-1")
	require.NoError(t, err)
	require.Nil(t, v)

	// The stale file must actually be gone.
	entries, err := os.ReadDir(filepath.Join(dir, "tokens"))
	require.NoError(t, err)
	require.Empty(t, entries)
}

func TestFilePendingStore_CreateGetPop(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := store.NewFilePendingStore(dir, newTestCipher(t))
	require.NoError(t, err)

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

func TestFilePendingStore_ExpiredEntryIsNotReturned(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := store.NewFilePendingStore(dir, newTestCipher(t))
	require.NoError(t, err)

	require.NoError(t, s.Create(ctx, "state-1", map[string]any{"sub": "user-1"}, 0))
	time.Sleep(1100 * time.Millisecond) // TTL is truncated to whole seconds

	v, err := s.Get(ctx, "state-1")
	require.NoError(t, err)
	require.Nil(t, v)
}

func TestFilePendingStore_WaitForResult_PollsUntilSetResult(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := store.NewFilePendingStore(dir, newTestCipher(t))
	require.NoError(t, err)

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

func TestFilePendingStore_WaitForResult_TimesOut(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := store.NewFilePendingStore(dir, newTestCipher(t))
	require.NoError(t, err)

	result, err := s.WaitForResult(ctx, "never-set", 0.1)
	require.NoError(t, err)
	require.Nil(t, result)
}
