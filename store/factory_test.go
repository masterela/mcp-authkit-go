package store_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/masterela/mcp-authkit-go/store"
)

func TestCreateStores_DefaultsToMemory(t *testing.T) {
	t.Setenv("TOKEN_STORAGE_MODE", "")

	tokenStore, pendingStore, err := store.CreateStores(store.FactoryOptions{})
	require.NoError(t, err)
	require.IsType(t, &store.MemoryTokenStore{}, tokenStore)
	require.IsType(t, &store.MemoryPendingStore{}, pendingStore)
}

func TestCreateStores_ExplicitMemoryMode(t *testing.T) {
	tokenStore, pendingStore, err := store.CreateStores(store.FactoryOptions{Mode: "memory"})
	require.NoError(t, err)
	require.IsType(t, &store.MemoryTokenStore{}, tokenStore)
	require.IsType(t, &store.MemoryPendingStore{}, pendingStore)
}

func TestCreateStores_FileModeRequiresEncryptionKey(t *testing.T) {
	t.Setenv("STORAGE_ENCRYPTION_KEY", "")
	t.Setenv("STORAGE_ENCRYPTION_KEY_PATH", "")

	_, _, err := store.CreateStores(store.FactoryOptions{Mode: "file", FilePath: t.TempDir()})
	require.Error(t, err)
	require.Contains(t, err.Error(), "STORAGE_ENCRYPTION_KEY")
}

func TestCreateStores_FileModeWithEncryptionKeySucceeds(t *testing.T) {
	t.Setenv("STORAGE_ENCRYPTION_KEY", "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=") // 32 bytes, base64
	tokenStore, pendingStore, err := store.CreateStores(store.FactoryOptions{Mode: "file", FilePath: t.TempDir()})
	require.NoError(t, err)
	require.IsType(t, &store.FileTokenStore{}, tokenStore)
	require.IsType(t, &store.FilePendingStore{}, pendingStore)
}

func TestCreateStores_RedisModeRequiresEncryptionKey(t *testing.T) {
	t.Setenv("STORAGE_ENCRYPTION_KEY", "")
	t.Setenv("STORAGE_ENCRYPTION_KEY_PATH", "")

	_, _, err := store.CreateStores(store.FactoryOptions{Mode: "redis"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "STORAGE_ENCRYPTION_KEY")
}

func TestCreateStores_UnknownModeReturnsError(t *testing.T) {
	_, _, err := store.CreateStores(store.FactoryOptions{Mode: "carrier-pigeon"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "carrier-pigeon")
}

func TestCreateStores_ModeFromEnvVar(t *testing.T) {
	t.Setenv("TOKEN_STORAGE_MODE", "memory")
	tokenStore, _, err := store.CreateStores(store.FactoryOptions{})
	require.NoError(t, err)
	require.IsType(t, &store.MemoryTokenStore{}, tokenStore)
}
