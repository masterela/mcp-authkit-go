package store_test

import (
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/masterela/mcp-authkit-go/store"
)

func randomKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	return key
}

func TestCipher_EncryptDecrypt_RoundTrips(t *testing.T) {
	c, err := store.NewCipher(randomKey(t))
	require.NoError(t, err)

	original := map[string]any{"access_token": "secret-value", "expires_at": float64(1234567890)}
	ciphertext, err := c.Encrypt(original)
	require.NoError(t, err)

	decrypted, err := c.Decrypt(ciphertext)
	require.NoError(t, err)
	require.Equal(t, original, decrypted)
}

func TestCipher_DifferentKeys_CannotDecryptEachOther(t *testing.T) {
	c1, err := store.NewCipher(randomKey(t))
	require.NoError(t, err)
	c2, err := store.NewCipher(randomKey(t))
	require.NoError(t, err)

	ciphertext, err := c1.Encrypt(map[string]any{"secret": "value"})
	require.NoError(t, err)

	_, err = c2.Decrypt(ciphertext)
	require.Error(t, err)
}

func TestCipher_TamperedCiphertext_FailsToDecrypt(t *testing.T) {
	c, err := store.NewCipher(randomKey(t))
	require.NoError(t, err)

	ciphertext, err := c.Encrypt(map[string]any{"secret": "value"})
	require.NoError(t, err)

	tampered := append([]byte{}, ciphertext...)
	tampered[len(tampered)-1] ^= 0xFF

	_, err = c.Decrypt(tampered)
	require.Error(t, err)
}

func TestCipher_TwoEncryptionsOfSameValueProduceDifferentCiphertext(t *testing.T) {
	c, err := store.NewCipher(randomKey(t))
	require.NoError(t, err)

	value := map[string]any{"secret": "value"}
	ct1, err := c.Encrypt(value)
	require.NoError(t, err)
	ct2, err := c.Encrypt(value)
	require.NoError(t, err)

	require.NotEqual(t, ct1, ct2, "nonce must be randomized per encryption")
}

func TestNewCipher_RejectsWrongKeyLength(t *testing.T) {
	_, err := store.NewCipher([]byte("too-short"))
	require.Error(t, err)
}

func TestNewCipherFromEnv_ReadsBase64KeyFromEnvVar(t *testing.T) {
	key := randomKey(t)
	t.Setenv("STORAGE_ENCRYPTION_KEY", base64.StdEncoding.EncodeToString(key))
	t.Setenv("STORAGE_ENCRYPTION_KEY_PATH", "")

	c, err := store.NewCipherFromEnv()
	require.NoError(t, err)

	ciphertext, err := c.Encrypt(map[string]any{"a": "b"})
	require.NoError(t, err)
	decrypted, err := c.Decrypt(ciphertext)
	require.NoError(t, err)
	require.Equal(t, "b", decrypted["a"])
}

func TestNewCipherFromEnv_FallsBackToEphemeralKeyWithoutEnvVars(t *testing.T) {
	t.Setenv("STORAGE_ENCRYPTION_KEY", "")
	t.Setenv("STORAGE_ENCRYPTION_KEY_PATH", "")

	c, err := store.NewCipherFromEnv()
	require.NoError(t, err)
	require.NotNil(t, c)
}
