package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// Cipher encrypts/decrypts store values at rest using AES-256-GCM.
//
// The Python original uses Fernet (AES-128-CBC+HMAC). Neither Go nor
// TypeScript has a well-maintained Fernet-compatible library, so this
// port uses AES-256-GCM instead — an equivalent authenticated-encryption
// primitive, native to Go's standard library. This is an intentional,
// documented deviation: there is no cross-language token-portability
// requirement between the Python/Go/TypeScript ports, so encrypted
// values are not expected to move between them.
type Cipher struct {
	aead cipher.AEAD
}

// NewCipher builds a Cipher from a raw 32-byte AES-256 key.
func NewCipher(key []byte) (*Cipher, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("store: encryption key must be 32 bytes for AES-256, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("store: creating AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("store: creating GCM mode: %w", err)
	}
	return &Cipher{aead: aead}, nil
}

// NewCipherFromEnv resolves the encryption key in the same order as the
// Python original: STORAGE_ENCRYPTION_KEY env var (base64-encoded 32
// bytes), then STORAGE_ENCRYPTION_KEY_PATH (a file containing the same),
// then an ephemeral generated key with a logged warning if neither is
// set — suitable for local dev, never for a real file/redis deployment
// (an ephemeral key means every restart makes prior encrypted entries
// unreadable).
func NewCipherFromEnv() (*Cipher, error) {
	if raw := os.Getenv("STORAGE_ENCRYPTION_KEY"); raw != "" {
		key, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			return nil, fmt.Errorf("store: STORAGE_ENCRYPTION_KEY is not valid base64: %w", err)
		}
		return NewCipher(key)
	}
	if path := os.Getenv("STORAGE_ENCRYPTION_KEY_PATH"); path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("store: reading STORAGE_ENCRYPTION_KEY_PATH: %w", err)
		}
		key, err := base64.StdEncoding.DecodeString(trimNewline(raw))
		if err != nil {
			return nil, fmt.Errorf("store: key file at STORAGE_ENCRYPTION_KEY_PATH is not valid base64: %w", err)
		}
		return NewCipher(key)
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("store: generating ephemeral encryption key: %w", err)
	}
	fmt.Fprintln(os.Stderr,
		"store: WARNING no STORAGE_ENCRYPTION_KEY or STORAGE_ENCRYPTION_KEY_PATH set — "+
			"using an ephemeral key that will not survive a restart. Generate a real key with:\n"+
			`  openssl rand -base64 32`+"\nthen set STORAGE_ENCRYPTION_KEY to the output.")
	return NewCipher(key)
}

func trimNewline(b []byte) string {
	s := string(b)
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r' || s[len(s)-1] == ' ') {
		s = s[:len(s)-1]
	}
	return s
}

// Encrypt serializes v to JSON and encrypts it, returning ciphertext
// with a randomly generated nonce prepended.
func (c *Cipher) Encrypt(v map[string]any) ([]byte, error) {
	plaintext, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("store: marshaling value: %w", err)
	}
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("store: generating nonce: %w", err)
	}
	ciphertext := c.aead.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt reverses Encrypt. Returns an error if the ciphertext is
// malformed or fails authentication (wrong key, tampered data).
func (c *Cipher) Decrypt(ciphertext []byte) (map[string]any, error) {
	nonceSize := c.aead.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("store: ciphertext too short")
	}
	nonce, encrypted := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := c.aead.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return nil, fmt.Errorf("store: decrypting: %w", err)
	}
	var v map[string]any
	if err := json.Unmarshal(plaintext, &v); err != nil {
		return nil, fmt.Errorf("store: unmarshaling decrypted value: %w", err)
	}
	return v, nil
}
