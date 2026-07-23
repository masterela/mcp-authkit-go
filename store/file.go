package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const filePollInterval = 500 * time.Millisecond

func safeName(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

// atomicWriteFile writes data to a temp file in dir then renames it into
// place — an atomic POSIX rename, so a concurrent reader never observes a
// partially-written file. Mirrors the Python original's tmp-then-replace
// pattern.
func atomicWriteFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return os.Rename(tmpPath, path)
}

// FileTokenStore is a TokenStore backed by encrypted files under
// storagePath/tokens/. Self-healing: a decrypt failure (e.g. the
// encryption key changed) deletes the stale file and returns "not
// found" rather than erroring — mirrors the Python original.
type FileTokenStore struct {
	dir    string
	cipher *Cipher
}

// NewFileTokenStore constructs a FileTokenStore rooted at
// storagePath/tokens[/namespace].
func NewFileTokenStore(storagePath string, namespace string, cipher *Cipher) (*FileTokenStore, error) {
	dir := filepath.Join(storagePath, "tokens")
	if namespace != "" {
		dir = filepath.Join(dir, namespace)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("store: creating token store dir: %w", err)
	}
	return &FileTokenStore{dir: dir, cipher: cipher}, nil
}

func (s *FileTokenStore) path(sub string) string {
	return filepath.Join(s.dir, safeName(sub)+".enc")
}

// Get implements [store.TokenStore].
func (s *FileTokenStore) Get(_ context.Context, sub string) (map[string]any, error) {
	data, err := os.ReadFile(s.path(sub))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	v, err := s.cipher.Decrypt(data)
	if err != nil {
		// Self-heal: a file we can no longer decrypt is unusable state,
		// not a transient error — remove it and report "not found" so
		// the caller re-authenticates rather than crash-looping.
		_ = os.Remove(s.path(sub))
		return nil, nil
	}
	return v, nil
}

// Set implements [store.TokenStore].
func (s *FileTokenStore) Set(_ context.Context, sub string, value map[string]any) error {
	data, err := s.cipher.Encrypt(value)
	if err != nil {
		return err
	}
	return atomicWriteFile(s.path(sub), data)
}

// Delete implements [store.TokenStore].
func (s *FileTokenStore) Delete(_ context.Context, sub string) error {
	err := os.Remove(s.path(sub))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

type filePendingRecord struct {
	Metadata map[string]any `json:"metadata"`
	Expires  int64          `json:"expires"` // unix seconds
}

// FilePendingStore is a PendingStore backed by encrypted files under
// storagePath/pending/. WaitForResult polls for the ".done" sidecar file
// every 500ms, since a plain file store has no cross-process
// notification mechanism to block on — mirrors the Python original.
type FilePendingStore struct {
	dir    string
	cipher *Cipher
}

// NewFilePendingStore constructs a FilePendingStore rooted at
// storagePath/pending/.
func NewFilePendingStore(storagePath string, cipher *Cipher) (*FilePendingStore, error) {
	dir := filepath.Join(storagePath, "pending")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("store: creating pending store dir: %w", err)
	}
	return &FilePendingStore{dir: dir, cipher: cipher}, nil
}

func (s *FilePendingStore) metaPath(key string) string {
	return filepath.Join(s.dir, safeName(key)+".enc")
}

func (s *FilePendingStore) donePath(key string) string {
	return filepath.Join(s.dir, safeName(key)+".done.enc")
}

func (s *FilePendingStore) writeRecord(path string, metadata map[string]any, ttlSeconds int) error {
	record := filePendingRecord{Metadata: metadata, Expires: time.Now().Add(time.Duration(ttlSeconds) * time.Second).Unix()}
	raw, err := json.Marshal(record)
	if err != nil {
		return err
	}
	// The record itself is JSON containing the metadata map; encrypting
	// that whole blob (rather than only the metadata) keeps the
	// encrypted-at-rest guarantee over the expiry timestamp too, at the
	// cost of one extra JSON layer versus the memory backend.
	encrypted, err := s.cipher.Encrypt(map[string]any{"record": string(raw)})
	if err != nil {
		return err
	}
	return atomicWriteFile(path, encrypted)
}

func (s *FilePendingStore) readRecord(path string) (*filePendingRecord, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	decrypted, err := s.cipher.Decrypt(data)
	if err != nil {
		_ = os.Remove(path)
		return nil, nil
	}
	rawStr, _ := decrypted["record"].(string)
	var record filePendingRecord
	if err := json.Unmarshal([]byte(rawStr), &record); err != nil {
		_ = os.Remove(path)
		return nil, nil
	}
	if time.Now().Unix() > record.Expires {
		_ = os.Remove(path)
		return nil, nil
	}
	return &record, nil
}

// Create implements [store.PendingStore].
func (s *FilePendingStore) Create(_ context.Context, key string, metadata map[string]any, ttl int) error {
	return s.writeRecord(s.metaPath(key), metadata, ttl)
}

// Get implements [store.PendingStore].
func (s *FilePendingStore) Get(_ context.Context, key string) (map[string]any, error) {
	record, err := s.readRecord(s.metaPath(key))
	if err != nil || record == nil {
		return nil, err
	}
	return record.Metadata, nil
}

// Pop implements [store.PendingStore].
func (s *FilePendingStore) Pop(_ context.Context, key string) (map[string]any, error) {
	record, err := s.readRecord(s.metaPath(key))
	if err != nil {
		return nil, err
	}
	_ = os.Remove(s.metaPath(key))
	if record == nil {
		return nil, nil
	}
	return record.Metadata, nil
}

// SetResult implements [store.PendingStore].
func (s *FilePendingStore) SetResult(_ context.Context, key string, result map[string]any, ttl int) error {
	return s.writeRecord(s.donePath(key), result, ttl)
}

// WaitForResult implements [store.PendingStore].
func (s *FilePendingStore) WaitForResult(ctx context.Context, key string, timeoutSeconds float64) (map[string]any, error) {
	deadline := time.Now().Add(time.Duration(timeoutSeconds * float64(time.Second)))
	path := s.donePath(key)

	for {
		if record, err := s.readRecord(path); err == nil && record != nil {
			_ = os.Remove(path) // consume: a second wait must not observe this again
			return record.Metadata, nil
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
