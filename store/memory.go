package store

import (
	"context"
	"sync"
	"time"
)

// MemoryTokenStore is an in-process TokenStore backed by a plain map. No
// encryption (nothing crosses a process boundary), no TTL — mirrors the
// Python original's MemoryTokenStore exactly. Zero-overhead, but state is
// lost on restart and is not shared across replicas.
type MemoryTokenStore struct {
	mu   sync.Mutex
	data map[string]map[string]any
}

// NewMemoryTokenStore constructs an empty MemoryTokenStore.
func NewMemoryTokenStore() *MemoryTokenStore {
	return &MemoryTokenStore{data: make(map[string]map[string]any)}
}

// Get implements [store.TokenStore].
func (s *MemoryTokenStore) Get(_ context.Context, sub string) (map[string]any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.data[sub]
	if !ok {
		return nil, nil
	}
	return cloneMap(v), nil
}

// Set implements [store.TokenStore].
func (s *MemoryTokenStore) Set(_ context.Context, sub string, value map[string]any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[sub] = cloneMap(value)
	return nil
}

// Delete implements [store.TokenStore].
func (s *MemoryTokenStore) Delete(_ context.Context, sub string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, sub)
	return nil
}

type pendingEntry struct {
	metadata map[string]any
	expires  time.Time
}

type doneEntry struct {
	ch     chan map[string]any
	result map[string]any
	fired  bool
}

// MemoryPendingStore is an in-process PendingStore. WaitForResult blocks
// on a channel rather than polling — the single-process equivalent of
// the Python original's asyncio.Event-based implementation, and strictly
// cheaper than the poll-based approach the File/Redis backends must use
// (they have no in-process notification mechanism to hook into).
type MemoryPendingStore struct {
	mu      sync.Mutex
	pending map[string]pendingEntry
	done    map[string]*doneEntry
}

// NewMemoryPendingStore constructs an empty MemoryPendingStore.
func NewMemoryPendingStore() *MemoryPendingStore {
	return &MemoryPendingStore{
		pending: make(map[string]pendingEntry),
		done:    make(map[string]*doneEntry),
	}
}

// Create implements [store.PendingStore].
func (s *MemoryPendingStore) Create(_ context.Context, key string, metadata map[string]any, ttl int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pending[key] = pendingEntry{metadata: cloneMap(metadata), expires: time.Now().Add(time.Duration(ttl) * time.Second)}
	return nil
}

// Get implements [store.PendingStore].
func (s *MemoryPendingStore) Get(_ context.Context, key string) (map[string]any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.pending[key]
	if !ok || time.Now().After(entry.expires) {
		delete(s.pending, key)
		return nil, nil
	}
	return cloneMap(entry.metadata), nil
}

// Pop implements [store.PendingStore].
func (s *MemoryPendingStore) Pop(_ context.Context, key string) (map[string]any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.pending[key]
	delete(s.pending, key)
	if !ok || time.Now().After(entry.expires) {
		return nil, nil
	}
	return cloneMap(entry.metadata), nil
}

// SetResult implements [store.PendingStore].
func (s *MemoryPendingStore) SetResult(_ context.Context, key string, result map[string]any, _ int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.done[key]
	if !ok {
		// A waiter hasn't called WaitForResult yet (or never will) —
		// still record the result so a WaitForResult that arrives later
		// observes it immediately rather than missing the signal.
		d = &doneEntry{ch: make(chan map[string]any, 1)}
		s.done[key] = d
	}
	if !d.fired {
		d.fired = true
		d.result = cloneMap(result)
		d.ch <- d.result
	}
	return nil
}

// WaitForResult implements [store.PendingStore].
func (s *MemoryPendingStore) WaitForResult(ctx context.Context, key string, timeoutSeconds float64) (map[string]any, error) {
	s.mu.Lock()
	d, ok := s.done[key]
	if !ok {
		d = &doneEntry{ch: make(chan map[string]any, 1)}
		s.done[key] = d
	}
	s.mu.Unlock()

	timer := time.NewTimer(time.Duration(timeoutSeconds * float64(time.Second)))
	defer timer.Stop()

	select {
	case result := <-d.ch:
		s.mu.Lock()
		delete(s.done, key) // consume: a second WaitForResult call must not observe this again
		s.mu.Unlock()
		return result, nil
	case <-timer.C:
		return nil, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func cloneMap(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
