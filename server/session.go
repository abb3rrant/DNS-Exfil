package server

import (
	"sync"
	"time"
)

// Session holds the state for a single exfiltration session.
type Session struct {
	mu        sync.Mutex
	ID        string
	Filename  string
	Salt      []byte
	Total     int
	Chunks    map[int][]byte
	CreatedAt time.Time
	UpdatedAt time.Time
}

// NewSession creates a new session with the given parameters.
func NewSession(id, filename string, salt []byte, total int) *Session {
	now := time.Now()
	return &Session{
		ID:        id,
		Filename:  filename,
		Salt:      salt,
		Total:     total,
		Chunks:    make(map[int][]byte),
		CreatedAt: now,
		UpdatedAt: now,
	}
}

// StoreChunk stores a data chunk at the given sequence number.
func (s *Session) StoreChunk(seq int, data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Chunks[seq] = data
	s.UpdatedAt = time.Now()
}

// IsComplete returns true if all chunks (1..Total) have been received.
func (s *Session) IsComplete() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.Chunks) == s.Total
}

// MissingChunks returns the sequence numbers of chunks not yet received.
func (s *Session) MissingChunks() []int {
	s.mu.Lock()
	defer s.mu.Unlock()
	var missing []int
	for i := 1; i <= s.Total; i++ {
		if _, ok := s.Chunks[i]; !ok {
			missing = append(missing, i)
		}
	}
	return missing
}

// Reassemble concatenates all chunks in sequence order and returns the result.
// Caller must ensure IsComplete() is true before calling.
func (s *Session) Reassemble() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	var result []byte
	for i := 1; i <= s.Total; i++ {
		result = append(result, s.Chunks[i]...)
	}
	return result
}

// SessionStore is a thread-safe map of active sessions.
type SessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*Session
	timeout  time.Duration
}

// NewSessionStore creates a new store with the given session timeout.
func NewSessionStore(timeout time.Duration) *SessionStore {
	return &SessionStore{
		sessions: make(map[string]*Session),
		timeout:  timeout,
	}
}

// Get returns a session by ID, or nil if not found.
func (ss *SessionStore) Get(id string) *Session {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	return ss.sessions[id]
}

// Create adds a new session. If one already exists with the same ID, it is
// overwritten (allows client retries of init).
func (ss *SessionStore) Create(s *Session) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.sessions[s.ID] = s
}

// Delete removes a session by ID.
func (ss *SessionStore) Delete(id string) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	delete(ss.sessions, id)
}

// StartCleanup launches a background goroutine that removes sessions older
// than the configured timeout. It stops when the done channel is closed.
func (ss *SessionStore) StartCleanup(interval time.Duration, done <-chan struct{}) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				ss.cleanup()
			}
		}
	}()
}

func (ss *SessionStore) cleanup() {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	cutoff := time.Now().Add(-ss.timeout)
	for id, s := range ss.sessions {
		s.mu.Lock()
		if s.UpdatedAt.Before(cutoff) {
			delete(ss.sessions, id)
		}
		s.mu.Unlock()
	}
}
