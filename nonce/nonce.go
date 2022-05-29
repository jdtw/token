package nonce

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

var ErrReused = errors.New("nonce reuse detected")

func New() ([]byte, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return nonce, nil
}

type Verifier interface {
	// Verify that the given nonce has not been seen. The expiry time of the associated token
	// is given so that the server may know when it is safe to stop tracking this nonce.
	Verify(nonce []byte, expires time.Time) error
}

// MapVerifier keeps an in-memory map of nonces that it has seen. The map is pruned
// of expired tokens periodically. This is NOT SAFE for use in a distributed environment.
type MapVerifier struct {
	seen       map[string]time.Time
	pruned     time.Time
	pruneEvery time.Duration
	wg         sync.WaitGroup
	sync.Mutex
}

var _ Verifier = &MapVerifier{}

// NewMapVerifier creates a new nonce verifier that prunes expired nonces at the given cadence.
func NewMapVerifier(pruneEvery time.Duration) *MapVerifier {
	return &MapVerifier{
		make(map[string]time.Time),
		time.Now(),
		pruneEvery,
		sync.WaitGroup{},
		sync.Mutex{},
	}
}

// Verify that the nonce has not been seen before, and save it in the map so that future calls
// with this nonce fail.
func (m *MapVerifier) Verify(nonce []byte, expires time.Time) error {
	encoded := hex.EncodeToString(nonce)
	m.Lock()
	defer m.Unlock()
	// Schedule a prune if needed...
	if now := time.Now(); now.Sub(m.pruned) >= m.pruneEvery {
		m.wg.Add(1)
		go func() {
			defer m.wg.Done()
			m.prune(now)
		}()
	}
	if _, ok := m.seen[encoded]; ok {
		return ErrReused
	}
	m.seen[encoded] = expires
	return nil
}

func (m *MapVerifier) prune(now time.Time) {
	m.Lock()
	defer m.Unlock()
	unexpired := make(map[string]time.Time)
	for id, exp := range m.seen {
		if exp.After(now) {
			unexpired[id] = exp
		}
	}
	m.seen = unexpired
}
