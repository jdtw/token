package nonce

import (
	"errors"
	"testing"
	"time"
)

func TestNonceReuse(t *testing.T) {
	now := time.Now()
	nv := NewMapVerifier(time.Hour)
	nonce, err := New()
	if err != nil {
		t.Fatal(err)
	}
	// Verify with an arbitrary expiry...
	if err := nv.Verify(nonce, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := nv.Verify(nonce, now.Add(time.Second)); !errors.Is(err, ErrReused) {
		t.Fatalf("Verify = %v, want %v", err, ErrReused)
	}
}

func TestPrune(t *testing.T) {
	// Prune on every call to Verify...
	nv := NewMapVerifier(time.Duration(0))
	// Add a nonce that has already expired. The call to Verify will succeed, but this
	// nonce should be pruned immediately.
	if err := nv.Verify([]byte("YELLOW SUBMARINE"), time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	nv.wg.Wait()
	if len(nv.seen) != 0 {
		t.Fatalf("Expected no entries in the seen map: %v", nv.seen)
	}
	// Add an unexpired nonce. This one should not be pruned.
	if err := nv.Verify([]byte("YELLOW SUBMARINE"), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	nv.wg.Wait()
	if len(nv.seen) != 1 {
		t.Fatalf("Expected exactly one entry in the seen map: %v", nv.seen)
	}
	// Add another nonce to be pruned to ensure that YELLOW SUBMARINE remains unperturbed.
	if err := nv.Verify([]byte("ORANGE SUBMARINE"), time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	nv.wg.Wait()
	if len(nv.seen) != 1 {
		t.Fatalf("Expected exactly one entry in the seen map: %v", nv.seen)
	}
	// And finally, ensure that reuse is still detected.
	if err := nv.Verify([]byte("YELLOW SUBMARINE"), time.Now()); !errors.Is(err, ErrReused) {
		t.Fatalf("Verify = %v, want %v", err, ErrReused)
	}
}

func TestPruneEvery(t *testing.T) {
	nv := NewMapVerifier(time.Hour)
	// Add an expired nonce and ensure that it is not pruned on Verify since the delta hasn't elapsed...
	if err := nv.Verify([]byte("YELLOW SUBMARINE"), time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	nv.wg.Wait()
	if len(nv.seen) != 1 {
		t.Fatalf("Expected exactly one entry in the seen map: %v", nv.seen)
	}
	// Pretend we haven't pruned in a while and then trigger one...
	nv.pruned = nv.pruned.Add(-nv.pruneEvery)
	if err := nv.Verify([]byte("YELLOW SUBMARINE"), time.Now()); !errors.Is(err, ErrReused) {
		t.Fatalf("Verify = %v, want %v", err, ErrReused)
	}
	nv.wg.Wait()
	if len(nv.seen) != 0 {
		t.Fatalf("Expected an empty seen map: %v", nv.seen)
	}
}
