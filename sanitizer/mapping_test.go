package sanitizer

import (
	"crypto/rand"
	"fmt"
	"sync"
	"testing"
)

func randKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, installKeyLen)
	if _, err := rand.Read(k); err != nil {
		t.Fatalf("rand key: %v", err)
	}
	return k
}

func TestMapping_PutOrGet_StableForSameValue(t *testing.T) {
	m := NewMapping()
	a := m.PutOrGet("sk-secret-aaa")
	b := m.PutOrGet("sk-secret-aaa")
	if a != b {
		t.Errorf("same input → different placeholders: %q vs %q", a, b)
	}
	if a == "" {
		t.Errorf("empty placeholder for non-empty input")
	}
}

func TestMapping_PutOrGet_DistinctValuesGetDistinctTokens(t *testing.T) {
	m := NewMapping()
	a := m.PutOrGet("sk-secret-aaa")
	b := m.PutOrGet("sk-secret-bbb")
	if a == b {
		t.Errorf("distinct inputs → same placeholder: %q", a)
	}
	if m.Size() != 2 {
		t.Errorf("Size() = %d, want 2", m.Size())
	}
}

func TestMapping_EmptyInput(t *testing.T) {
	m := NewMapping()
	if got := m.PutOrGet(""); got != "" {
		t.Errorf("PutOrGet(\"\") = %q, want empty", got)
	}
	if m.Size() != 0 {
		t.Errorf("empty input must not consume a token (size=%d)", m.Size())
	}
}

func TestMapping_Lookup(t *testing.T) {
	m := NewMapping()
	pa := m.PutOrGet("sk-aaa")
	pb := m.PutOrGet("sk-bbb")

	if v, ok := m.Lookup(placeholderToken(pa)); !ok || v != "sk-aaa" {
		t.Errorf("Lookup(token-a) = (%q, %v), want (%q, true)", v, ok, "sk-aaa")
	}
	if v, ok := m.Lookup(placeholderToken(pb)); !ok || v != "sk-bbb" {
		t.Errorf("Lookup(token-b) = (%q, %v), want (%q, true)", v, ok, "sk-bbb")
	}
	if _, ok := m.Lookup(tok32('f')); ok {
		t.Errorf("Lookup of an unminted token should miss")
	}
}

func TestMapping_Reset(t *testing.T) {
	m := NewMapping()
	p := m.PutOrGet("sk-aaa")
	m.Reset()
	if m.Size() != 0 {
		t.Errorf("Size() after Reset() = %d, want 0", m.Size())
	}
	if _, ok := m.Lookup(placeholderToken(p)); ok {
		t.Errorf("token should not resolve after Reset()")
	}
}

// TestMapping_TokenStableAcrossInstallKey is P2 property (a): the same
// secret maps to the SAME placeholder for any mapping sharing the install
// key — so an identical secret keeps the upstream prompt-cache key stable
// across processes / sub-agents.
func TestMapping_TokenStableAcrossInstallKey(t *testing.T) {
	key := randKey(t)
	mA := newMappingWithKey(0, key)
	mB := newMappingWithKey(0, key)
	// Insertion order differs between the two mappings — must not matter.
	mA.PutOrGet("DB_URL")
	a := mA.PutOrGet("API_KEY")
	b := mB.PutOrGet("API_KEY")
	if a != b {
		t.Errorf("same secret + same install key → different placeholders: %q vs %q", a, b)
	}
}

// TestMapping_ForeignTokenMisses is P2 property (b): a token minted by a
// DIFFERENT install key is absent from this table, so Lookup misses and
// the restorer will pass it through verbatim. This kills both the
// cross-process wrong-secret restore and the enumeration oracle.
func TestMapping_ForeignTokenMisses(t *testing.T) {
	mA := newMappingWithKey(0, randKey(t))
	pA := mA.PutOrGet("sk-AAAA-secret")

	mB := newMappingWithKey(0, randKey(t))
	_ = mB.PutOrGet("sk-BBBB-secret")

	if _, ok := mB.Lookup(placeholderToken(pA)); ok {
		t.Errorf("token minted under install A must not resolve under install B")
	}
}

// TestMapping_LRUKeepsHotEntry is the P7 repro: a repeatedly-referenced
// secret must not be the eviction victim (FIFO-by-insertion would evict
// the hottest entry first).
func TestMapping_LRUKeepsHotEntry(t *testing.T) {
	m := NewMappingWithCap(2)
	hot := m.PutOrGet("HOT") // entry 1
	m.PutOrGet("S2")         // entry 2
	_ = m.PutOrGet("HOT")    // reference again → moves to back of LRU
	m.PutOrGet("S3")         // at cap → evicts the LRU, which is now S2

	if _, ok := m.Lookup(placeholderToken(hot)); !ok {
		t.Errorf("HOT was evicted despite being the most-referenced (LRU broken)")
	}
}

func TestMapping_CapEviction(t *testing.T) {
	m := NewMappingWithCap(3)
	pa := m.PutOrGet("a")
	m.PutOrGet("b")
	m.PutOrGet("c")
	if m.Size() != 3 {
		t.Fatalf("Size = %d, want 3", m.Size())
	}
	if _, ok := m.Lookup(placeholderToken(pa)); !ok {
		t.Errorf("a should still resolve before cap pressure")
	}
	// Adding "d" evicts the LRU ("a").
	pd := m.PutOrGet("d")
	if m.Size() != 3 {
		t.Errorf("Size after eviction = %d, want 3 (cap)", m.Size())
	}
	if _, ok := m.Lookup(placeholderToken(pa)); ok {
		t.Errorf("a (LRU) should have been evicted")
	}
	if v, ok := m.Lookup(placeholderToken(pd)); !ok || v != "d" {
		t.Errorf("new entry d v=%q ok=%v, want (\"d\", true)", v, ok)
	}
}

func TestMapping_EvictionCounter(t *testing.T) {
	m := NewMappingWithCap(1)
	m.PutOrGet("a")
	if m.Evictions() != 0 {
		t.Errorf("Evictions before pressure = %d, want 0", m.Evictions())
	}
	m.PutOrGet("b") // evicts a
	m.PutOrGet("c") // evicts b
	if m.Evictions() != 2 {
		t.Errorf("Evictions = %d, want 2", m.Evictions())
	}
}

func TestMapping_CapUnboundedWhenZero(t *testing.T) {
	m := NewMappingWithCap(0)
	for i := 0; i < 100; i++ {
		m.PutOrGet(fmt.Sprintf("v-%d", i))
	}
	if m.Size() != 100 {
		t.Errorf("Size with cap=0 = %d, want 100 (unbounded)", m.Size())
	}
}

func TestMapping_Concurrent(t *testing.T) {
	m := NewMapping()
	const n = 50
	var wg sync.WaitGroup
	wg.Add(n)
	results := make([]string, n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			results[i] = m.PutOrGet("shared-secret")
		}(i)
	}
	wg.Wait()
	first := results[0]
	for i, r := range results {
		if r != first {
			t.Errorf("concurrent results diverged at %d: %q vs %q", i, r, first)
		}
	}
	if m.Size() != 1 {
		t.Errorf("Size() = %d, want 1 (deduplicated)", m.Size())
	}
}
