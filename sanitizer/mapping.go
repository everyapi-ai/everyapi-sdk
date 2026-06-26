package sanitizer

import (
	"sync"
)

// DefaultMappingCap is the soft cap on how many distinct secrets the
// mapping table will hold before it starts evicting an entry to make
// room for a new one. Real workloads are nowhere near this — a typical
// prompt has < 5 sensitive substrings, and even a long-running proxy
// serving a single buyer rarely exceeds a few hundred distinct values in
// a day — but a long-lived detached process with a high false-positive
// detector set could in theory grow unbounded. 10 000 is a comfortable
// headroom over realistic usage while still being trivially small in RAM.
const DefaultMappingCap = 10000

// Mapping is the in-memory real↔placeholder table that gives the
// sanitizer its trust-minimal property: the platform never sees real
// secret values, and it cannot inject a placeholder the proxy doesn't
// already know about (the placeholder body is a keyed HMAC of the real
// value, so a token the proxy never minted is absent from the table).
//
// The mapping is process-scoped — there is no on-disk persistence of the
// real↔token table — so a fresh proxy process starts with a clean table
// and a buyer's secrets can never leak between processes. The placeholder
// TOKENS, however, are stable across processes because they're derived
// from the per-install key (see installkey.go), so prompt-cache keys on
// the upstream don't rotate for an identical secret.
//
// Lookups are by exact byte equality of the real value (for minting) or
// of the token (for restore). Two identical real values always map to
// the SAME placeholder token.
//
// Eviction: once the table hits Cap distinct values, the LEAST-recently
// used entry is evicted to make room (LRU). A repeatedly-cited secret is
// therefore kept hot and never evicted out from under an in-flight
// response. The evicted secret's token becomes unresolvable — if it
// later appears in an upstream response, the restorer passes it through
// verbatim, which is harmless: the SDK sees literal placeholder text and
// the buyer notices something is off. The alternative (refusing to add
// new entries) would be worse — fresh secrets in the prompt would leak
// through unsanitised.
type Mapping struct {
	mu        sync.RWMutex
	key       []byte            // per-install HMAC key used to derive tokens
	byReal    map[string]string // real value → token
	byToken   map[string]string // token → real value (for the inbound restore pass)
	order     []string          // tokens in LRU order; order[0] is the least-recently-used
	cap       int               // 0 = unbounded
	evictions int64             // count of entries dropped under cap pressure
}

// NewMapping returns an empty mapping with the default cap, keyed by the
// process-wide install key.
func NewMapping() *Mapping {
	return NewMappingWithCap(DefaultMappingCap)
}

// NewMappingWithCap returns an empty mapping with the given soft cap;
// pass 0 for "unbounded" (mainly useful in tests).
func NewMappingWithCap(cap int) *Mapping {
	return newMappingWithKey(cap, installKey())
}

// newMappingWithKey is the test seam: it builds a mapping with an
// explicit HMAC key so tests can simulate two distinct installs (whose
// tokens for the same secret must differ).
func newMappingWithKey(cap int, key []byte) *Mapping {
	return &Mapping{
		key:     key,
		byReal:  make(map[string]string),
		byToken: make(map[string]string),
		cap:     cap,
	}
}

// PutOrGet returns the placeholder string for `real`, allocating a token
// if this is the first sighting. Empty input returns "" — the sanitizer
// must never produce a placeholder for the empty string because that
// would corrupt any downstream text that happens to be empty in the
// original prompt.
//
// On a HIT the entry is moved to the back of the LRU order so a
// repeatedly-referenced secret is never the eviction victim. If the table
// is at its Cap when a NEW value arrives, the least-recently-used entry
// is evicted to make room.
func (m *Mapping) PutOrGet(real string) string {
	if real == "" {
		return ""
	}
	token := deriveToken(m.key, real)

	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.byToken[token]; ok {
		m.touchLocked(token)
		return MakePlaceholder(token)
	}
	// Evict the LRU entry if at cap. Cap == 0 means unbounded.
	if m.cap > 0 && len(m.byToken) >= m.cap && len(m.order) > 0 {
		oldest := m.order[0]
		m.order = m.order[1:]
		if v, ok := m.byToken[oldest]; ok {
			delete(m.byReal, v)
			delete(m.byToken, oldest)
			m.evictions++
		}
	}
	m.byReal[real] = token
	m.byToken[token] = real
	m.order = append(m.order, token)
	return MakePlaceholder(token)
}

// touchLocked moves token to the back of the LRU order. Caller holds the
// write lock.
func (m *Mapping) touchLocked(token string) {
	for i, t := range m.order {
		if t == token {
			m.order = append(m.order[:i], m.order[i+1:]...)
			m.order = append(m.order, token)
			return
		}
	}
}

// Lookup returns the real value for a token, or "" + false if the token
// wasn't minted by this process (or was evicted from the table after a
// cap-driven roll). The proxy uses this on the inbound (downstream) pass:
// it finds placeholder matches in response bytes and resolves each token
// back to the real value. A placeholder the upstream invented out of thin
// air (an attack trying to use the sanitizer as an oracle) will miss here
// — the token can't be fabricated without the per-install key — and the
// placeholder text passes through to the SDK as-is.
func (m *Mapping) Lookup(token string) (string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	v, ok := m.byToken[token]
	return v, ok
}

// Size returns the number of distinct real values currently held.
func (m *Mapping) Size() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.byReal)
}

// Evictions returns the number of entries dropped under cap pressure
// over the mapping's lifetime. Surfaced through /__sanitizer/status so an
// operator can tell when over-detection is rolling real secrets out of
// the table.
func (m *Mapping) Evictions() int64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.evictions
}

// Reset clears the table. Called by the server on shutdown; making it
// explicit (rather than relying on GC) helps with tests that want a
// fresh mapping per case. The install key is retained — it's process
// identity, not session state.
func (m *Mapping) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.byReal = make(map[string]string)
	m.byToken = make(map[string]string)
	m.order = nil
	m.evictions = 0
}
