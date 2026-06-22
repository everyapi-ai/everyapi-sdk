package api

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestIsOfficialEveryAPIHost(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		{"everyapi.ai", true},
		{"api.everyapi.ai", true},
		{"app.everyapi.ai", true},
		{"a.b.everyapi.ai", true},
		{"EVERYAPI.AI", true},         // case-insensitive
		{"api.everyapi.ai:443", true}, // defensive port strip
		{"  app.everyapi.ai  ", true}, // trimmed
		{"everyapi.ai.", true},        // rooted FQDN
		{"api.everyapi.ai.", true},    // rooted FQDN subdomain
		{"localhost", false},
		{"127.0.0.1", false},
		{"", false},
		{"everyapipro.com", false},
		{"noteveryapi.ai", false},
		{"xeveryapi.ai", false}, // suffix "everyapi.ai" but not ".everyapi.ai"
		{"everyapi.ai.evil.com", false},
		{"evil.com", false},
	}
	for _, c := range cases {
		if got := isOfficialEveryAPIHost(c.host); got != c.want {
			t.Errorf("isOfficialEveryAPIHost(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

// makeLeaf builds a real self-signed leaf certificate with a fresh
// key. No mocks — spkiPin must operate on an actual x509 cert.
func makeLeaf(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestSPKIPinDeterministicAndFormat(t *testing.T) {
	c1 := makeLeaf(t)
	p1, p1again := spkiPin(c1), spkiPin(c1)
	if p1 != p1again {
		t.Fatalf("spkiPin not deterministic: %q vs %q", p1, p1again)
	}
	raw, err := base64.StdEncoding.DecodeString(p1)
	if err != nil {
		t.Fatalf("pin not valid base64: %v", err)
	}
	if len(raw) != 32 {
		t.Errorf("pin decodes to %d bytes, want 32 (sha256)", len(raw))
	}
	if p2 := spkiPin(makeLeaf(t)); p2 == p1 {
		t.Error("different key produced the same pin")
	}
}

func newTestReporter(buf *bytes.Buffer, expected map[string]struct{}) *pinReporter {
	return &pinReporter{out: buf, expected: expected, seen: make(map[string]struct{})}
}

// TestInspectDormantWhenNoPins pins the v1 contract: with no baseline
// configured the hook is a SILENT no-op on official hosts — no stderr
// noise, never an error. (The earlier cut logged the observed pin on
// every run; that was unactionable noise and not actually collected
// anywhere, so it was removed.)
func TestInspectDormantWhenNoPins(t *testing.T) {
	buf := &bytes.Buffer{}
	r := newTestReporter(buf, map[string]struct{}{}) // empty = dormant
	leaf := makeLeaf(t)

	if err := r.inspect("api.everyapi.ai", [][]*x509.Certificate{{leaf}}); err != nil {
		t.Fatalf("report-only must never error: %v", err)
	}
	if err := r.inspect("api.everyapi.ai", [][]*x509.Certificate{{leaf}}); err != nil {
		t.Fatalf("report-only must never error: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("dormant (no pins) must be silent, got:\n%s", buf.String())
	}
}

func TestInspectSkipsNonOfficialHost(t *testing.T) {
	buf := &bytes.Buffer{}
	r := newTestReporter(buf, map[string]struct{}{})
	if err := r.inspect("localhost", [][]*x509.Certificate{{makeLeaf(t)}}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("non-official host must not be inspected/logged, got: %q", buf.String())
	}
}

func TestInspectDisabledIsNoOp(t *testing.T) {
	t.Setenv("EVERYAPI_TLS_PIN", "off")
	r := newPinReporter()
	if !r.disabled {
		t.Fatal("EVERYAPI_TLS_PIN=off should disable the reporter")
	}
	// Seed a non-empty expected set with a pin that does NOT match the
	// cert, so an enabled reporter WOULD warn here — proving the
	// `disabled` gate short-circuits the check, not just dormancy.
	buf := &bytes.Buffer{}
	r.out = buf
	r.expected = map[string]struct{}{"some-other-pin": {}}
	if err := r.inspect("api.everyapi.ai", [][]*x509.Certificate{{makeLeaf(t)}}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("disabled reporter must produce no output, got: %q", buf.String())
	}
}

func TestInspectMatchVsMismatch(t *testing.T) {
	leaf := makeLeaf(t)
	pin := spkiPin(leaf)

	// Seeded expected set containing this leaf's pin → silent match.
	buf := &bytes.Buffer{}
	r := newTestReporter(buf, map[string]struct{}{pin: {}})
	if err := r.inspect("app.everyapi.ai", [][]*x509.Certificate{{leaf}}); err != nil {
		t.Fatalf("matching pin must not error: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("matching pin must be silent, got: %q", buf.String())
	}

	// A different cert is not in the expected set → loud, still nil.
	other := makeLeaf(t)
	if err := r.inspect("app.everyapi.ai", [][]*x509.Certificate{{other}}); err != nil {
		t.Fatalf("report-only mismatch must not error: %v", err)
	}
	if !strings.Contains(buf.String(), "MISMATCH") {
		t.Errorf("expected a mismatch warning, got: %q", buf.String())
	}

	// With enforce flipped on, a fresh mismatch DOES error (guards the
	// reserved enforcement path the next change will turn on).
	r2 := newTestReporter(&bytes.Buffer{}, map[string]struct{}{pin: {}})
	r2.enforce = true
	if err := r2.inspect("app.everyapi.ai", [][]*x509.Certificate{{makeLeaf(t)}}); err == nil {
		t.Error("enforce=true must reject a pin mismatch")
	}
}

// TestInspectMatchesIntermediateInChain is the core of the cert-rotation
// fix: the leaf is NOT pinned, only an issuing intermediate is. A chain
// whose leaf pin is absent but whose intermediate pin is present must
// match silently — that is what lets the leaf rotate without a release.
func TestInspectMatchesIntermediateInChain(t *testing.T) {
	leaf := makeLeaf(t)
	intermediate := makeLeaf(t) // stand-in for the issuing CA cert
	interPin := spkiPin(intermediate)

	// Expected set pins ONLY the intermediate, never the leaf.
	buf := &bytes.Buffer{}
	r := newTestReporter(buf, map[string]struct{}{interPin: {}})

	if err := r.inspect("api.everyapi.ai", [][]*x509.Certificate{{leaf, intermediate}}); err != nil {
		t.Fatalf("intermediate match must not error: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("intermediate match must be silent (leaf rotation case), got: %q", buf.String())
	}

	// A chain where neither leaf nor intermediate is pinned → mismatch,
	// and the warning reports the LEAF pin (chains[0][0]), not the others.
	other, otherInter := makeLeaf(t), makeLeaf(t)
	if err := r.inspect("api.everyapi.ai", [][]*x509.Certificate{{other, otherInter}}); err != nil {
		t.Fatalf("report-only mismatch must not error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "MISMATCH") {
		t.Errorf("expected mismatch warning, got: %q", out)
	}
	if !strings.Contains(out, spkiPin(other)) {
		t.Errorf("warning must report the leaf pin %q, got: %q", spkiPin(other), out)
	}
	// Must report ONLY the leaf (chains[0][0]), never some other chain cert.
	if strings.Contains(out, spkiPin(otherInter)) {
		t.Errorf("warning must not report the intermediate pin %q, got: %q", spkiPin(otherInter), out)
	}
}

// TestInspectMultiChainMatchAndEmptyGuard covers the cross-signed case —
// cs.VerifiedChains can hold more than one chain (GTS R4 is itself
// cross-signed) — and the empty-inner-chain guard protecting the
// chains[0][0] deref on the mismatch path.
func TestInspectMultiChainMatchAndEmptyGuard(t *testing.T) {
	intermediate := makeLeaf(t)
	interPin := spkiPin(intermediate)

	buf := &bytes.Buffer{}
	r := newTestReporter(buf, map[string]struct{}{interPin: {}})

	// The pinned intermediate appears ONLY in the second verified chain;
	// the outer loop must still find it → silent match.
	chains := [][]*x509.Certificate{
		{makeLeaf(t), makeLeaf(t)},  // unrelated cross-signed path
		{makeLeaf(t), intermediate}, // path carrying the pinned WE1
	}
	if err := r.inspect("api.everyapi.ai", chains); err != nil {
		t.Fatalf("match in a non-first chain must not error: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("match in the second chain must be silent, got: %q", buf.String())
	}

	// An empty inner chain must no-op, not panic on the chains[0][0] deref.
	if err := r.inspect("api.everyapi.ai", [][]*x509.Certificate{{}}); err != nil {
		t.Fatalf("empty inner chain must not error: %v", err)
	}
}

// TestExpectedSPKIPinsWellFormed guards the hand-pasted production pin
// set against a typo: every key must be valid standard base64 that
// decodes to exactly 32 bytes (a SHA-256 digest). A malformed entry
// would silently never match any real cert, turning the report-only
// pinning into a permanent false "mismatch" — caught here at build/CI
// instead of in the field.
func TestExpectedSPKIPinsWellFormed(t *testing.T) {
	if len(expectedSPKIPins) == 0 {
		t.Fatal("expectedSPKIPins is empty — the live leaf pins must be populated")
	}
	for pin := range expectedSPKIPins {
		raw, err := base64.StdEncoding.DecodeString(pin)
		if err != nil {
			t.Errorf("pin %q is not valid base64: %v", pin, err)
			continue
		}
		if len(raw) != 32 {
			t.Errorf("pin %q decodes to %d bytes, want 32 (SHA-256)", pin, len(raw))
		}
	}
}
