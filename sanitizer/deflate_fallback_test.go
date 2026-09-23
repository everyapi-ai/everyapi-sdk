package sanitizer

import (
	"bytes"
	"compress/flate"
	"compress/zlib"
	"strings"
	"testing"
)

// deflateSecretBody is a JSON body shaped like a real request so a decode failure shows up the way it would in production: the walkers only sanitise something that still parses as JSON, so a body corrupted at byte 0 forwards this key verbatim.
const deflateSecretBody = `{"model":"gpt-4","api_key":"sk-ant-api03-DEADBEEFDEADBEEFDEADBEEFDEADBEEF","messages":[{"role":"user","content":"hello"}]}`

func rawDeflate(t *testing.T, payload string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw, err := flate.NewWriter(&buf, flate.BestCompression)
	if err != nil {
		t.Fatalf("flate.NewWriter: %v", err)
	}
	if _, err := zw.Write([]byte(payload)); err != nil {
		t.Fatalf("flate write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("flate close: %v", err)
	}
	return buf.Bytes()
}

func zlibDeflate(t *testing.T, payload string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	if _, err := zw.Write([]byte(payload)); err != nil {
		t.Fatalf("zlib write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zlib close: %v", err)
	}
	return buf.Bytes()
}

// TestDecodeBodyRawDeflateRoundTrip pins the raw-deflate half of the ambiguous "deflate" encoding. zlib.NewReader consumes its two-byte header from the reader even when it rejects the stream, so a zlib-first / flate-fallback decoder that shares one reader hands flate a stream already advanced past its first two bytes — the body comes back corrupt from byte 0 rather than failing, which is the dangerous direction for a redaction proxy.
func TestDecodeBodyRawDeflateRoundTrip(t *testing.T) {
	encoded := rawDeflate(t, deflateSecretBody)
	out, err := decodeBody("deflate", encoded)
	if err != nil {
		t.Fatalf("decodeBody(raw deflate) returned error: %v", err)
	}
	if string(out) != deflateSecretBody {
		t.Fatalf("raw-deflate body did not round-trip\n got: %q\nwant: %q", string(out), deflateSecretBody)
	}
	if !looksJSON(out) {
		t.Fatalf("decoded raw-deflate body is not JSON-shaped, the protocol walkers would skip it: %q", string(out))
	}
}

// TestDecodeBodyZlibRoundTrip keeps the RFC 7230 reading working: a genuine zlib-wrapped body must still take the zlib path, not be misrouted to raw flate by the header sniff.
func TestDecodeBodyZlibRoundTrip(t *testing.T) {
	encoded := zlibDeflate(t, deflateSecretBody)
	out, err := decodeBody("deflate", encoded)
	if err != nil {
		t.Fatalf("decodeBody(zlib deflate) returned error: %v", err)
	}
	if string(out) != deflateSecretBody {
		t.Fatalf("zlib body did not round-trip\n got: %q\nwant: %q", string(out), deflateSecretBody)
	}
}

// TestDecodeBodyDeflateHeaderSniffIsExhaustive runs both framings over payloads of varying length and content so the sniff is exercised against many different first bytes; a single fixture can pass by luck when a raw-deflate stream happens to start with bytes that satisfy the zlib header check.
func TestDecodeBodyDeflateHeaderSniffIsExhaustive(t *testing.T) {
	payloads := []string{
		"",
		"a",
		"{}",
		`{"k":"v"}`,
		strings.Repeat("sk-ant-api03-DEADBEEF", 200),
		deflateSecretBody,
	}
	for _, payload := range payloads {
		for name, encoded := range map[string][]byte{
			"raw":  rawDeflate(t, payload),
			"zlib": zlibDeflate(t, payload),
		} {
			out, err := decodeBody("deflate", encoded)
			if err != nil {
				t.Errorf("%s framing, %d-byte payload: decodeBody returned error: %v", name, len(payload), err)
				continue
			}
			if string(out) != payload {
				t.Errorf("%s framing, %d-byte payload: round-trip mismatch\n got: %q\nwant: %q", name, len(payload), string(out), payload)
			}
		}
	}
}
