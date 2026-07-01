// Package sanitizer is the buyer-side privacy proxy described in
// docs/cli/channel-marketplace.md §7-2.
//
// Lifecycle:
//
//	everyapi proxy start  →  listen on :8888
//	buyer SDK ──────────▶  proxy intercepts
//	                       1. detect sensitive substrings in the request body
//	                       2. replace each with a stable placeholder
//	                       3. forward to the configured EveryAPI gateway
//	                       4. on response (streaming or buffered), undo the
//	                          substitution before returning bytes to the SDK
//
// The mapping table lives only in this process's memory and is dropped
// at shutdown. The platform never sees the real values, only the
// placeholder strings; the platform also cannot inject a placeholder
// the proxy doesn't recognise (the placeholder body is a keyed HMAC of
// the real secret, so a token the proxy didn't mint is not in its table
// and resolves to nothing), so a malicious upstream response can't trick
// the proxy into emitting attacker-controlled text into the SDK.
package sanitizer

import (
	"fmt"
	"regexp"
	"strings"
)

// PlaceholderPrefix / PlaceholderSuffix wrap the per-secret token. The
// bracketing chosen here is deliberately unusual so it never collides
// with anything an LLM is likely to emit on its own:
//
//   - `<<__` and `__>>` aren't valid HTML / Markdown / JSON syntax in
//     the same byte sequence
//   - all-caps "EVERYAPI_SECRET" makes it visually obvious in a prompt
//     dump that the value got substituted
//
// The body is a fixed-width lowercase-hex token (see placeholder.go's
// deriveToken): a truncated keyed HMAC of the real secret. That makes
// the placeholder stable across processes (identical secret → identical
// placeholder, so upstream prompt caching still hits) AND unguessable
// (an attacker can't fabricate or enumerate a valid token without the
// per-install key).
const (
	PlaceholderPrefix = "<<__EVERYAPI_SECRET_"
	PlaceholderSuffix = "__>>"
)

// MakePlaceholder returns the wire form for the given placeholder token
// (the lowercase-hex HMAC body produced by deriveToken).
func MakePlaceholder(token string) string {
	return PlaceholderPrefix + token + PlaceholderSuffix
}

// placeholderRE matches a fully-formed placeholder. Used by the response
// restore passes to find substitution targets. The body charset is
// lowercase hex of a fixed width, anchored tightly so literal text that
// merely opens with our prefix can't be mistaken for a placeholder.
var placeholderRE = regexp.MustCompile(
	regexp.QuoteMeta(PlaceholderPrefix) +
		fmt.Sprintf("[0-9a-f]{%d}", placeholderTokenLen) +
		regexp.QuoteMeta(PlaceholderSuffix),
)

// FindPlaceholders returns the byte spans of every complete
// placeholder inside s.
func FindPlaceholders(s string) [][]int {
	return placeholderRE.FindAllStringIndex(s, -1)
}

// placeholderToken extracts the hex token from a complete placeholder
// string (as returned by MakePlaceholder / matched by placeholderRE).
func placeholderToken(placeholder string) string {
	return placeholder[len(PlaceholderPrefix) : len(placeholder)-len(PlaceholderSuffix)]
}

func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
}

// PartialAtTail reports whether the suffix of s might be the prefix of a
// placeholder that hasn't fully streamed in yet, so a streaming restorer
// knows how many tail bytes to hold back as carryover pending the next
// chunk. Returns the byte offset where the partial match starts, or -1
// if no suffix of s could grow into a placeholder.
//
// We can't blindly carry over the maximum-placeholder-length bytes
// because we'd starve callers expecting promptly-flushed streams; we
// can't always emit the whole chunk because half of a placeholder split
// across two chunks would never get reassembled.
func PartialAtTail(s string) int {
	if len(s) == 0 {
		return -1
	}
	// Case 1: a proper prefix of PlaceholderPrefix sits at the tail (the
	// opening brackets themselves are still streaming in).
	maxTail := len(PlaceholderPrefix) - 1
	if maxTail > len(s) {
		maxTail = len(s)
	}
	for i := len(s) - maxTail; i < len(s); i++ {
		if i < 0 {
			continue
		}
		rem := s[i:]
		if len(rem) <= len(PlaceholderPrefix) && PlaceholderPrefix[:len(rem)] == rem {
			return i
		}
	}
	// Case 2: the full prefix is present but the hex token and/or the
	// closing suffix haven't finished arriving.
	last := strings.LastIndex(s, PlaceholderPrefix)
	if last < 0 {
		return -1
	}
	body := s[last+len(PlaceholderPrefix):]
	// Count leading hex chars of the token.
	nhex := 0
	for nhex < len(body) && isHexDigit(body[nhex]) {
		nhex++
	}
	if nhex < placeholderTokenLen {
		// Token still accumulating. Hold back only if every byte we've
		// seen so far is a hex digit; a non-hex byte before the token is
		// complete means this isn't our placeholder (just literal text
		// that opened with the prefix).
		if nhex == len(body) {
			return last
		}
		return -1
	}
	// Token complete (>= full width). Inspect what follows for the suffix.
	rest := body[placeholderTokenLen:]
	if len(rest) == 0 {
		// Token done, suffix not yet streamed — hold back.
		return last
	}
	if len(rest) >= len(PlaceholderSuffix) {
		// Either a complete placeholder (placeholderRE handles it) or
		// trailing literal text — nothing partial to hold.
		return -1
	}
	if PlaceholderSuffix[:len(rest)] == rest {
		// Partial closing suffix — hold back.
		return last
	}
	return -1
}
