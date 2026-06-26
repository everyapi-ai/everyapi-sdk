package sanitizer

import (
	"strings"
	"testing"
)

// tok32 is a stand-in 32-hex placeholder token for tests that need a
// well-formed-but-arbitrary token without minting one through a mapping.
func tok32(c byte) string { return strings.Repeat(string(c), placeholderTokenLen) }

func TestMakePlaceholder(t *testing.T) {
	token := tok32('a')
	want := "<<__EVERYAPI_SECRET_" + token + "__>>"
	if got := MakePlaceholder(token); got != want {
		t.Errorf("MakePlaceholder(%q) = %q, want %q", token, got, want)
	}
}

func TestFindPlaceholders(t *testing.T) {
	p1 := MakePlaceholder(tok32('a'))
	p2 := MakePlaceholder(tok32('b'))
	s := "hello " + p1 + " and " + p2 + " world"
	got := FindPlaceholders(s)
	if len(got) != 2 {
		t.Fatalf("want 2 placeholders, got %d (%v)", len(got), got)
	}
	if s[got[0][0]:got[0][1]] != p1 {
		t.Errorf("first span = %q, want %q", s[got[0][0]:got[0][1]], p1)
	}
	if s[got[1][0]:got[1][1]] != p2 {
		t.Errorf("second span = %q, want %q", s[got[1][0]:got[1][1]], p2)
	}
}

func TestFindPlaceholders_None(t *testing.T) {
	if got := FindPlaceholders("nothing to see here"); got != nil {
		t.Errorf("want nil, got %v", got)
	}
}

func TestFindPlaceholders_WrongBodyCharset(t *testing.T) {
	// Old dense-numeric ids and non-hex bodies must NOT match the new
	// regex — they're not tokens this scheme mints.
	for _, body := range []string{"001", "999", strings.Repeat("g", 32), strings.Repeat("a", 31)} {
		s := "x " + PlaceholderPrefix + body + PlaceholderSuffix + " y"
		if got := FindPlaceholders(s); got != nil {
			t.Errorf("body %q should not match placeholderRE, got %v", body, got)
		}
	}
}

func TestPartialAtTail_NoMatch(t *testing.T) {
	full := MakePlaceholder(tok32('a'))
	cases := []string{
		"",
		"hello world",
		full + " done",                  // complete, not partial
		"this is not the prefix at all", // no prefix
		PlaceholderPrefix + "hello world",
	}
	for _, s := range cases {
		if got := PartialAtTail(s); got != -1 {
			t.Errorf("PartialAtTail(%q) = %d, want -1", s, got)
		}
	}
}

func TestPartialAtTail_PrefixPartial(t *testing.T) {
	full := MakePlaceholder(tok32('a'))
	for end := 1; end < len(PlaceholderPrefix); end++ {
		prefix := full[:end]
		s := "lorem ipsum " + prefix
		idx := PartialAtTail(s)
		if idx < 0 {
			t.Errorf("PartialAtTail(%q) should detect partial prefix, got -1", s)
			continue
		}
		if got := s[idx:]; got != prefix {
			t.Errorf("PartialAtTail(%q) idx=%d gives %q, want %q", s, idx, got, prefix)
		}
	}
}

func TestPartialAtTail_TokenAccumulating(t *testing.T) {
	// Prefix present, fewer than the full token's hex chars so far.
	s := "lorem " + PlaceholderPrefix + "1a2b"
	if got := PartialAtTail(s); got != 6 {
		t.Errorf("PartialAtTail(%q) = %d, want 6", s, got)
	}
}

func TestPartialAtTail_SuffixPartial(t *testing.T) {
	// Full token then a partial closing `__>>`.
	for end := 1; end < len(PlaceholderSuffix); end++ {
		s := "lorem " + PlaceholderPrefix + tok32('c') + PlaceholderSuffix[:end]
		if got := PartialAtTail(s); got != 6 {
			t.Errorf("PartialAtTail(%q) = %d, want 6", s, got)
		}
	}
}

func TestPartialAtTail_TokenDoneNoSuffix(t *testing.T) {
	s := "x " + PlaceholderPrefix + tok32('d')
	if got := PartialAtTail(s); got != 2 {
		t.Errorf("PartialAtTail(%q) = %d, want 2", s, got)
	}
}

func TestPartialAtTail_NonHexBeforeTokenDone(t *testing.T) {
	// A non-hex byte before the token is full → not our placeholder.
	s := "x " + PlaceholderPrefix + "1a2z" // 'z' is not hex
	if got := PartialAtTail(s); got != -1 {
		t.Errorf("PartialAtTail(%q) = %d, want -1 (non-hex, not a partial)", s, got)
	}
}

func TestPartialAtTail_CompletePlaceholderAtTailIsNotPartial(t *testing.T) {
	s := "lorem " + MakePlaceholder(tok32('a'))
	if got := PartialAtTail(s); got != -1 {
		t.Errorf("PartialAtTail(%q) = %d, want -1 (complete, not partial)", s, got)
	}
}

func TestPlaceholderPrefixSuffixDistinct(t *testing.T) {
	if strings.Contains("{}\"\\n", PlaceholderPrefix) || strings.Contains("{}\"\\n", PlaceholderSuffix) {
		t.Errorf("placeholder brackets collide with common JSON chars")
	}
}
