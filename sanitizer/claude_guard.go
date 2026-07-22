package sanitizer

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

var claudeGuardInlineCode = regexp.MustCompile("`[^`\\n]*`")

type claudeGuardStream struct {
	source     io.ReadCloser
	reader     *bufio.Reader
	pending    []byte
	held       []byte
	blockText  strings.Builder
	guardBlock bool
	polluted   bool
}

const maxClaudeGuardEventBytes = 16 << 20
const maxClaudeGuardBlockText = 1 << 20
const maxClaudeGuardHeldBytes = 2 << 20

func newClaudeGuardStream(source io.ReadCloser) io.ReadCloser {
	return &claudeGuardStream{source: source, reader: bufio.NewReader(source), guardBlock: true}
}

func (s *claudeGuardStream) Read(p []byte) (int, error) {
	for len(s.pending) == 0 {
		event, err := readClaudeSSEEvent(s.reader)
		if len(event) > 0 {
			s.consume(event)
		}
		if err != nil {
			if len(s.pending) == 0 && len(s.held) > 0 && !s.polluted {
				s.flushHeld()
			}
			if len(s.pending) == 0 {
				return 0, err
			}
			break
		}
	}
	n := copy(p, s.pending)
	s.pending = s.pending[n:]
	return n, nil
}

func (s *claudeGuardStream) consume(event []byte) {
	eventType, text, isText := claudeSSEEventText(event)
	switch eventType {
	case "content_block_start":
		s.flushHeld()
		s.blockText.Reset()
		s.guardBlock = true
		s.polluted = false
	case "content_block_stop":
		if !s.polluted {
			s.flushHeld()
		}
		s.held = nil
		s.blockText.Reset()
		s.guardBlock = false
		s.polluted = false
	}
	if !isText || !s.guardBlock {
		if len(s.held) > 0 && (eventType == "" || eventType == "ping") {
			s.hold(event)
			return
		}
		if !s.polluted {
			s.flushHeld()
		}
		s.pending = append(s.pending, event...)
		return
	}
	if s.polluted {
		return
	}
	if s.blockText.Len()+len(text) > maxClaudeGuardBlockText {
		s.flushHeld()
		s.guardBlock = false
		s.pending = append(s.pending, event...)
		return
	}
	s.blockText.WriteString(text)
	full := stripClaudeGuardMarkdownCode(s.blockText.String())
	// Line signals must not see the unterminated last line: a delta boundary
	// falling right after a word at the start of a prose line would otherwise
	// fabricate a standalone repeat and drop a clean block. Runs tokenize on
	// whitespace, so they read the full text (a partial word can only delay a
	// run match, never invent one). The final full-text check happens at
	// content_block_stop, before the held flush.
	lineView := full
	if !strings.HasSuffix(full, "\n") {
		if i := strings.LastIndexByte(full, '\n'); i >= 0 {
			lineView = full[:i+1]
		} else {
			lineView = ""
		}
	}
	if repeatedStandaloneLineDominatesTail(lineView, 3) || LongestTokenRun(full) >= 5 ||
		LeakedToolMarkup(full) ||
		strings.Contains(full, "The model's tool call could not be parsed (retry also failed).") {
		s.held = nil
		s.polluted = true
		return
	}
	// Hold (delay, never drop) while the flood shape MIGHT be forming — a
	// second standalone repeat, or a run still in progress at the tail. The
	// trailing-run form (not the longest run anywhere) is what lets ordinary
	// doubled words pass: "that that is true" has a trailing run of 1 once
	// the sentence continues, so a hold started on the doubled word is
	// released on the next delta instead of freezing the block. flushHeld
	// re-checks the full text before releasing, so lifting a hold can never
	// leak a confirmed flood.
	if RepeatedStandaloneLine(lineView, 2) || trailingTokenRun(full) >= 2 {
		s.hold(event)
		return
	}
	if len(s.held) > 0 {
		s.flushHeld()
		if s.polluted {
			return
		}
	}
	s.pending = append(s.pending, event...)
}

func (s *claudeGuardStream) hold(event []byte) {
	if len(s.held)+len(event) > maxClaudeGuardHeldBytes {
		s.flushHeld()
		s.guardBlock = false
		s.pending = append(s.pending, event...)
		return
	}
	s.held = append(s.held, event...)
}

// flushHeld releases the held events — but first re-checks the block's FULL
// text. The per-delta strong pass excludes the unterminated last line, and
// many streams end a block without an explicit content_block_stop (the next
// content_block_start, a message_delta, or EOF closes it instead), so this
// release point is the last place a flood ending at the block boundary can
// still be confirmed and dropped.
func (s *claudeGuardStream) flushHeld() {
	if len(s.held) > 0 && !s.polluted &&
		claudeTextHasStrongPollution(stripClaudeGuardMarkdownCode(s.blockText.String())) {
		s.polluted = true
		s.held = nil
		return
	}
	s.pending = append(s.pending, s.held...)
	s.held = nil
}

func (s *claudeGuardStream) Close() error { return s.source.Close() }

func readClaudeSSEEvent(reader *bufio.Reader) ([]byte, error) {
	var event []byte
	for {
		line, err := reader.ReadSlice('\n')
		event = append(event, line...)
		if len(event) >= maxClaudeGuardEventBytes {
			return event, nil
		}
		if bytes.Equal(line, []byte("\n")) || bytes.Equal(line, []byte("\r\n")) {
			return event, err
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		if err != nil {
			return event, err
		}
	}
}

func claudeSSEEventText(raw []byte) (eventType, text string, isText bool) {
	data, ok := sseEventData(raw)
	if !ok {
		return "", "", false
	}
	var event struct {
		Type  string `json:"type"`
		Delta struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"delta"`
	}
	if json.Unmarshal(data, &event) != nil {
		return "", "", false
	}
	return event.Type, event.Delta.Text,
		event.Type == "content_block_delta" && event.Delta.Type == "text_delta"
}

// The degeneration flood token mutates faster than any control-word list can
// track (course/court/課/课/... were all observed in the wild before this
// package stopped chasing them). Detection is therefore SHAPE-based: the two
// invariants across every observed variant are
//
//   - one identical short single-token line standing alone, over and over
//     (RepeatedStandaloneLine / RepeatedStandaloneLineTokens), which also
//     catches interleaved floods where two tokens alternate, and
//   - one short token repeated back-to-back inside a line ("course course
//     course …"), which LongestTokenRun measures (newlines are whitespace to
//     strings.Fields, so a pure line flood counts here too).
//
// Callers strip fenced code first (stripClaudeGuardMarkdownCode / the CLI's
// stripClaudeMarkdownCode) so code listings with repeated short lines ("end",
// "fi", ...) never feed the counters.

// claudeFloodToken reports whether s can be a flood token: word-sized and
// letter-bearing, so rules like "---" or long prose lines never count. The
// cap is in runes, not bytes — a byte cap would admit 32 Latin letters but
// only 10 CJK characters, exempting longer CJK flood phrases from detection.
// Every corpus flood token fits well under 16 runes ("parameter" is 9).
func claudeFloodToken(s string) bool {
	return s != "" && utf8.RuneCountInString(s) <= 16 && strings.ContainsFunc(s, unicode.IsLetter)
}

// StandaloneLineTokens returns each flood-shaped token that stands alone on a
// line, with the number of lines it occupies. Empty on clean prose. Callers
// derive their signal from the map: in-block repetition here (see
// RepeatedStandaloneLine), or accumulation across adjacent assistant turns in
// the CLI's recovery clusterer, so a flood smeared thinly over several turns
// still crosses a threshold.
func StandaloneLineTokens(text string) map[string]int {
	counts := map[string]int{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		// Single token only: interior whitespace (any Unicode space, so an
		// ideographic space also splits) means prose or list items, which
		// repeat legitimately ("- done"). Keys are lowercased to match
		// LongestTokenRun — a case-varying flood must not split across keys.
		if strings.ContainsFunc(line, unicode.IsSpace) || !claudeFloodToken(line) {
			continue
		}
		counts[strings.ToLower(line)]++
	}
	return counts
}

// RepeatedStandaloneLine reports whether any single short token stands alone
// on at least minRepeat lines (not necessarily adjacent).
func RepeatedStandaloneLine(text string, minRepeat int) bool {
	for _, n := range StandaloneLineTokens(text) {
		if n >= minRepeat {
			return true
		}
	}
	return false
}

// trailingTokenRun returns the length of the back-to-back run of one
// flood-shaped token at the very END of text — i.e. a repetition that is
// still in progress. A doubled word in the middle of prose ("that that is
// true") has a trailing run of 1 and is not suspicious; a stream currently
// emitting "court court" is.
func trailingTokenRun(text string) int {
	words := strings.Fields(strings.ToLower(text))
	run := 0
	last := ""
	for i := len(words) - 1; i >= 0; i-- {
		word := strings.Trim(words[i], `.,:;!?"'()[]{}<>。，`)
		if !claudeFloodToken(word) {
			break
		}
		if last == "" {
			last = word
			run = 1
			continue
		}
		if word != last {
			break
		}
		run++
	}
	return run
}

// LongestTokenRun returns the longest back-to-back run of one flood-shaped
// token under whitespace tokenization, trailing punctuation ignored
// ("course." continues a "course" run).
func LongestTokenRun(text string) int {
	longest, run := 0, 0
	previous := ""
	for _, word := range strings.Fields(strings.ToLower(text)) {
		word = strings.Trim(word, `.,:;!?"'()[]{}<>。，`)
		if !claudeFloodToken(word) {
			previous, run = "", 0
			continue
		}
		if word == previous {
			run++
		} else {
			previous, run = word, 1
		}
		if run > longest {
			longest = run
		}
	}
	return longest
}

// repeatedStandaloneLineDominatesTail reports whether some token stands alone
// on >= minRepeat lines AND lines of REPEATING tokens (standalone count >= 2,
// any of them — an interleaved two-token flood counts in full) make up more
// than 2/3 of the non-blank lines from that token's first appearance to the
// end of text. Real floods trail the prose and repeat their few tokens over
// and over; a legitimate label/value checklist ("auth-service\nPassed\n
// billing\nPassed\nweb\nPassed") repeats only the value while every label is
// one-off, so its repeating-line share stays at or below the bar. One-off
// lone lines dilute rather than reinforce.
func repeatedStandaloneLineDominatesTail(text string, minRepeat int) bool {
	lines := strings.Split(text, "\n")
	tokens := make([]string, len(lines))
	blank := make([]bool, len(lines))
	counts := map[string]int{}
	firstAt := map[string]int{}
	for i, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" {
			blank[i] = true
			continue
		}
		if !strings.ContainsFunc(line, unicode.IsSpace) && claudeFloodToken(line) {
			token := strings.ToLower(line)
			tokens[i] = token
			counts[token]++
			if _, seen := firstAt[token]; !seen {
				firstAt[token] = i
			}
		}
	}
	for token, n := range counts {
		if n < minRepeat {
			continue
		}
		repeatingLines, nonBlank := 0, 0
		for i := firstAt[token]; i < len(lines); i++ {
			if blank[i] {
				continue
			}
			nonBlank++
			if tokens[i] != "" && counts[tokens[i]] >= 2 {
				repeatingLines++
			}
		}
		if nonBlank > 0 && repeatingLines*3 > nonBlank*2 {
			return true
		}
	}
	return false
}

// LeakedToolMarkup reports whether text carries the model's tool-call wire
// markup leaked into visible prose — `invoke name="` followed by
// `parameter name=`. Unlike the retired flood word lists this is a fixed
// protocol frame, not a mutating token: the markup IS the tool-call syntax,
// so matching it is structural detection, not content chasing. The leading
// `<` is deliberately not required: in-the-wild variants mangle the opening
// bracket (e.g. a leaked `antml:invoke name="…` prefix) while the parameter
// markup survives.
func LeakedToolMarkup(text string) bool {
	invoke := strings.Index(text, `invoke name="`)
	return invoke >= 0 && strings.Contains(text[invoke:], `parameter name=`)
}

// claudeTextHasStrongPollution takes text already stripped of fenced code.
func claudeTextHasStrongPollution(visible string) bool {
	if repeatedStandaloneLineDominatesTail(visible, 3) {
		return true
	}
	// 5, not 3: with no word list narrowing the match, legitimate emphasis
	// ("no no no") must stay clear. Every corpus incident repeats >= 8.
	if LongestTokenRun(visible) >= 5 {
		return true
	}
	if LeakedToolMarkup(visible) {
		return true
	}
	return strings.Contains(visible, "The model's tool call could not be parsed (retry also failed).")
}

// anthropicSSEHasToolCallCorruption recognizes the stable Opus 4.8 failure in
// complete captured streams. Production forwarding uses claudeGuardStream's
// event-level detector so clean responses retain streaming latency.
func anthropicSSEHasToolCallCorruption(stream []byte) bool {
	var text strings.Builder
	stopReason := ""
	structuredToolUse := false

	for len(stream) > 0 {
		end := nextEventBoundary(stream)
		if end < 0 {
			end = len(stream)
		}
		raw := stream[:end]
		stream = stream[end:]
		data, ok := sseEventData(raw)
		if !ok {
			continue
		}
		var event map[string]any
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.UseNumber()
		if err := dec.Decode(&event); err != nil {
			continue
		}
		switch eventType, _ := event["type"].(string); eventType {
		case "content_block_start":
			if block, ok := event["content_block"].(map[string]any); ok {
				blockType, _ := block["type"].(string)
				if strings.HasSuffix(blockType, "tool_use") {
					structuredToolUse = true
				}
			}
		case "content_block_delta":
			if delta, ok := event["delta"].(map[string]any); ok {
				if deltaType, _ := delta["type"].(string); deltaType == "text_delta" {
					if value, ok := delta["text"].(string); ok {
						text.WriteString(value)
					}
				}
			}
		case "message_delta":
			if delta, ok := event["delta"].(map[string]any); ok {
				stopReason, _ = delta["stop_reason"].(string)
			}
		}
	}

	visible := stripClaudeGuardMarkdownCode(text.String())
	if LeakedToolMarkup(visible) {
		return true
	}
	if strings.Contains(visible, "The model's tool call could not be parsed (retry also failed).") {
		return true
	}
	// A tool_use stop without any structured tool block is invalid on the
	// Anthropic wire. This structural check catches variants whose leaked
	// control token is new and therefore absent from the lexical list below.
	if stopReason == "tool_use" && !structuredToolUse {
		return true
	}

	// The shape fallback only applies when the corruption's defining
	// symptom is present: a tool-ish stop with NO structured tool_use
	// block. A response that carries a real tool_use block is functional
	// for Claude Code even if its narration happens to repeat a word, and
	// rejecting it would hard-fail a valid turn (and bill its output
	// tokens again on retry). stop_sequence without a tool block is a
	// perfectly valid completion whenever the caller supplies
	// stop_sequences, so that path keeps the full strong thresholds; only
	// tool_use-without-a-block (invalid on the wire by itself) may use the
	// lower ones.
	if structuredToolUse {
		return false
	}
	switch stopReason {
	case "tool_use":
		return RepeatedStandaloneLine(visible, 2) || LongestTokenRun(visible) >= 3
	case "stop_sequence":
		return repeatedStandaloneLineDominatesTail(visible, 3) || LongestTokenRun(visible) >= 5
	default:
		return false
	}
}

func sseEventData(raw []byte) ([]byte, bool) {
	var parts [][]byte
	for _, line := range bytes.Split(raw, []byte("\n")) {
		line = bytes.TrimSuffix(line, []byte("\r"))
		if !bytes.HasPrefix(line, []byte("data:")) {
			continue
		}
		data := line[len("data:"):]
		if len(data) > 0 && data[0] == ' ' {
			data = data[1:]
		}
		parts = append(parts, data)
	}
	return bytes.Join(parts, []byte("\n")), len(parts) > 0
}

func stripClaudeGuardMarkdownCode(text string) string {
	var kept []string
	fence := ""
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		// Only the marker that opened a fence can close it, so a ~~~ block
		// quoting ``` lines (or vice versa) doesn't flip state mid-fence.
		if fence != "" {
			if strings.HasPrefix(trimmed, fence) {
				fence = ""
			}
			continue
		}
		if strings.HasPrefix(trimmed, "```") {
			fence = "```"
			continue
		}
		if strings.HasPrefix(trimmed, "~~~") {
			fence = "~~~"
			continue
		}
		// Classic markdown indented code blocks are quoted examples too.
		if strings.HasPrefix(line, "    ") || strings.HasPrefix(line, "\t") {
			continue
		}
		kept = append(kept, line)
	}
	return claudeGuardInlineCode.ReplaceAllString(strings.Join(kept, "\n"), "")
}
