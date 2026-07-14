package sanitizer

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"regexp"
	"strings"
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
	if claudeTextHasStrongPollution(s.blockText.String()) {
		s.held = nil
		s.polluted = true
		return
	}
	if claudeTextHasPollutionCandidate(text) || len(s.held) > 0 {
		s.hold(event)
		return
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

func (s *claudeGuardStream) flushHeld() {
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

func claudeTextHasPollutionCandidate(text string) bool {
	lower := strings.ToLower(text)
	for _, marker := range []string{"course", "court", "課", "invoke name", "parameter name", "antml:"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func claudeTextHasStrongPollution(text string) bool {
	visible := stripClaudeGuardMarkdownCode(text)
	if invoke := strings.Index(visible, `invoke name="`); invoke >= 0 &&
		strings.Contains(visible[invoke:], `parameter name=`) {
		return true
	}
	if strings.Contains(visible, "The model's tool call could not be parsed (retry also failed).") {
		return true
	}
	previous := ""
	repeated := 0
	for _, word := range strings.Fields(strings.ToLower(visible)) {
		word = strings.Trim(word, `.,:;!?"'()[]{}<>`)
		switch word {
		case "course", "court", "課":
			if word == previous {
				repeated++
			} else {
				previous, repeated = word, 1
			}
			if repeated >= 3 {
				return true
			}
		default:
			previous, repeated = "", 0
		}
	}
	return false
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
	// Match `invoke name="` without requiring the leading `<`: in-the-wild
	// variants of the corruption mangle the opening bracket (e.g. a leaked
	// `antml:invoke name="...` prefix) while the parameter markup survives.
	if invoke := strings.Index(visible, `invoke name="`); invoke >= 0 &&
		strings.Contains(visible[invoke:], `parameter name=`) {
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

	standalone := 0
	for _, line := range strings.Split(visible, "\n") {
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "call", "course", "court", "count", "invoke", "parameter", "課":
			standalone++
		}
	}
	// The lexical fallback only applies when the corruption's defining
	// symptom is present: a tool-ish stop with NO structured tool_use
	// block. A response that carries a real tool_use block is functional
	// for Claude Code even if its narration happens to contain standalone
	// control words, and rejecting it would hard-fail a valid turn (and
	// bill its output tokens again on retry).
	return (stopReason == "tool_use" || stopReason == "stop_sequence") &&
		!structuredToolUse && standalone >= 2
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
