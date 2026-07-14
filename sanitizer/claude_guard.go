package sanitizer

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
)

var claudeGuardInlineCode = regexp.MustCompile("`[^`\\n]*`")

// anthropicSSEHasToolCallCorruption recognizes the stable Opus 4.8 failure
// where a tool call is serialized into the assistant text channel instead of
// a structured tool_use block. The caller supplies one complete Anthropic SSE
// response; buffering is intentional because no response bytes may reach
// Claude Code before the terminal stop_reason has been validated.
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
