package otelagentsession

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/everyapi-ai/everyapi-sdk/api"
	"go.opentelemetry.io/otel/attribute"
)

var _ func() Mapper = NewDevelopmentMapper

func TestDevelopmentMapperUsesCanonicalSessionAsConversationOnly(t *testing.T) {
	mapper := NewDevelopmentMapper()
	attrs := mapper.Attributes(Context{Session: api.AgentSessionSummary{
		ID:                 "55f46b64-75a1-4f07-93d6-29b67c730b61",
		AgentKind:          "codex",
		AgentVersion:       "1.2.3",
		IdentitySource:     "explicit_session",
		IdentityConfidence: "high",
		Status:             api.AgentSessionStatusActive,
		RequestCount:       8,
	}})
	values := attributeMap(attrs)

	if got := values["gen_ai.conversation.id"].AsString(); got != "55f46b64-75a1-4f07-93d6-29b67c730b61" {
		t.Fatalf("gen_ai.conversation.id = %q", got)
	}
	if _, ok := values["gen_ai.agent.id"]; ok {
		t.Fatal("canonical Session UUID must not be exported as gen_ai.agent.id")
	}
	if got := values["everyapi.agent.kind"].AsString(); got != "codex" {
		t.Fatalf("everyapi.agent.kind = %q", got)
	}
	if got := values["everyapi.agent.version"].AsString(); got != "1.2.3" {
		t.Fatalf("everyapi.agent.version = %q", got)
	}
	if got := values["everyapi.agent_session.request_count"].AsInt64(); got != 8 {
		t.Fatalf("everyapi.agent_session.request_count = %d", got)
	}

	wantKeys := []string{
		"everyapi.agent.kind",
		"everyapi.agent.version",
		"everyapi.agent_session.identity.confidence",
		"everyapi.agent_session.identity.source",
		"everyapi.agent_session.request_count",
		"everyapi.agent_session.status",
		"gen_ai.conversation.id",
	}
	gotKeys := make([]string, 0, len(values))
	for key := range values {
		gotKeys = append(gotKeys, key)
	}
	slices.Sort(gotKeys)
	if !slices.Equal(gotKeys, wantKeys) {
		t.Fatalf("attribute keys = %v, want %v", gotKeys, wantKeys)
	}
}

func TestDevelopmentMapperEmitsOnlyAnExplicitStableAgentID(t *testing.T) {
	mapper := NewDevelopmentMapper()
	values := attributeMap(mapper.Attributes(Context{
		Session: api.AgentSessionSummary{ID: "session-id", AgentKind: "claude"},
		AgentID: "  hosted-agent-42  ",
	}))
	if got := values["gen_ai.agent.id"].AsString(); got != "hosted-agent-42" {
		t.Fatalf("gen_ai.agent.id = %q", got)
	}
}

func TestDevelopmentMapperNeverExportsContentAttributes(t *testing.T) {
	mapper := NewDevelopmentMapper()
	attrs := mapper.Attributes(Context{Session: api.AgentSessionSummary{
		ID:                 "session-id",
		AgentKind:          "codex",
		IdentitySource:     "codex_thread",
		IdentityConfidence: "medium",
	}})
	values := attributeMap(attrs)
	for _, key := range []string{
		"gen_ai.input.messages",
		"gen_ai.output.messages",
		"gen_ai.system_instructions",
		"gen_ai.tool.call.arguments",
		"gen_ai.tool.call.result",
		"everyapi.agent_session.alias",
		"everyapi.agent_session.prompt",
		"everyapi.agent_session.response",
	} {
		if _, ok := values[key]; ok {
			t.Fatalf("content/private attribute %q was exported", key)
		}
	}
}

func TestDevelopmentMapperIgnoresCallerContentByDefault(t *testing.T) {
	mapper := NewDevelopmentMapper()
	values := attributeMap(mapper.Attributes(Context{
		Session: api.AgentSessionSummary{ID: "session-id"},
		Content: &ContentAttributes{
			SystemInstructions: json.RawMessage(`[{"type":"text","content":"private system"}]`),
			InputMessages:      json.RawMessage(`[{"role":"user","parts":[{"type":"text","content":"private input"}]}]`),
			OutputMessages:     json.RawMessage(`[{"role":"assistant","parts":[{"type":"text","content":"private output"}],"finish_reason":"stop"}]`),
		},
	}))

	for _, key := range []string{
		"gen_ai.system_instructions",
		"gen_ai.input.messages",
		"gen_ai.output.messages",
	} {
		if _, ok := values[key]; ok {
			t.Fatalf("default mapper exported opt-in content attribute %q", key)
		}
	}
}

func TestDevelopmentMapperEmitsValidContentAfterExplicitOptIn(t *testing.T) {
	mapper := NewDevelopmentMapperWithOptions(WithContentAttributes())
	values := attributeMap(mapper.Attributes(Context{
		Session: api.AgentSessionSummary{ID: "session-id"},
		Content: &ContentAttributes{
			SystemInstructions: json.RawMessage(`[{"type":"text","content":"system"}]`),
			InputMessages:      json.RawMessage(`[{"role":"user","parts":[{"type":"text","content":"input"}]}]`),
			OutputMessages:     json.RawMessage(`[{"role":"assistant","parts":[{"type":"text","content":"output"}],"finish_reason":"stop"}]`),
		},
	}))

	if got := values["gen_ai.system_instructions"].AsString(); got != `[{"type":"text","content":"system"}]` {
		t.Fatalf("gen_ai.system_instructions = %q", got)
	}
	if got := values["gen_ai.input.messages"].AsString(); got != `[{"role":"user","parts":[{"type":"text","content":"input"}]}]` {
		t.Fatalf("gen_ai.input.messages = %q", got)
	}
	if got := values["gen_ai.output.messages"].AsString(); got != `[{"role":"assistant","parts":[{"type":"text","content":"output"}],"finish_reason":"stop"}]` {
		t.Fatalf("gen_ai.output.messages = %q", got)
	}
}

func TestDevelopmentMapperRejectsSchemaInvalidOptInContent(t *testing.T) {
	tests := []struct {
		name    string
		key     string
		content ContentAttributes
	}{
		{
			name:    "system item is not an object",
			key:     "gen_ai.system_instructions",
			content: ContentAttributes{SystemInstructions: json.RawMessage(`[1]`)},
		},
		{
			name:    "system item omits type",
			key:     "gen_ai.system_instructions",
			content: ContentAttributes{SystemInstructions: json.RawMessage(`[{}]`)},
		},
		{
			name:    "system type is not a string",
			key:     "gen_ai.system_instructions",
			content: ContentAttributes{SystemInstructions: json.RawMessage(`[{"type":1}]`)},
		},
		{
			name:    "system type is null",
			key:     "gen_ai.system_instructions",
			content: ContentAttributes{SystemInstructions: json.RawMessage(`[{"type":null}]`)},
		},
		{
			name:    "input message is not an object",
			key:     "gen_ai.input.messages",
			content: ContentAttributes{InputMessages: json.RawMessage(`[1]`)},
		},
		{
			name:    "input message omits parts",
			key:     "gen_ai.input.messages",
			content: ContentAttributes{InputMessages: json.RawMessage(`[{"role":"user"}]`)},
		},
		{
			name:    "input role is not a string",
			key:     "gen_ai.input.messages",
			content: ContentAttributes{InputMessages: json.RawMessage(`[{"role":1,"parts":[]}]`)},
		},
		{
			name:    "input role is null",
			key:     "gen_ai.input.messages",
			content: ContentAttributes{InputMessages: json.RawMessage(`[{"role":null,"parts":[]}]`)},
		},
		{
			name:    "input part is not an object",
			key:     "gen_ai.input.messages",
			content: ContentAttributes{InputMessages: json.RawMessage(`[{"role":"user","parts":[1]}]`)},
		},
		{
			name:    "input part omits type",
			key:     "gen_ai.input.messages",
			content: ContentAttributes{InputMessages: json.RawMessage(`[{"role":"user","parts":[{}]}]`)},
		},
		{
			name:    "output omits finish reason",
			key:     "gen_ai.output.messages",
			content: ContentAttributes{OutputMessages: json.RawMessage(`[{"role":"assistant","parts":[]}]`)},
		},
		{
			name:    "output finish reason is not a string",
			key:     "gen_ai.output.messages",
			content: ContentAttributes{OutputMessages: json.RawMessage(`[{"role":"assistant","parts":[],"finish_reason":1}]`)},
		},
		{
			name:    "output finish reason is null",
			key:     "gen_ai.output.messages",
			content: ContentAttributes{OutputMessages: json.RawMessage(`[{"role":"assistant","parts":[],"finish_reason":null}]`)},
		},
	}

	mapper := NewDevelopmentMapperWithOptions(WithContentAttributes())
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			values := attributeMap(mapper.Attributes(Context{
				Session: api.AgentSessionSummary{ID: "session-id"},
				Content: &test.content,
			}))
			if _, ok := values[test.key]; ok {
				t.Fatalf("mapper exported schema-invalid content attribute %q", test.key)
			}
		})
	}
}

func TestDevelopmentMapperOmitsInvalidOrBlankOptInContent(t *testing.T) {
	mapper := NewDevelopmentMapperWithOptions(WithContentAttributes())
	values := attributeMap(mapper.Attributes(Context{
		Session: api.AgentSessionSummary{ID: "session-id"},
		Content: &ContentAttributes{
			SystemInstructions: json.RawMessage(`not-json`),
			InputMessages:      json.RawMessage(`   `),
		},
	}))

	for _, key := range []string{"gen_ai.system_instructions", "gen_ai.input.messages"} {
		if _, ok := values[key]; ok {
			t.Fatalf("mapper exported invalid content attribute %q", key)
		}
	}
}

func TestDevelopmentMapperOmitsContentOutsideSchemaArrayShape(t *testing.T) {
	mapper := NewDevelopmentMapperWithOptions(WithContentAttributes())
	values := attributeMap(mapper.Attributes(Context{
		Session: api.AgentSessionSummary{ID: "session-id"},
		Content: &ContentAttributes{
			SystemInstructions: json.RawMessage(`{"type":"text","content":"not an array"}`),
			InputMessages:      json.RawMessage(`"not an array"`),
			OutputMessages:     json.RawMessage(`null`),
		},
	}))

	for _, key := range []string{
		"gen_ai.system_instructions",
		"gen_ai.input.messages",
		"gen_ai.output.messages",
	} {
		if _, ok := values[key]; ok {
			t.Fatalf("mapper exported content outside the GenAI schema array shape: %q", key)
		}
	}
}

func TestDevelopmentMapperOmitsBlankValues(t *testing.T) {
	mapper := NewDevelopmentMapper()
	if attrs := mapper.Attributes(Context{}); len(attrs) != 0 {
		t.Fatalf("blank context exported attributes: %#v", attrs)
	}
}

func attributeMap(attrs []attribute.KeyValue) map[string]attribute.Value {
	values := make(map[string]attribute.Value, len(attrs))
	for _, item := range attrs {
		values[string(item.Key)] = item.Value
	}
	return values
}
