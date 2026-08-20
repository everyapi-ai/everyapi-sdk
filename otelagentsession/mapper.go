// Package otelagentsession maps EveryAPI's Agent Session contract onto
// OpenTelemetry GenAI attributes. Identity metadata is always content-free;
// sensitive instructions and messages require an explicit mapper option. The
// upstream GenAI semantic conventions are Development status, so callers
// depend on Mapper rather than on database fields or generated version-specific
// constants.
package otelagentsession

import (
	"encoding/json"
	"strings"

	"github.com/everyapi-ai/everyapi-sdk/api"
	"go.opentelemetry.io/otel/attribute"
)

const (
	conversationIDKey     = attribute.Key("gen_ai.conversation.id")
	agentIDKey            = attribute.Key("gen_ai.agent.id")
	agentKindKey          = attribute.Key("everyapi.agent.kind")
	agentVersionKey       = attribute.Key("everyapi.agent.version")
	identitySourceKey     = attribute.Key("everyapi.agent_session.identity.source")
	identityConfidence    = attribute.Key("everyapi.agent_session.identity.confidence")
	sessionStatusKey      = attribute.Key("everyapi.agent_session.status")
	requestCountKey       = attribute.Key("everyapi.agent_session.request_count")
	systemInstructionsKey = attribute.Key("gen_ai.system_instructions")
	inputMessagesKey      = attribute.Key("gen_ai.input.messages")
	outputMessagesKey     = attribute.Key("gen_ai.output.messages")
)

// ContentAttributes carries pre-serialized values that follow OpenTelemetry's
// GenAI JSON schemas. Content is ignored unless the mapper is constructed with
// WithContentAttributes.
type ContentAttributes struct {
	SystemInstructions json.RawMessage
	InputMessages      json.RawMessage
	OutputMessages     json.RawMessage
}

// Context carries Session identity plus optional caller-owned telemetry
// content. Content is ignored unless the mapper is explicitly configured to
// include it. AgentID is deliberately separate from Session.ID: OpenTelemetry
// defines gen_ai.agent.id as the stable identifier of a hosted Agent resource,
// while Session.ID is a conversation/session/thread identifier.
type Context struct {
	Session api.AgentSessionSummary
	AgentID string
	Content *ContentAttributes
}

// Mapper isolates the Development-status OpenTelemetry GenAI convention so a
// future convention revision can be swapped without changing the EveryAPI API
// schema or persisted Session model.
type Mapper interface {
	Attributes(Context) []attribute.KeyValue
}

type DevelopmentMapper struct {
	includeContent bool
}

type MapperOption func(*DevelopmentMapper)

// WithContentAttributes explicitly enables sensitive GenAI content attributes.
// The default mapper always ignores Context.Content.
func WithContentAttributes() MapperOption {
	return func(mapper *DevelopmentMapper) {
		mapper.includeContent = true
	}
}

var _ Mapper = DevelopmentMapper{}

// NewDevelopmentMapper returns the default, content-free mapper. Its exact
// zero-argument function signature is preserved for SDK compatibility.
func NewDevelopmentMapper() Mapper {
	return DevelopmentMapper{}
}

// NewDevelopmentMapperWithOptions returns a mapper configured with the given
// explicit options.
func NewDevelopmentMapperWithOptions(options ...MapperOption) Mapper {
	mapper := DevelopmentMapper{}
	for _, option := range options {
		if option != nil {
			option(&mapper)
		}
	}
	return mapper
}

// Attributes returns identity metadata and, only when explicitly configured,
// caller-supplied OpenTelemetry-formatted instructions and messages. It never
// derives content from the Session API or emits aliases. Explicitly supplied
// message arrays may contain tool arguments and results permitted by the schema.
func (mapper DevelopmentMapper) Attributes(input Context) []attribute.KeyValue {
	attrs := make([]attribute.KeyValue, 0, 11)
	appendString := func(key attribute.Key, value string) {
		if value = strings.TrimSpace(value); value != "" {
			attrs = append(attrs, key.String(value))
		}
	}

	appendString(conversationIDKey, input.Session.ID)
	appendString(agentIDKey, input.AgentID)
	appendString(agentKindKey, input.Session.AgentKind)
	appendString(agentVersionKey, input.Session.AgentVersion)
	appendString(identitySourceKey, input.Session.IdentitySource)
	appendString(identityConfidence, input.Session.IdentityConfidence)
	appendString(sessionStatusKey, string(input.Session.Status))
	if input.Session.RequestCount > 0 {
		attrs = append(attrs, requestCountKey.Int64(input.Session.RequestCount))
	}
	if mapper.includeContent && input.Content != nil {
		appendJSON := func(key attribute.Key, value json.RawMessage, validate func(json.RawMessage) ([]byte, bool)) {
			if value, ok := validate(value); ok {
				attrs = append(attrs, key.String(string(value)))
			}
		}
		appendJSON(systemInstructionsKey, input.Content.SystemInstructions, validateSystemInstructions)
		appendJSON(inputMessagesKey, input.Content.InputMessages, validateInputMessages)
		appendJSON(outputMessagesKey, input.Content.OutputMessages, validateOutputMessages)
	}
	return attrs
}
