package otelagentsession

import (
	"bytes"
	"encoding/json"
)

// These validators implement the required structural contract of the current
// OpenTelemetry GenAI Development schemas. They intentionally live behind the
// version-replaceable DevelopmentMapper rather than in the Session API model.
// GenericPart makes every message part with a string type schema-valid; message
// role and finish_reason also permit custom string values.
func validateSystemInstructions(value json.RawMessage) ([]byte, bool) {
	return validateJSONArray(value, validateMessagePart)
}

func validateInputMessages(value json.RawMessage) ([]byte, bool) {
	return validateJSONArray(value, func(item json.RawMessage) bool {
		return validateMessage(item, false)
	})
}

func validateOutputMessages(value json.RawMessage) ([]byte, bool) {
	return validateJSONArray(value, func(item json.RawMessage) bool {
		return validateMessage(item, true)
	})
}

func validateJSONArray(value json.RawMessage, validateItem func(json.RawMessage) bool) ([]byte, bool) {
	value = bytes.TrimSpace(value)
	if len(value) == 0 || value[0] != '[' {
		return nil, false
	}

	var items []json.RawMessage
	if err := json.Unmarshal(value, &items); err != nil {
		return nil, false
	}
	for _, item := range items {
		if !validateItem(item) {
			return nil, false
		}
	}
	return value, true
}

func validateMessage(value json.RawMessage, requireFinishReason bool) bool {
	object, ok := decodeJSONObject(value)
	if !ok || !isJSONString(object["role"]) {
		return false
	}
	if name, exists := object["name"]; exists && !isJSONStringOrNull(name) {
		return false
	}

	parts, ok := decodeJSONArray(object["parts"])
	if !ok {
		return false
	}
	for _, part := range parts {
		if !validateMessagePart(part) {
			return false
		}
	}

	if requireFinishReason && !isJSONString(object["finish_reason"]) {
		return false
	}
	return true
}

func validateMessagePart(value json.RawMessage) bool {
	object, ok := decodeJSONObject(value)
	return ok && isJSONString(object["type"])
}

func decodeJSONObject(value json.RawMessage) (map[string]json.RawMessage, bool) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(value, &object); err != nil || object == nil {
		return nil, false
	}
	return object, true
}

func decodeJSONArray(value json.RawMessage) ([]json.RawMessage, bool) {
	value = bytes.TrimSpace(value)
	if len(value) == 0 || value[0] != '[' {
		return nil, false
	}
	var items []json.RawMessage
	if err := json.Unmarshal(value, &items); err != nil {
		return nil, false
	}
	return items, true
}

func isJSONString(value json.RawMessage) bool {
	var decoded any
	if err := json.Unmarshal(value, &decoded); err != nil {
		return false
	}
	_, ok := decoded.(string)
	return ok
}

func isJSONStringOrNull(value json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(value), []byte("null")) || isJSONString(value)
}
