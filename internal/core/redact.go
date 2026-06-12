package core

import (
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

const RedactedValue = "[REDACTED]"

// RedactSecrets returns a copy of v with sensitive fields replaced by a marker.
func RedactSecrets(v interface{}) interface{} {
	normalized, err := normalizeForRedaction(v)
	if err != nil {
		return RedactedValue
	}
	return redactSecretFields("", normalized)
}

// RedactConfig returns a JSON/YAML friendly, redacted config shape.
func RedactConfig(cfg *Config) map[string]interface{} {
	redacted, ok := RedactSecrets(cfg).(map[string]interface{})
	if !ok {
		return map[string]interface{}{"error": "failed to redact config"}
	}
	return redacted
}

// RedactLogEntries replaces configured secret values in log entries.
func RedactLogEntries(entries []LogEntry, cfg *Config) []LogEntry {
	secrets := ConfiguredSecretValues(cfg)
	if len(secrets) == 0 {
		return entries
	}

	out := make([]LogEntry, len(entries))
	for i, entry := range entries {
		entry.Raw = RedactString(entry.Raw, secrets)
		entry.Message = RedactString(entry.Message, secrets)
		out[i] = entry
	}
	return out
}

// ConfiguredSecretValues extracts concrete secret strings from config fields.
func ConfiguredSecretValues(cfg *Config) []string {
	normalized, err := normalizeForRedaction(cfg)
	if err != nil {
		return nil
	}
	secrets := make(map[string]struct{})
	collectSecretValues("", normalized, secrets)

	out := make([]string, 0, len(secrets))
	for s := range secrets {
		if len(s) >= 4 {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return len(out[i]) > len(out[j])
	})
	return out
}

// RedactString replaces exact configured secret values in s.
func RedactString(s string, secrets []string) string {
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		s = strings.ReplaceAll(s, secret, RedactedValue)
	}
	return s
}

func normalizeForRedaction(v interface{}) (interface{}, error) {
	data, err := yaml.Marshal(v)
	if err != nil {
		return nil, err
	}
	var normalized interface{}
	if err := yaml.Unmarshal(data, &normalized); err != nil {
		return nil, err
	}
	return normalized, nil
}

func redactSecretFields(key string, v interface{}) interface{} {
	if isSensitiveKey(key) {
		return redactedSecretValue(v)
	}

	switch typed := v.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{}, len(typed))
		for k, val := range typed {
			out[k] = redactSecretFields(k, val)
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(typed))
		for i, val := range typed {
			out[i] = redactSecretFields(key, val)
		}
		return out
	default:
		return v
	}
}

func redactedSecretValue(v interface{}) interface{} {
	switch typed := v.(type) {
	case nil:
		return nil
	case string:
		if typed == "" {
			return ""
		}
		return RedactedValue
	case []interface{}:
		if len(typed) == 0 {
			return typed
		}
		return RedactedValue
	case map[string]interface{}:
		if len(typed) == 0 {
			return typed
		}
		return RedactedValue
	default:
		if fmt.Sprint(typed) == "" {
			return typed
		}
		return RedactedValue
	}
}

func collectSecretValues(key string, v interface{}, secrets map[string]struct{}) {
	if isSensitiveKey(key) {
		collectStrings(v, secrets)
		return
	}

	switch typed := v.(type) {
	case map[string]interface{}:
		for k, val := range typed {
			collectSecretValues(k, val, secrets)
		}
	case []interface{}:
		for _, val := range typed {
			collectSecretValues(key, val, secrets)
		}
	}
}

func collectStrings(v interface{}, out map[string]struct{}) {
	switch typed := v.(type) {
	case string:
		if strings.TrimSpace(typed) != "" {
			out[typed] = struct{}{}
		}
	case []interface{}:
		for _, val := range typed {
			collectStrings(val, out)
		}
	case map[string]interface{}:
		for _, val := range typed {
			collectStrings(val, out)
		}
	}
}

func isSensitiveKey(key string) bool {
	n := normalizeSecretKey(key)
	if n == "" {
		return false
	}

	exact := map[string]bool{
		"token":         true,
		"tokens":        true,
		"password":      true,
		"authorization": true,
	}
	if exact[n] {
		return true
	}

	contains := []string{
		"apikey",
		"apikeys",
		"readonlykey",
		"readonlykeys",
		"secret",
		"clientsecret",
		"authtoken",
		"bearertoken",
		"geminiapikey",
		"webhook",
	}
	for _, marker := range contains {
		if strings.Contains(n, marker) {
			return true
		}
	}

	return strings.HasSuffix(n, "token") || strings.HasSuffix(n, "tokens")
}

func normalizeSecretKey(key string) string {
	key = strings.ToLower(strings.TrimSpace(key))
	replacer := strings.NewReplacer("_", "", "-", "", ".", "", " ", "")
	return replacer.Replace(key)
}
