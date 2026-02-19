package aiengine

import (
	"os"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

// Cooldown durations for different error types.
const (
	rateLimitCooldown      = 60 * time.Second       // 429 rate limit
	quotaExhaustedCooldown = 10 * time.Minute       // quota exhausted
	invalidKeyCooldown     = 24 * time.Hour          // 401 / invalid key
)

// rotatablePatterns are error substrings that indicate key-level rate limiting.
var rotatablePatterns = []string{
	"resource_exhausted",
	"rate_limit_exceeded",
	"quota",
	"rate limit",
	"too many requests",
	"429",
}

// keyState tracks the health of a single API key.
type keyState struct {
	key           string
	healthy       bool
	cooldownUntil time.Time
	lastError     string
	errorCount    int
}

// KeyManager manages multiple Gemini API keys with automatic rotation
// on rate limit (429) or quota exhaustion. Rate limits are per-key,
// so rotating to a fresh key is the only way to maintain throughput.
type KeyManager struct {
	mu       sync.Mutex
	keys     []*keyState
	current  int
	logger   zerolog.Logger
}

// NewKeyManager creates a KeyManager from a list of API key strings.
// Empty or short strings are silently ignored.
func NewKeyManager(keys []string, logger zerolog.Logger) *KeyManager {
	km := &KeyManager{
		logger: logger.With().Str("component", "key_manager").Logger(),
	}

	for _, k := range keys {
		k = strings.TrimSpace(k)
		if len(k) < 10 {
			continue
		}
		km.keys = append(km.keys, &keyState{
			key:     k,
			healthy: true,
		})
	}

	if len(km.keys) == 0 {
		km.logger.Warn().Msg("no Gemini API keys configured")
	} else {
		km.logger.Info().Int("count", len(km.keys)).Msg("API keys loaded")
	}

	return km
}

// HasKeys returns true if at least one key was loaded.
func (km *KeyManager) HasKeys() bool {
	return len(km.keys) > 0
}

// CurrentKey returns the current healthy key, or empty string if none available.
// It automatically clears expired cooldowns before checking.
func (km *KeyManager) CurrentKey() string {
	km.mu.Lock()
	defer km.mu.Unlock()

	km.clearExpiredCooldowns()

	// Try current key first
	if km.current < len(km.keys) && km.keys[km.current].healthy {
		return km.keys[km.current].key
	}

	// Find any healthy key
	for i, ks := range km.keys {
		if ks.healthy {
			km.current = i
			return ks.key
		}
	}

	return ""
}

// IsRotatableError returns true if the error indicates a per-key rate limit
// that can be resolved by switching to a different key.
func IsRotatableError(statusCode int, errMsg string) bool {
	if statusCode == 429 {
		return true
	}
	// 503 is model overload, not key-specific — don't rotate
	if statusCode == 503 {
		return false
	}
	lower := strings.ToLower(errMsg)
	for _, pattern := range rotatablePatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

// RotateOnError marks the current key as unhealthy with an appropriate cooldown
// and attempts to switch to the next healthy key.
// Returns the new key, or empty string if all keys are exhausted.
func (km *KeyManager) RotateOnError(statusCode int, errMsg string) string {
	km.mu.Lock()
	defer km.mu.Unlock()

	if len(km.keys) == 0 {
		return ""
	}

	current := km.keys[km.current]

	// Idempotency: if already marked unhealthy (concurrent request hit the same wall),
	// just try to find the next healthy key without double-penalizing.
	if !current.healthy {
		return km.findNextHealthyKey()
	}

	// Determine cooldown based on error type
	cooldown := rateLimitCooldown
	lowerMsg := strings.ToLower(errMsg)
	if strings.Contains(lowerMsg, "quota") {
		cooldown = quotaExhaustedCooldown
	} else if statusCode == 401 || strings.Contains(lowerMsg, "invalid") {
		cooldown = invalidKeyCooldown
	}

	// Mark current key unhealthy
	current.healthy = false
	current.cooldownUntil = time.Now().Add(cooldown)
	current.lastError = truncateStr(errMsg, 200)
	current.errorCount++

	km.logger.Warn().
		Int("key_index", km.current+1).
		Str("cooldown", cooldown.String()).
		Str("error", current.lastError).
		Msg("key rate limited, rotating")

	newKey := km.findNextHealthyKey()
	if newKey != "" {
		km.logger.Info().Int("key_index", km.current+1).Msg("rotated to new key")
	} else {
		km.logger.Error().Msg("all keys exhausted, no healthy keys available")
	}
	return newKey
}

// findNextHealthyKey cycles through keys to find a healthy one.
// Must be called with km.mu held.
func (km *KeyManager) findNextHealthyKey() string {
	km.clearExpiredCooldowns()

	for i := 0; i < len(km.keys); i++ {
		candidate := (km.current + 1 + i) % len(km.keys)
		if km.keys[candidate].healthy {
			km.current = candidate
			return km.keys[candidate].key
		}
	}
	return ""
}

// clearExpiredCooldowns restores keys whose cooldown has elapsed.
// Must be called with km.mu held.
func (km *KeyManager) clearExpiredCooldowns() {
	now := time.Now()
	for i, ks := range km.keys {
		if !ks.healthy && !ks.cooldownUntil.IsZero() && now.After(ks.cooldownUntil) {
			ks.healthy = true
			ks.cooldownUntil = time.Time{}
			km.logger.Info().Int("key_index", i+1).Msg("key cooldown expired, restored to healthy")
		}
	}
}

// HealthyCount returns the number of currently healthy keys.
func (km *KeyManager) HealthyCount() int {
	km.mu.Lock()
	defer km.mu.Unlock()
	km.clearExpiredCooldowns()

	count := 0
	for _, ks := range km.keys {
		if ks.healthy {
			count++
		}
	}
	return count
}

// TotalCount returns the total number of loaded keys.
func (km *KeyManager) TotalCount() int {
	return len(km.keys)
}

// KeyStatus is the health snapshot of a single key (for the /status API).
type KeyStatus struct {
	Index             int           `json:"index"`
	Healthy           bool          `json:"healthy"`
	InCooldown        bool          `json:"in_cooldown"`
	CooldownRemaining time.Duration `json:"cooldown_remaining_ms,omitempty"`
	LastError         string        `json:"last_error,omitempty"`
	ErrorCount        int           `json:"error_count"`
}

// Status returns a snapshot of all key states.
func (km *KeyManager) Status() []KeyStatus {
	km.mu.Lock()
	defer km.mu.Unlock()
	km.clearExpiredCooldowns()

	now := time.Now()
	out := make([]KeyStatus, len(km.keys))
	for i, ks := range km.keys {
		remaining := time.Duration(0)
		inCooldown := false
		if !ks.healthy && ks.cooldownUntil.After(now) {
			inCooldown = true
			remaining = ks.cooldownUntil.Sub(now)
		}
		out[i] = KeyStatus{
			Index:             i + 1,
			Healthy:           ks.healthy,
			InCooldown:        inCooldown,
			CooldownRemaining: remaining,
			LastError:         ks.lastError,
			ErrorCount:        ks.errorCount,
		}
	}
	return out
}

func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// getStringSliceSetting extracts a []string from config settings.
// Supports both []string and []interface{} (from YAML unmarshaling).
func getStringSliceSetting(settings map[string]interface{}, key string) []string {
	val, ok := settings[key]
	if !ok {
		return nil
	}
	switch v := val.(type) {
	case []string:
		return v
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// collectAPIKeys gathers keys from config settings.
// Checks "gemini_api_key" (single) and "gemini_api_keys" (list).
// Also checks environment variables GEMINI_API_KEY, GEMINI_API_KEY_2, etc.
func collectAPIKeys(settings map[string]interface{}) []string {
	var keys []string

	// Single key from config
	if single := getStringSetting(settings, "gemini_api_key", ""); single != "" {
		keys = append(keys, single)
	}

	// Key list from config
	if list := getStringSliceSetting(settings, "gemini_api_keys"); len(list) > 0 {
		keys = append(keys, list...)
	}

	// Environment variables: GEMINI_API_KEY, GEMINI_API_KEY_2, GEMINI_API_KEY_3, GEMINI_API_KEY_4
	envVars := []string{"GEMINI_API_KEY", "GEMINI_API_KEY_2", "GEMINI_API_KEY_3", "GEMINI_API_KEY_4"}
	for _, envVar := range envVars {
		if val := getEnv(envVar); val != "" {
			keys = append(keys, val)
		}
	}

	// Deduplicate
	seen := make(map[string]bool)
	unique := make([]string, 0, len(keys))
	for _, k := range keys {
		k = strings.TrimSpace(k)
		if k != "" && !seen[k] {
			seen[k] = true
			unique = append(unique, k)
		}
	}

	return unique
}

// getEnv reads an environment variable.
func getEnv(key string) string {
	return os.Getenv(key)
}
