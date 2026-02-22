package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ─── DefaultConfig ──────────────────────────────────────────────────────────

func TestDefaultConfig_Values(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Server.Host != "0.0.0.0" {
		t.Errorf("default Host = %q, want 0.0.0.0", cfg.Server.Host)
	}
	if cfg.Server.Port != 1780 {
		t.Errorf("default Port = %d, want 1780", cfg.Server.Port)
	}
	if !cfg.Bus.Embedded {
		t.Error("expected Bus.Embedded = true by default")
	}
	if cfg.Bus.Port != 4222 {
		t.Errorf("default Bus.Port = %d, want 4222", cfg.Bus.Port)
	}
	if cfg.Alerts.MaxStore != 10000 {
		t.Errorf("default MaxStore = %d, want 10000", cfg.Alerts.MaxStore)
	}
	if !cfg.Alerts.EnableConsole {
		t.Error("expected EnableConsole = true by default")
	}
	if cfg.Logging.Level != "info" {
		t.Errorf("default Level = %q, want info", cfg.Logging.Level)
	}
	if cfg.Logging.Format != "console" {
		t.Errorf("default Format = %q, want console", cfg.Logging.Format)
	}
	// Rust engine should be disabled by default (optional sidecar)
	if cfg.RustEngine.Enabled {
		t.Error("RustEngine should be disabled by default")
	}
	if cfg.RustEngine.MinScore != 0.1 {
		t.Errorf("RustEngine.MinScore = %v, want 0.1", cfg.RustEngine.MinScore)
	}
	// Escalation should be disabled by default
	if cfg.Escalation.Enabled {
		t.Error("Escalation should be disabled by default")
	}
	if len(cfg.Escalation.Timeouts) == 0 {
		t.Error("Escalation should have default timeouts even when disabled")
	}
}

func TestDefaultConfig_ModulesPresent(t *testing.T) {
	cfg := DefaultConfig()
	expected := []string{
		"network_guardian", "api_fortress", "iot_shield", "injection_shield",
		"supply_chain", "ransomware", "auth_fortress", "deepfake_shield",
		"identity_monitor", "llm_firewall", "ai_containment", "data_poisoning",
		"quantum_crypto", "runtime_watcher", "cloud_posture", "ai_analysis_engine",
	}
	for _, name := range expected {
		mod, ok := cfg.Modules[name]
		if !ok {
			t.Errorf("missing module %q in default config", name)
		}
		if !mod.Enabled {
			t.Errorf("expected module %q to be enabled", name)
		}
	}
}

// ─── LoadConfig ─────────────────────────────────────────────────────────────

func TestLoadConfig_EmptyPath_ReturnsDefaults(t *testing.T) {
	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatalf("LoadConfig(\"\") error: %v", err)
	}
	if cfg.Server.Port != 1780 {
		t.Errorf("expected default port 1780, got %d", cfg.Server.Port)
	}
}

func TestLoadConfig_NonExistentFile_ReturnsDefaults(t *testing.T) {
	cfg, err := LoadConfig("/this/path/does/not/exist/config.yaml")
	if err != nil {
		t.Fatalf("LoadConfig with non-existent file should not error, got: %v", err)
	}
	if cfg.Server.Port != 1780 {
		t.Errorf("expected default port 1780, got %d", cfg.Server.Port)
	}
}

func TestLoadConfig_ValidYAML(t *testing.T) {
	yaml := `
server:
  host: "127.0.0.1"
  port: 9999
logging:
  level: "debug"
  format: "json"
`
	path := writeTempConfig(t, yaml)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig error: %v", err)
	}
	if cfg.Server.Host != "127.0.0.1" {
		t.Errorf("Host = %q, want 127.0.0.1", cfg.Server.Host)
	}
	if cfg.Server.Port != 9999 {
		t.Errorf("Port = %d, want 9999", cfg.Server.Port)
	}
	if cfg.Logging.Level != "debug" {
		t.Errorf("Level = %q, want debug", cfg.Logging.Level)
	}
	if cfg.Logging.Format != "json" {
		t.Errorf("Format = %q, want json", cfg.Logging.Format)
	}
}

func TestLoadConfig_InvalidYAML(t *testing.T) {
	path := writeTempConfig(t, ": bad: yaml: {{{{")
	_, err := LoadConfig(path)
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestLoadConfig_APIKey_FromEnv(t *testing.T) {
	t.Setenv("ONESEC_API_KEY", "env-test-key-12345")
	// Use an empty YAML file so LoadConfig reads the file path (triggering the env-key check)
	// The env key is only applied when a file path is given and no api_keys exist in the file.
	path := writeTempConfig(t, "")
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Server.APIKeys) == 0 {
		t.Error("expected APIKeys to be populated from env when config file has no keys")
	}
	if len(cfg.Server.APIKeys) > 0 && cfg.Server.APIKeys[0] != "env-test-key-12345" {
		t.Errorf("APIKeys[0] = %q, want env-test-key-12345", cfg.Server.APIKeys[0])
	}
}

func TestLoadConfig_APIKey_FromConfig_TakesPrecedence(t *testing.T) {
	t.Setenv("ONESEC_API_KEY", "env-key")
	yaml := `
server:
  api_keys:
    - "config-key"
`
	path := writeTempConfig(t, yaml)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Server.APIKeys) != 1 || cfg.Server.APIKeys[0] != "config-key" {
		t.Errorf("expected config key to take precedence: %v", cfg.Server.APIKeys)
	}
}

// ─── SaveConfig ─────────────────────────────────────────────────────────────

func TestSaveConfig_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	original := DefaultConfig()
	original.Server.Port = 8888
	original.Logging.Level = "debug"

	if err := SaveConfig(original, path); err != nil {
		t.Fatalf("SaveConfig error: %v", err)
	}

	loaded, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig after save error: %v", err)
	}
	if loaded.Server.Port != 8888 {
		t.Errorf("Port = %d, want 8888", loaded.Server.Port)
	}
}

// ─── IsModuleEnabled ────────────────────────────────────────────────────────

func TestIsModuleEnabled(t *testing.T) {
	cfg := DefaultConfig()

	// Known enabled module
	if !cfg.IsModuleEnabled("api_fortress") {
		t.Error("api_fortress should be enabled")
	}

	// Unknown module defaults to enabled
	if !cfg.IsModuleEnabled("unknown_module") {
		t.Error("unknown module should default to enabled")
	}

	// Explicitly disable
	cfg.Modules["api_fortress"] = ModuleConfig{Enabled: false}
	if cfg.IsModuleEnabled("api_fortress") {
		t.Error("api_fortress should now be disabled")
	}
}

// ─── GetModuleSettings / GetModuleSetting ───────────────────────────────────

func TestGetModuleSettings(t *testing.T) {
	cfg := DefaultConfig()

	// Module without extra settings returns empty map
	settings := cfg.GetModuleSettings("api_fortress")
	if settings == nil {
		t.Error("expected non-nil settings")
	}

	// Unknown module
	settings2 := cfg.GetModuleSettings("nonexistent")
	if settings2 == nil {
		t.Error("expected non-nil map for nonexistent module")
	}
}

func TestGetModuleSetting(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Modules["test_mod"] = ModuleConfig{
		Enabled:  true,
		Settings: map[string]interface{}{"threshold": 42},
	}

	val := cfg.GetModuleSetting("test_mod", "threshold", 100)
	if val.(int) != 42 {
		t.Errorf("expected 42, got %v", val)
	}

	def := cfg.GetModuleSetting("test_mod", "missing_key", "default_val")
	if def != "default_val" {
		t.Errorf("expected default_val, got %v", def)
	}
}

// ─── LogLevel ────────────────────────────────────────────────────────────────

func TestLogLevel(t *testing.T) {
	cases := []struct{ in, want string }{
		{"INFO", "info"},
		{"DEBUG", "debug"},
		{"Warn", "warn"},
		{"", ""},
	}
	for _, tc := range cases {
		cfg := DefaultConfig()
		cfg.Logging.Level = tc.in
		if got := cfg.LogLevel(); got != tc.want {
			t.Errorf("LogLevel(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// ─── AuthEnabled / ValidateAPIKey ────────────────────────────────────────────

func TestAuthEnabled(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.AuthEnabled() {
		t.Error("AuthEnabled should be false with no keys")
	}
	cfg.Server.APIKeys = []string{"key1"}
	if !cfg.AuthEnabled() {
		t.Error("AuthEnabled should be true with keys")
	}
}

func TestValidateAPIKey(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Server.APIKeys = []string{"correct-key", "another-key"}
	cfg.Server.ReadOnlyKeys = []string{"readonly-key"}

	if cfg.ValidateAPIKey("correct-key") != "write" {
		t.Error("should accept 'correct-key' as write")
	}
	if cfg.ValidateAPIKey("another-key") != "write" {
		t.Error("should accept 'another-key' as write")
	}
	if cfg.ValidateAPIKey("readonly-key") != "read" {
		t.Error("should accept 'readonly-key' as read")
	}
	if cfg.ValidateAPIKey("wrong-key") != "" {
		t.Error("should reject 'wrong-key'")
	}
	if cfg.ValidateAPIKey("") != "" {
		t.Error("should reject empty key")
	}
}

func TestValidateAPIKey_TimingSafe(t *testing.T) {
	// Just ensure it doesn't panic with tricky inputs
	cfg := DefaultConfig()
	cfg.Server.APIKeys = []string{"a"}
	cfg.ValidateAPIKey(strings.Repeat("b", 10000))
}

// ─── Helpers ────────────────────────────────────────────────────────────────

func writeTempConfig(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	return f.Name()
}
