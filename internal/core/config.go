package core

import (
	"crypto/subtle"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config holds the entire 1SEC configuration.
type Config struct {
	Server  ServerConfig            `yaml:"server"`
	Bus     BusConfig               `yaml:"bus"`
	Alerts  AlertConfig             `yaml:"alerts"`
	Syslog  SyslogConfig            `yaml:"syslog"`
	Modules map[string]ModuleConfig `yaml:"modules"`
	Logging LoggingConfig           `yaml:"logging"`
}

// ServerConfig holds API server settings.
type ServerConfig struct {
	Host        string   `yaml:"host"`
	Port        int      `yaml:"port"`
	APIKeys     []string `yaml:"api_keys"`
	CORSOrigins []string `yaml:"cors_origins"`
}

// SyslogConfig holds syslog ingestion settings.
type SyslogConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Protocol string `yaml:"protocol"` // "udp", "tcp", or "both"
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
}

// BusConfig holds NATS event bus settings.
type BusConfig struct {
	URL       string `yaml:"url"`
	Embedded  bool   `yaml:"embedded"`
	DataDir   string `yaml:"data_dir"`
	Port      int    `yaml:"port"`
	ClusterID string `yaml:"cluster_id"`
}

// AlertConfig holds alert pipeline settings.
type AlertConfig struct {
	MaxStore      int      `yaml:"max_store"`
	WebhookURLs   []string `yaml:"webhook_urls"`
	EnableConsole bool     `yaml:"enable_console"`
}

// ModuleConfig holds per-module configuration.
type ModuleConfig struct {
	Enabled  bool                   `yaml:"enabled"`
	Settings map[string]interface{} `yaml:"settings"`
}

// LoggingConfig holds logging settings.
type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

// DefaultConfig returns a Config with sane defaults — zero-config works out of the box.
func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Host: "0.0.0.0",
			Port: 1780,
		},
		Bus: BusConfig{
			URL:       "nats://127.0.0.1:4222",
			Embedded:  true,
			DataDir:   "./data/nats",
			Port:      4222,
			ClusterID: "1sec-cluster",
		},
		Alerts: AlertConfig{
			MaxStore:      10000,
			EnableConsole: true,
		},
		Syslog: SyslogConfig{
			Enabled:  false,
			Protocol: "udp",
			Host:     "0.0.0.0",
			Port:     1514,
		},
		Modules: map[string]ModuleConfig{
			"network_guardian":    {Enabled: true, Settings: map[string]interface{}{}},
			"api_fortress":       {Enabled: true, Settings: map[string]interface{}{}},
			"iot_shield":         {Enabled: true, Settings: map[string]interface{}{}},
			"injection_shield":   {Enabled: true, Settings: map[string]interface{}{}},
			"supply_chain":       {Enabled: true, Settings: map[string]interface{}{}},
			"ransomware":         {Enabled: true, Settings: map[string]interface{}{}},
			"auth_fortress":      {Enabled: true, Settings: map[string]interface{}{}},
			"deepfake_shield":    {Enabled: true, Settings: map[string]interface{}{}},
			"identity_monitor":   {Enabled: true, Settings: map[string]interface{}{}},
			"llm_firewall":       {Enabled: true, Settings: map[string]interface{}{}},
			"ai_containment":     {Enabled: true, Settings: map[string]interface{}{}},
			"data_poisoning":     {Enabled: true, Settings: map[string]interface{}{}},
			"quantum_crypto":     {Enabled: true, Settings: map[string]interface{}{}},
			"runtime_watcher":    {Enabled: true, Settings: map[string]interface{}{}},
			"cloud_posture":      {Enabled: true, Settings: map[string]interface{}{}},
			"ai_analysis_engine": {Enabled: true, Settings: map[string]interface{}{}},
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "console",
		},
	}
}

// LoadConfig loads configuration from a YAML file, falling back to defaults.
func LoadConfig(path string) (*Config, error) {
	cfg := DefaultConfig()

	if path == "" {
		return cfg, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	// Load API keys from environment if not set in config
	if len(cfg.Server.APIKeys) == 0 {
		if envKey := os.Getenv("ONESEC_API_KEY"); envKey != "" {
			cfg.Server.APIKeys = []string{envKey}
		}
	}

	return cfg, nil
}

// SaveConfig writes the configuration to a YAML file.
func SaveConfig(cfg *Config, path string) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshaling config: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}

// IsModuleEnabled checks if a module is enabled in the configuration.
func (c *Config) IsModuleEnabled(name string) bool {
	mod, ok := c.Modules[name]
	if !ok {
		return true
	}
	return mod.Enabled
}

// GetModuleSettings returns the settings map for a module.
func (c *Config) GetModuleSettings(name string) map[string]interface{} {
	mod, ok := c.Modules[name]
	if !ok || mod.Settings == nil {
		return map[string]interface{}{}
	}
	return mod.Settings
}

// GetModuleSetting returns a specific setting value for a module.
func (c *Config) GetModuleSetting(module, key string, defaultVal interface{}) interface{} {
	settings := c.GetModuleSettings(module)
	if val, ok := settings[key]; ok {
		return val
	}
	return defaultVal
}

// LogLevel returns the parsed log level string.
func (c *Config) LogLevel() string {
	return strings.ToLower(c.Logging.Level)
}

// AuthEnabled returns true if API key authentication is configured.
func (c *Config) AuthEnabled() bool {
	return len(c.Server.APIKeys) > 0
}

// ValidateAPIKey checks if the provided key matches any configured API key.
// Uses constant-time comparison to prevent timing attacks.
func (c *Config) ValidateAPIKey(key string) bool {
	for _, valid := range c.Server.APIKeys {
		if subtle.ConstantTimeCompare([]byte(key), []byte(valid)) == 1 {
			return true
		}
	}
	return false
}
