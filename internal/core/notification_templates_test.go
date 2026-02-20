package core

import (
	"testing"
	"time"
)

func makeTestAlert() *Alert {
	return &Alert{
		ID:          "abc12345-6789-0000-0000-000000000000",
		Timestamp:   time.Date(2026, 1, 15, 10, 30, 0, 0, time.UTC),
		Module:      "injection_shield",
		Type:        "sql_injection",
		Severity:    SeverityCritical,
		Status:      AlertStatusOpen,
		Title:       "SQL Injection Detected",
		Description: "Malicious SQL payload detected in POST /api/login",
		Metadata: map[string]interface{}{
			"source_ip": "10.0.0.50",
		},
		Mitigations: []string{"Block source IP", "Review WAF rules"},
	}
}

func makeTestRule() ResponseRule {
	return ResponseRule{
		Action: ActionWebhook,
		Params: map[string]string{
			"url":         "https://hooks.example.com/webhook",
			"routing_key": "test-routing-key",
			"auth_token":  "test-token",
		},
	}
}

func TestGetNotificationTemplate(t *testing.T) {
	tests := []struct {
		name     string
		expected string
	}{
		{"pagerduty", "pagerduty"},
		{"pd", "pagerduty"},
		{"slack", "slack"},
		{"teams", "teams"},
		{"msteams", "teams"},
		{"discord", "discord"},
		{"generic", "generic"},
		{"", "generic"},
	}

	for _, tt := range tests {
		tmpl := GetNotificationTemplate(tt.name)
		if tmpl == nil {
			t.Errorf("GetNotificationTemplate(%q) returned nil", tt.name)
			continue
		}
		if tmpl.Name() != tt.expected {
			t.Errorf("GetNotificationTemplate(%q).Name() = %q, want %q", tt.name, tmpl.Name(), tt.expected)
		}
	}

	if tmpl := GetNotificationTemplate("nonexistent"); tmpl != nil {
		t.Error("expected nil for unknown template")
	}
}

func TestValidTemplateNames(t *testing.T) {
	names := ValidTemplateNames()
	if len(names) != 5 {
		t.Errorf("expected 5 template names, got %d", len(names))
	}
}

func TestPagerDutyTemplate(t *testing.T) {
	alert := makeTestAlert()
	rule := makeTestRule()
	tmpl := &PagerDutyTemplate{}

	payload := tmpl.Format(alert, rule)

	if payload["routing_key"] != "test-routing-key" {
		t.Errorf("expected routing_key, got %v", payload["routing_key"])
	}
	if payload["event_action"] != "trigger" {
		t.Errorf("expected event_action=trigger, got %v", payload["event_action"])
	}

	inner, ok := payload["payload"].(map[string]interface{})
	if !ok {
		t.Fatal("expected payload.payload to be a map")
	}
	if inner["severity"] != "critical" {
		t.Errorf("expected severity=critical, got %v", inner["severity"])
	}
	if inner["component"] != "injection_shield" {
		t.Errorf("expected component=injection_shield, got %v", inner["component"])
	}
}

func TestSlackTemplate(t *testing.T) {
	alert := makeTestAlert()
	rule := makeTestRule()
	tmpl := &SlackTemplate{}

	payload := tmpl.Format(alert, rule)

	blocks, ok := payload["blocks"].([]map[string]interface{})
	if !ok {
		t.Fatal("expected blocks array")
	}
	if len(blocks) < 3 {
		t.Errorf("expected at least 3 blocks, got %d", len(blocks))
	}
	if blocks[0]["type"] != "header" {
		t.Errorf("expected first block to be header, got %v", blocks[0]["type"])
	}
}

func TestTeamsTemplate(t *testing.T) {
	alert := makeTestAlert()
	rule := makeTestRule()
	tmpl := &TeamsTemplate{}

	payload := tmpl.Format(alert, rule)

	if payload["@type"] != "MessageCard" {
		t.Errorf("expected @type=MessageCard, got %v", payload["@type"])
	}
	if payload["themeColor"] != "D32F2F" {
		t.Errorf("expected themeColor=D32F2F for critical, got %v", payload["themeColor"])
	}
}

func TestDiscordTemplate(t *testing.T) {
	alert := makeTestAlert()
	rule := makeTestRule()
	tmpl := &DiscordTemplate{}

	payload := tmpl.Format(alert, rule)

	embeds, ok := payload["embeds"].([]map[string]interface{})
	if !ok {
		t.Fatal("expected embeds array")
	}
	if len(embeds) != 1 {
		t.Errorf("expected 1 embed, got %d", len(embeds))
	}
	if embeds[0]["color"] != 0xD32F2F {
		t.Errorf("expected color 0xD32F2F for critical, got %v", embeds[0]["color"])
	}
}

func TestGenericTemplate(t *testing.T) {
	alert := makeTestAlert()
	rule := makeTestRule()
	tmpl := &GenericTemplate{}

	payload := tmpl.Format(alert, rule)

	if payload["action"] != "webhook" {
		t.Errorf("expected action=webhook, got %v", payload["action"])
	}
	if payload["source"] != "1sec-response-engine" {
		t.Errorf("expected source=1sec-response-engine, got %v", payload["source"])
	}
}

func TestTruncate(t *testing.T) {
	short := "hello"
	if truncate(short, 10) != "hello" {
		t.Error("truncate should not modify short strings")
	}

	long := "this is a very long string that should be truncated"
	result := truncate(long, 10)
	if len(result) != 13 { // 10 + "..."
		t.Errorf("expected truncated length 13, got %d", len(result))
	}
}

func TestSeverityColorMapping(t *testing.T) {
	severities := []Severity{SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}
	tmpl := &SlackTemplate{}
	rule := makeTestRule()

	for _, sev := range severities {
		alert := makeTestAlert()
		alert.Severity = sev
		payload := tmpl.Format(alert, rule)
		if payload["blocks"] == nil {
			t.Errorf("nil blocks for severity %s", sev.String())
		}
	}
}
