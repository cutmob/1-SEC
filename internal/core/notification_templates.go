package core

import (
	"fmt"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// notification_templates.go — pre-built webhook payload formatters for
// PagerDuty, Slack, Microsoft Teams, Discord, and generic JSON.
//
// SOC teams shouldn't need a translation proxy between 1SEC and their tools.
// Each template produces the exact JSON schema the target service expects.
//
// Usage in enforcement config:
//   actions:
//     - action: webhook
//       params:
//         url: "https://events.pagerduty.com/v2/enqueue"
//         template: "pagerduty"
//         routing_key: "YOUR_PD_ROUTING_KEY"
// ---------------------------------------------------------------------------

// NotificationTemplate formats an alert into a service-specific payload.
type NotificationTemplate interface {
	Format(alert *Alert, rule ResponseRule) map[string]interface{}
	Name() string
}

// GetNotificationTemplate returns a template by name, or nil if unknown.
func GetNotificationTemplate(name string) NotificationTemplate {
	switch strings.ToLower(name) {
	case "pagerduty", "pd":
		return &PagerDutyTemplate{}
	case "slack":
		return &SlackTemplate{}
	case "teams", "msteams":
		return &TeamsTemplate{}
	case "discord":
		return &DiscordTemplate{}
	case "generic", "":
		return &GenericTemplate{}
	default:
		return nil
	}
}

// ValidTemplateNames returns all supported template names.
func ValidTemplateNames() []string {
	return []string{"generic", "pagerduty", "slack", "teams", "discord"}
}

// ---------------------------------------------------------------------------
// PagerDuty Events API v2
// ---------------------------------------------------------------------------

type PagerDutyTemplate struct{}

func (t *PagerDutyTemplate) Name() string { return "pagerduty" }

func (t *PagerDutyTemplate) Format(alert *Alert, rule ResponseRule) map[string]interface{} {
	routingKey := rule.Params["routing_key"]
	if routingKey == "" {
		routingKey = rule.Params["auth_token"]
	}

	pdSeverity := "warning"
	switch alert.Severity {
	case SeverityCritical:
		pdSeverity = "critical"
	case SeverityHigh:
		pdSeverity = "error"
	case SeverityMedium:
		pdSeverity = "warning"
	default:
		pdSeverity = "info"
	}

	sourceIP, _ := alert.Metadata["source_ip"].(string)

	payload := map[string]interface{}{
		"routing_key":  routingKey,
		"event_action": "trigger",
		"dedup_key":    fmt.Sprintf("1sec-%s-%s", alert.Module, alert.ID[:8]),
		"payload": map[string]interface{}{
			"summary":   fmt.Sprintf("[1SEC] %s — %s", alert.Severity.String(), alert.Title),
			"source":    "1sec-response-engine",
			"severity":  pdSeverity,
			"component": alert.Module,
			"group":     "security",
			"class":     alert.Type,
			"timestamp": alert.Timestamp.Format(time.RFC3339),
			"custom_details": map[string]interface{}{
				"alert_id":    alert.ID,
				"module":      alert.Module,
				"severity":    alert.Severity.String(),
				"description": alert.Description,
				"source_ip":   sourceIP,
				"mitigations": alert.Mitigations,
			},
		},
	}
	return payload
}

// ---------------------------------------------------------------------------
// Slack Block Kit
// ---------------------------------------------------------------------------

type SlackTemplate struct{}

func (t *SlackTemplate) Name() string { return "slack" }

func (t *SlackTemplate) Format(alert *Alert, rule ResponseRule) map[string]interface{} {
	emoji := "⚠️"
	color := "#ff9800"
	switch alert.Severity {
	case SeverityCritical:
		emoji = "🚨"
		color = "#d32f2f"
	case SeverityHigh:
		emoji = "🔴"
		color = "#f44336"
	case SeverityMedium:
		emoji = "🟠"
		color = "#ff9800"
	default:
		emoji = "🔵"
		color = "#2196f3"
	}

	sourceIP, _ := alert.Metadata["source_ip"].(string)
	fields := []map[string]interface{}{
		{"type": "mrkdwn", "text": fmt.Sprintf("*Module:*\n%s", alert.Module)},
		{"type": "mrkdwn", "text": fmt.Sprintf("*Severity:*\n%s", alert.Severity.String())},
	}
	if sourceIP != "" {
		fields = append(fields, map[string]interface{}{"type": "mrkdwn", "text": fmt.Sprintf("*Source IP:*\n`%s`", sourceIP)})
	}

	blocks := []map[string]interface{}{
		{
			"type": "header",
			"text": map[string]interface{}{
				"type": "plain_text",
				"text": fmt.Sprintf("%s 1SEC Alert: %s", emoji, alert.Title),
			},
		},
		{
			"type": "section",
			"text": map[string]interface{}{
				"type": "mrkdwn",
				"text": truncate(alert.Description, 500),
			},
		},
		{
			"type":   "section",
			"fields": fields,
		},
		{
			"type": "context",
			"elements": []map[string]interface{}{
				{"type": "mrkdwn", "text": fmt.Sprintf("Alert ID: `%s` | %s", alert.ID[:12], alert.Timestamp.Format(time.RFC3339))},
			},
		},
	}

	return map[string]interface{}{
		"blocks": blocks,
		"attachments": []map[string]interface{}{
			{"color": color, "blocks": []interface{}{}},
		},
	}
}

// ---------------------------------------------------------------------------
// Microsoft Teams Adaptive Card
// ---------------------------------------------------------------------------

type TeamsTemplate struct{}

func (t *TeamsTemplate) Name() string { return "teams" }

func (t *TeamsTemplate) Format(alert *Alert, rule ResponseRule) map[string]interface{} {
	sourceIP, _ := alert.Metadata["source_ip"].(string)

	themeColor := "FF9800"
	switch alert.Severity {
	case SeverityCritical:
		themeColor = "D32F2F"
	case SeverityHigh:
		themeColor = "F44336"
	}

	facts := []map[string]string{
		{"name": "Module", "value": alert.Module},
		{"name": "Severity", "value": alert.Severity.String()},
		{"name": "Alert ID", "value": alert.ID[:12]},
	}
	if sourceIP != "" {
		facts = append(facts, map[string]string{"name": "Source IP", "value": sourceIP})
	}

	return map[string]interface{}{
		"@type":      "MessageCard",
		"@context":   "http://schema.org/extensions",
		"themeColor": themeColor,
		"summary":    fmt.Sprintf("1SEC: %s", alert.Title),
		"sections": []map[string]interface{}{
			{
				"activityTitle": fmt.Sprintf("🛡️ 1SEC Alert: %s", alert.Title),
				"activitySubtitle": alert.Timestamp.Format(time.RFC3339),
				"facts":            facts,
				"text":             truncate(alert.Description, 500),
				"markdown":         true,
			},
		},
	}
}

// ---------------------------------------------------------------------------
// Discord Embed
// ---------------------------------------------------------------------------

type DiscordTemplate struct{}

func (t *DiscordTemplate) Name() string { return "discord" }

func (t *DiscordTemplate) Format(alert *Alert, rule ResponseRule) map[string]interface{} {
	color := 0xFF9800
	switch alert.Severity {
	case SeverityCritical:
		color = 0xD32F2F
	case SeverityHigh:
		color = 0xF44336
	case SeverityMedium:
		color = 0xFF9800
	default:
		color = 0x2196F3
	}

	sourceIP, _ := alert.Metadata["source_ip"].(string)
	fields := []map[string]interface{}{
		{"name": "Module", "value": alert.Module, "inline": true},
		{"name": "Severity", "value": alert.Severity.String(), "inline": true},
	}
	if sourceIP != "" {
		fields = append(fields, map[string]interface{}{"name": "Source IP", "value": fmt.Sprintf("`%s`", sourceIP), "inline": true})
	}

	return map[string]interface{}{
		"embeds": []map[string]interface{}{
			{
				"title":       fmt.Sprintf("🛡️ 1SEC: %s", alert.Title),
				"description": truncate(alert.Description, 500),
				"color":       color,
				"fields":      fields,
				"footer":      map[string]string{"text": fmt.Sprintf("Alert %s", alert.ID[:12])},
				"timestamp":   alert.Timestamp.Format(time.RFC3339),
			},
		},
	}
}

// ---------------------------------------------------------------------------
// Generic JSON (default — the existing behavior)
// ---------------------------------------------------------------------------

type GenericTemplate struct{}

func (t *GenericTemplate) Name() string { return "generic" }

func (t *GenericTemplate) Format(alert *Alert, rule ResponseRule) map[string]interface{} {
	return map[string]interface{}{
		"alert":     alert,
		"action":    string(rule.Action),
		"timestamp": time.Now().UTC(),
		"source":    "1sec-response-engine",
	}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
