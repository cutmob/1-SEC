package injection

import (
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/1sec-project/1sec/internal/core"
)

// AnalyzeInput scans a string for injection patterns and returns detected threats.
func (s *Shield) AnalyzeInput(input, source string) []Detection {
	if input == "" {
		return nil
	}

	atomic.AddInt64(&s.stats.TotalScanned, 1)

	var detections []Detection
	normalized := normalizeInput(input)

	for _, p := range s.patterns {
		if p.Regex.MatchString(normalized) {
			d := Detection{
				PatternName: p.Name,
				Category:    p.Category,
				Severity:    p.Severity,
				MatchedText: truncate(p.Regex.FindString(normalized), 200),
				Input:       truncate(input, 500),
				Source:      source,
			}
			detections = append(detections, d)
			s.incrementStat(p.Category)
		}
	}

	return detections
}

// Detection represents a detected injection attempt.
type Detection struct {
	PatternName string        `json:"pattern_name"`
	Category    string        `json:"category"`
	Severity    core.Severity `json:"severity"`
	MatchedText string        `json:"matched_text"`
	Input       string        `json:"input"`
	Source      string        `json:"source"`
}

func (s *Shield) analyzeEvent(event *core.SecurityEvent) {
	fieldsToScan := extractScanFields(event)

	for fieldName, value := range fieldsToScan {
		detections := s.AnalyzeInput(value, fieldName)
		if len(detections) == 0 {
			continue
		}

		// Find highest severity among detections
		maxSeverity := core.SeverityInfo
		categories := make(map[string]bool)
		for _, d := range detections {
			if d.Severity > maxSeverity {
				maxSeverity = d.Severity
			}
			categories[d.Category] = true
		}

		catList := make([]string, 0, len(categories))
		for c := range categories {
			catList = append(catList, categoryLabel(c))
		}

		newEvent := core.NewSecurityEvent(
			ModuleName,
			"injection_detected",
			maxSeverity,
			fmt.Sprintf("Injection attempt detected: %s in field %q", strings.Join(catList, ", "), fieldName),
		)
		newEvent.SourceIP = event.SourceIP
		newEvent.UserAgent = event.UserAgent
		newEvent.RequestID = event.RequestID
		newEvent.Details["original_event_id"] = event.ID
		newEvent.Details["field"] = fieldName
		newEvent.Details["categories"] = catList
		newEvent.Details["detection_count"] = len(detections)
		newEvent.Details["detections"] = detections

		if s.bus != nil {
			if err := s.bus.PublishEvent(newEvent); err != nil {
				s.logger.Error().Err(err).Msg("failed to publish injection event")
			}
		}

		alert := core.NewAlert(newEvent,
			fmt.Sprintf("Injection Attack Detected: %s", strings.Join(catList, ", ")),
			fmt.Sprintf("Detected %d injection pattern(s) in field %q from IP %s. Categories: %s. Highest severity: %s.",
				len(detections), fieldName, event.SourceIP, strings.Join(catList, ", "), maxSeverity.String()),
		)
		alert.Mitigations = []string{
			"Block the source IP if repeated attempts are detected",
			"Review and sanitize the affected input field",
			"Ensure parameterized queries are used for database operations",
			"Implement Content Security Policy headers for XSS prevention",
			"Validate and whitelist allowed URL schemes for SSRF prevention",
		}

		if s.pipeline != nil {
			s.pipeline.Process(alert)
		}
	}
}

func extractScanFields(event *core.SecurityEvent) map[string]string {
	fields := make(map[string]string)

	if event.Details == nil {
		return fields
	}

	// Extract common fields that may contain user input
	stringFields := []string{
		"url", "path", "query", "body", "header", "cookie",
		"user_input", "payload", "request_body", "query_string",
		"form_data", "json_body", "xml_body", "parameter",
		"username", "password", "email", "search", "filter",
		"sort", "order_by", "filename", "redirect_url", "callback",
		"template", "expression", "command", "sql", "ldap_filter",
	}

	for _, field := range stringFields {
		if val, ok := event.Details[field]; ok {
			switch v := val.(type) {
			case string:
				if v != "" {
					fields[field] = v
				}
			}
		}
	}

	// Also scan the summary if it looks like it contains request data
	if event.Summary != "" {
		fields["summary"] = event.Summary
	}

	return fields
}

func normalizeInput(input string) string {
	// Decode common encodings to catch evasion attempts
	result := input

	// URL decode common sequences
	replacer := strings.NewReplacer(
		"%20", " ",
		"%27", "'",
		"%22", "\"",
		"%3C", "<",
		"%3E", ">",
		"%28", "(",
		"%29", ")",
		"%3B", ";",
		"%7C", "|",
		"%26", "&",
		"%2F", "/",
		"%5C", "\\",
		"%2E", ".",
		"%3D", "=",
		"%23", "#",
		"%2D", "-",
		"%2A", "*",
		"%09", "\t",
		"%0A", "\n",
		"%0D", "\r",
	)
	result = replacer.Replace(result)

	// Handle double URL encoding
	result = replacer.Replace(result)

	// Normalize unicode homoglyphs commonly used for evasion
	unicodeReplacer := strings.NewReplacer(
		"\u2018", "'", // left single quote
		"\u2019", "'", // right single quote
		"\u201C", "\"", // left double quote
		"\u201D", "\"", // right double quote
		"\uFF1C", "<", // fullwidth less-than
		"\uFF1E", ">", // fullwidth greater-than
		"\uFF08", "(", // fullwidth left paren
		"\uFF09", ")", // fullwidth right paren
		"\u2024", ".", // one dot leader
		"\uFF0F", "/", // fullwidth solidus
		"\uFF3C", "\\", // fullwidth reverse solidus
	)
	result = unicodeReplacer.Replace(result)

	return result
}

func (s *Shield) incrementStat(category string) {
	s.stats.mu.Lock()
	defer s.stats.mu.Unlock()
	switch category {
	case "sqli":
		s.stats.SQLiDetected++
	case "xss":
		s.stats.XSSDetected++
	case "cmdi":
		s.stats.CMDiDetected++
	case "ssrf":
		s.stats.SSRFDetected++
	case "ldapi":
		s.stats.LDAPiDetected++
	case "template":
		s.stats.TemplDetected++
	case "nosql":
		s.stats.NoSQLDetected++
	case "path":
		s.stats.PathDetected++
	}
}

func categoryLabel(cat string) string {
	switch cat {
	case "sqli":
		return "SQL Injection"
	case "xss":
		return "Cross-Site Scripting"
	case "cmdi":
		return "Command Injection"
	case "ssrf":
		return "Server-Side Request Forgery"
	case "ldapi":
		return "LDAP Injection"
	case "template":
		return "Template Injection"
	case "nosql":
		return "NoSQL Injection"
	case "path":
		return "Path Traversal"
	default:
		return cat
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
