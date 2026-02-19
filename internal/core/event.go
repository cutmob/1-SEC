package core

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// Severity represents the severity level of a security event or alert.
type Severity int

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "INFO"
	case SeverityLow:
		return "LOW"
	case SeverityMedium:
		return "MEDIUM"
	case SeverityHigh:
		return "HIGH"
	case SeverityCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

func (s Severity) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

func (s *Severity) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	switch str {
	case "INFO":
		*s = SeverityInfo
	case "LOW":
		*s = SeverityLow
	case "MEDIUM":
		*s = SeverityMedium
	case "HIGH":
		*s = SeverityHigh
	case "CRITICAL":
		*s = SeverityCritical
	default:
		*s = SeverityInfo
	}
	return nil
}

// SecurityEvent is the standard event structure published to the event bus.
type SecurityEvent struct {
	ID        string                 `json:"id"`
	Timestamp time.Time              `json:"timestamp"`
	Source    string                 `json:"source"`
	Module    string                 `json:"module"`
	Type      string                 `json:"type"`
	Severity  Severity               `json:"severity"`
	Summary   string                 `json:"summary"`
	Details   map[string]interface{} `json:"details,omitempty"`
	RawData   []byte                 `json:"raw_data,omitempty"`
	SourceIP  string                 `json:"source_ip,omitempty"`
	DestIP    string                 `json:"dest_ip,omitempty"`
	UserAgent string                 `json:"user_agent,omitempty"`
	RequestID string                 `json:"request_id,omitempty"`
}

// NewSecurityEvent creates a new SecurityEvent with a generated ID and current timestamp.
func NewSecurityEvent(module, eventType string, severity Severity, summary string) *SecurityEvent {
	return &SecurityEvent{
		ID:        uuid.New().String(),
		Timestamp: time.Now().UTC(),
		Module:    module,
		Type:      eventType,
		Severity:  severity,
		Summary:   summary,
		Details:   make(map[string]interface{}),
	}
}

// Marshal serializes the event to JSON.
func (e *SecurityEvent) Marshal() ([]byte, error) {
	return json.Marshal(e)
}

// UnmarshalSecurityEvent deserializes a SecurityEvent from JSON.
func UnmarshalSecurityEvent(data []byte) (*SecurityEvent, error) {
	var event SecurityEvent
	if err := json.Unmarshal(data, &event); err != nil {
		return nil, err
	}
	return &event, nil
}
