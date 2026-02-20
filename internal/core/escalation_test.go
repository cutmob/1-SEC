package core

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

func makeAlertForEscalation(severity Severity) *Alert {
	return &Alert{
		ID:       uuid.New().String(),
		Module:   "test_module",
		Severity: severity,
		Status:   AlertStatusOpen,
		Title:    "Test Alert for Escalation",
		Metadata: map[string]interface{}{"source_ip": "10.0.0.1"},
	}
}

func TestEscalationManager_TracksAlert(t *testing.T) {
	logger := zerolog.Nop()
	pipeline := NewAlertPipeline(logger, 100)
	cfg := EscalationConfig{
		Enabled: true,
		Timeouts: map[string]EscalationTimer{
			"HIGH": {Timeout: 5 * time.Second, EscalateTo: "CRITICAL", ReNotify: false, MaxEscalations: 1},
		},
	}

	em := NewEscalationManager(logger, cfg, pipeline)
	defer em.Stop()

	alert := makeAlertForEscalation(SeverityHigh)
	pipeline.Process(alert)
	em.Track(alert)

	stats := em.Stats()
	if stats["tracked_alerts"].(int) != 1 {
		t.Errorf("expected 1 tracked alert, got %v", stats["tracked_alerts"])
	}
}

func TestEscalationManager_AcknowledgeCancels(t *testing.T) {
	logger := zerolog.Nop()
	pipeline := NewAlertPipeline(logger, 100)
	cfg := EscalationConfig{
		Enabled: true,
		Timeouts: map[string]EscalationTimer{
			"HIGH": {Timeout: 100 * time.Millisecond, EscalateTo: "CRITICAL", ReNotify: false, MaxEscalations: 1},
		},
	}

	em := NewEscalationManager(logger, cfg, pipeline)
	defer em.Stop()

	var escalated atomic.Int32
	em.AddHandler(func(event *EscalationEvent, alert *Alert) {
		escalated.Add(1)
	})

	alert := makeAlertForEscalation(SeverityHigh)
	pipeline.Process(alert)
	em.Track(alert)

	// Acknowledge before timeout
	em.Acknowledge(alert.ID)

	time.Sleep(300 * time.Millisecond)

	if escalated.Load() != 0 {
		t.Error("expected no escalation after acknowledgement")
	}

	stats := em.Stats()
	if stats["tracked_alerts"].(int) != 0 {
		t.Errorf("expected 0 tracked alerts after ack, got %v", stats["tracked_alerts"])
	}
}

func TestEscalationManager_EscalatesOnTimeout(t *testing.T) {
	logger := zerolog.Nop()
	pipeline := NewAlertPipeline(logger, 100)
	cfg := EscalationConfig{
		Enabled: true,
		Timeouts: map[string]EscalationTimer{
			"MEDIUM": {Timeout: 100 * time.Millisecond, EscalateTo: "HIGH", ReNotify: false, MaxEscalations: 1},
		},
	}

	em := NewEscalationManager(logger, cfg, pipeline)
	defer em.Stop()

	eventCh := make(chan *EscalationEvent, 1)
	em.AddHandler(func(event *EscalationEvent, alert *Alert) {
		eventCh <- event
	})

	alert := makeAlertForEscalation(SeverityMedium)
	pipeline.Process(alert)
	em.Track(alert)

	select {
	case escalationEvent := <-eventCh:
		if escalationEvent.OldSeverity != "MEDIUM" {
			t.Errorf("expected old severity MEDIUM, got %s", escalationEvent.OldSeverity)
		}
		if escalationEvent.NewSeverity != "HIGH" {
			t.Errorf("expected new severity HIGH, got %s", escalationEvent.NewSeverity)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for escalation event")
	}
}

func TestEscalationManager_DisabledNoOp(t *testing.T) {
	logger := zerolog.Nop()
	pipeline := NewAlertPipeline(logger, 100)
	cfg := EscalationConfig{Enabled: false}

	em := NewEscalationManager(logger, cfg, pipeline)
	defer em.Stop()

	alert := makeAlertForEscalation(SeverityHigh)
	em.Track(alert)

	stats := em.Stats()
	if stats["tracked_alerts"].(int) != 0 {
		t.Error("expected no tracking when disabled")
	}
}

func TestEscalationManager_MaxEscalations(t *testing.T) {
	logger := zerolog.Nop()
	pipeline := NewAlertPipeline(logger, 100)
	cfg := EscalationConfig{
		Enabled: true,
		Timeouts: map[string]EscalationTimer{
			"HIGH": {Timeout: 50 * time.Millisecond, EscalateTo: "CRITICAL", ReNotify: false, MaxEscalations: 1},
		},
	}

	em := NewEscalationManager(logger, cfg, pipeline)
	defer em.Stop()

	var count atomic.Int32
	em.AddHandler(func(event *EscalationEvent, alert *Alert) {
		count.Add(1)
	})

	alert := makeAlertForEscalation(SeverityHigh)
	pipeline.Process(alert)
	em.Track(alert)

	time.Sleep(500 * time.Millisecond)

	if count.Load() > 1 {
		t.Errorf("expected max 1 escalation, got %d", count.Load())
	}
}

func TestEscalationManager_IgnoresUnknownSeverity(t *testing.T) {
	logger := zerolog.Nop()
	pipeline := NewAlertPipeline(logger, 100)
	cfg := EscalationConfig{
		Enabled: true,
		Timeouts: map[string]EscalationTimer{
			"CRITICAL": {Timeout: 100 * time.Millisecond, EscalateTo: "CRITICAL", ReNotify: false, MaxEscalations: 1},
		},
	}

	em := NewEscalationManager(logger, cfg, pipeline)
	defer em.Stop()

	// LOW severity has no escalation config
	alert := makeAlertForEscalation(SeverityLow)
	em.Track(alert)

	stats := em.Stats()
	if stats["tracked_alerts"].(int) != 0 {
		t.Error("expected no tracking for unconfigured severity")
	}
}
