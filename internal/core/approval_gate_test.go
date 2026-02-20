package core

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

func makeAlertForApproval() *Alert {
	return &Alert{
		ID:       uuid.New().String(),
		Module:   "test_module",
		Severity: SeverityCritical,
		Title:    "Test Alert",
		Metadata: map[string]interface{}{"source_ip": "10.0.0.1"},
	}
}

func TestApprovalGate_RequiresApproval(t *testing.T) {
	logger := zerolog.Nop()
	cfg := DefaultApprovalGateConfig()
	cfg.Enabled = true

	ag := NewApprovalGate(logger, cfg)
	defer ag.Stop()

	if !ag.RequiresApproval(ActionKillProcess) {
		t.Error("expected kill_process to require approval")
	}
	if !ag.RequiresApproval(ActionQuarantineFile) {
		t.Error("expected quarantine_file to require approval")
	}
	if ag.RequiresApproval(ActionWebhook) {
		t.Error("expected webhook to NOT require approval")
	}
	if ag.RequiresApproval(ActionLog) {
		t.Error("expected log_only to NOT require approval")
	}
}

func TestApprovalGate_DisabledNoApproval(t *testing.T) {
	logger := zerolog.Nop()
	cfg := DefaultApprovalGateConfig()
	cfg.Enabled = false

	ag := NewApprovalGate(logger, cfg)
	defer ag.Stop()

	if ag.RequiresApproval(ActionKillProcess) {
		t.Error("expected no approval required when disabled")
	}
}

func TestApprovalGate_SubmitAndApprove(t *testing.T) {
	logger := zerolog.Nop()
	cfg := DefaultApprovalGateConfig()
	cfg.Enabled = true

	ag := NewApprovalGate(logger, cfg)
	defer ag.Stop()

	var executed atomic.Int32
	ag.AddHandler(func(approval *PendingApproval) {
		executed.Add(1)
	})

	alert := makeAlertForApproval()
	rule := ResponseRule{Action: ActionKillProcess, Params: map[string]string{}}

	id := ag.Submit(alert, rule, "pid:1234")

	pending := ag.GetPending()
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending, got %d", len(pending))
	}
	if pending[0].ID != id {
		t.Error("pending ID mismatch")
	}

	pa, err := ag.Approve(id, "admin@example.com")
	if err != nil {
		t.Fatalf("approve failed: %v", err)
	}
	if pa.Status != "approved" {
		t.Errorf("expected status=approved, got %s", pa.Status)
	}
	if pa.DecidedBy != "admin@example.com" {
		t.Errorf("expected decidedBy=admin@example.com, got %s", pa.DecidedBy)
	}

	if executed.Load() != 1 {
		t.Error("expected handler to be called on approve")
	}

	// Should be gone from pending
	pending = ag.GetPending()
	if len(pending) != 0 {
		t.Errorf("expected 0 pending after approve, got %d", len(pending))
	}
}

func TestApprovalGate_SubmitAndReject(t *testing.T) {
	logger := zerolog.Nop()
	cfg := DefaultApprovalGateConfig()
	cfg.Enabled = true

	ag := NewApprovalGate(logger, cfg)
	defer ag.Stop()

	var executed atomic.Int32
	ag.AddHandler(func(approval *PendingApproval) {
		executed.Add(1)
	})

	alert := makeAlertForApproval()
	rule := ResponseRule{Action: ActionDisableUser}

	id := ag.Submit(alert, rule, "user:jdoe")

	pa, err := ag.Reject(id, "soc-lead")
	if err != nil {
		t.Fatalf("reject failed: %v", err)
	}
	if pa.Status != "rejected" {
		t.Errorf("expected status=rejected, got %s", pa.Status)
	}

	// Handler should NOT be called on reject
	if executed.Load() != 0 {
		t.Error("handler should not be called on reject")
	}
}

func TestApprovalGate_DoubleApproveError(t *testing.T) {
	logger := zerolog.Nop()
	cfg := DefaultApprovalGateConfig()
	cfg.Enabled = true

	ag := NewApprovalGate(logger, cfg)
	defer ag.Stop()

	alert := makeAlertForApproval()
	rule := ResponseRule{Action: ActionKillProcess}
	id := ag.Submit(alert, rule, "target")

	_, err := ag.Approve(id, "admin")
	if err != nil {
		t.Fatal(err)
	}

	// Second approve should fail (not found since it was removed)
	_, err = ag.Approve(id, "admin")
	if err == nil {
		t.Error("expected error on double approve")
	}
}

func TestApprovalGate_NotFoundError(t *testing.T) {
	logger := zerolog.Nop()
	cfg := DefaultApprovalGateConfig()
	cfg.Enabled = true

	ag := NewApprovalGate(logger, cfg)
	defer ag.Stop()

	_, err := ag.Approve("nonexistent-id", "admin")
	if err == nil {
		t.Error("expected error for nonexistent ID")
	}
}

func TestApprovalGate_MaxPendingEviction(t *testing.T) {
	logger := zerolog.Nop()
	cfg := ApprovalGateConfig{
		Enabled:         true,
		RequireApproval: []string{"kill_process"},
		TTL:             10 * time.Minute,
		MaxPending:      2,
	}

	ag := NewApprovalGate(logger, cfg)
	defer ag.Stop()

	alert := makeAlertForApproval()
	rule := ResponseRule{Action: ActionKillProcess}

	ag.Submit(alert, rule, "target1")
	ag.Submit(alert, rule, "target2")
	// This should evict the oldest
	ag.Submit(alert, rule, "target3")

	pending := ag.GetPending()
	if len(pending) != 2 {
		t.Errorf("expected 2 pending after eviction, got %d", len(pending))
	}
}

func TestApprovalGate_Stats(t *testing.T) {
	logger := zerolog.Nop()
	cfg := DefaultApprovalGateConfig()
	cfg.Enabled = true

	ag := NewApprovalGate(logger, cfg)
	defer ag.Stop()

	stats := ag.Stats()
	if stats["enabled"] != true {
		t.Error("expected enabled=true")
	}
	if stats["pending_count"].(int) != 0 {
		t.Error("expected 0 pending")
	}
}

func TestApprovalGate_History(t *testing.T) {
	logger := zerolog.Nop()
	cfg := DefaultApprovalGateConfig()
	cfg.Enabled = true

	ag := NewApprovalGate(logger, cfg)
	defer ag.Stop()

	alert := makeAlertForApproval()
	rule := ResponseRule{Action: ActionKillProcess}

	id1 := ag.Submit(alert, rule, "target1")
	id2 := ag.Submit(alert, rule, "target2")

	ag.Approve(id1, "admin")
	ag.Reject(id2, "admin")

	history := ag.GetHistory(10)
	if len(history) != 2 {
		t.Errorf("expected 2 history entries, got %d", len(history))
	}
}
