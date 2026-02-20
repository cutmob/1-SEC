package core

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// mockExecutor is a test executor that succeeds or fails based on config.
type mockExecutor struct {
	shouldFail bool
	callCount  int
}

func (m *mockExecutor) Execute(ctx context.Context, alert *Alert, rule ResponseRule, logger zerolog.Logger) (string, string, error) {
	m.callCount++
	if m.shouldFail {
		return "", "", fmt.Errorf("mock failure")
	}
	return "mock-target", "mock action executed", nil
}

func (m *mockExecutor) Validate(rule ResponseRule) error { return nil }

func makeAlertForChain() *Alert {
	return &Alert{
		ID:       uuid.New().String(),
		Module:   "test_module",
		Severity: SeverityHigh,
		Title:    "Chain Test Alert",
		Metadata: map[string]interface{}{"source_ip": "10.0.0.1"},
	}
}

func TestChainExecutor_RegisterChain(t *testing.T) {
	logger := zerolog.Nop()
	executors := map[ActionType]ActionExecutor{
		ActionLog: &LogOnlyExecutor{},
	}

	ce := NewChainExecutor(logger, executors)

	chain := &ActionChain{
		Name: "test-chain",
		Steps: []ChainStep{
			{Name: "step1", Action: ActionLog},
			{Name: "step2", Action: ActionLog},
		},
		EntryPoint: "step1",
	}

	err := ce.RegisterChain(chain)
	if err != nil {
		t.Fatalf("RegisterChain failed: %v", err)
	}

	chains := ce.GetChains()
	if len(chains) != 1 {
		t.Errorf("expected 1 chain, got %d", len(chains))
	}
}

func TestChainExecutor_RegisterChainValidation(t *testing.T) {
	logger := zerolog.Nop()
	ce := NewChainExecutor(logger, nil)

	// Empty name
	err := ce.RegisterChain(&ActionChain{Steps: []ChainStep{{Name: "s1", Action: ActionLog}}})
	if err == nil {
		t.Error("expected error for empty chain name")
	}

	// No steps
	err = ce.RegisterChain(&ActionChain{Name: "empty"})
	if err == nil {
		t.Error("expected error for empty steps")
	}

	// Bad entry point
	err = ce.RegisterChain(&ActionChain{
		Name:       "bad-entry",
		Steps:      []ChainStep{{Name: "s1", Action: ActionLog}},
		EntryPoint: "nonexistent",
	})
	if err == nil {
		t.Error("expected error for bad entry point")
	}

	// Bad on_success reference
	err = ce.RegisterChain(&ActionChain{
		Name: "bad-ref",
		Steps: []ChainStep{
			{Name: "s1", Action: ActionLog, OnSuccess: "nonexistent"},
		},
		EntryPoint: "s1",
	})
	if err == nil {
		t.Error("expected error for bad on_success reference")
	}
}

func TestChainExecutor_SimpleChain(t *testing.T) {
	logger := zerolog.Nop()
	mock := &mockExecutor{shouldFail: false}
	executors := map[ActionType]ActionExecutor{
		ActionLog: mock,
	}

	ce := NewChainExecutor(logger, executors)

	chain := &ActionChain{
		Name: "simple",
		Steps: []ChainStep{
			{Name: "step1", Action: ActionLog, OnSuccess: "step2"},
			{Name: "step2", Action: ActionLog},
		},
		EntryPoint: "step1",
	}
	ce.RegisterChain(chain)

	alert := makeAlertForChain()
	record, err := ce.Execute(context.Background(), "simple", alert, logger)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if record.Status != "completed" {
		t.Errorf("expected status=completed, got %s", record.Status)
	}
	if len(record.Steps) != 2 {
		t.Errorf("expected 2 step records, got %d", len(record.Steps))
	}
	if mock.callCount != 2 {
		t.Errorf("expected 2 executor calls, got %d", mock.callCount)
	}
}

func TestChainExecutor_FailureBranch(t *testing.T) {
	logger := zerolog.Nop()
	failMock := &mockExecutor{shouldFail: true}
	successMock := &mockExecutor{shouldFail: false}

	executors := map[ActionType]ActionExecutor{
		ActionBlockIP: failMock,
		ActionLog:     successMock,
	}

	ce := NewChainExecutor(logger, executors)

	chain := &ActionChain{
		Name: "with-fallback",
		Steps: []ChainStep{
			{Name: "block", Action: ActionBlockIP, OnSuccess: "done", OnFailure: "log-fallback"},
			{Name: "log-fallback", Action: ActionLog},
			{Name: "done", Action: ActionLog},
		},
		EntryPoint: "block",
	}
	ce.RegisterChain(chain)

	alert := makeAlertForChain()
	record, err := ce.Execute(context.Background(), "with-fallback", alert, logger)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if record.Status != "partial" {
		t.Errorf("expected status=partial, got %s", record.Status)
	}
	if len(record.Steps) != 2 {
		t.Errorf("expected 2 steps (block failed → log-fallback), got %d", len(record.Steps))
	}
	if record.Steps[0].Status != ActionStatusFailed {
		t.Error("expected first step to fail")
	}
	if record.Steps[1].Status != ActionStatusSuccess {
		t.Error("expected fallback step to succeed")
	}
}

func TestChainExecutor_ChainNotFound(t *testing.T) {
	logger := zerolog.Nop()
	ce := NewChainExecutor(logger, nil)

	_, err := ce.Execute(context.Background(), "nonexistent", makeAlertForChain(), logger)
	if err == nil {
		t.Error("expected error for nonexistent chain")
	}
}

func TestChainExecutor_Records(t *testing.T) {
	logger := zerolog.Nop()
	executors := map[ActionType]ActionExecutor{
		ActionLog: &mockExecutor{shouldFail: false},
	}

	ce := NewChainExecutor(logger, executors)
	ce.RegisterChain(&ActionChain{
		Name:       "rec-test",
		Steps:      []ChainStep{{Name: "s1", Action: ActionLog}},
		EntryPoint: "s1",
	})

	ce.Execute(context.Background(), "rec-test", makeAlertForChain(), logger)
	ce.Execute(context.Background(), "rec-test", makeAlertForChain(), logger)

	records := ce.GetRecords(10)
	if len(records) != 2 {
		t.Errorf("expected 2 records, got %d", len(records))
	}
}

func TestChainExecutor_Stats(t *testing.T) {
	logger := zerolog.Nop()
	executors := map[ActionType]ActionExecutor{
		ActionLog: &mockExecutor{shouldFail: false},
	}

	ce := NewChainExecutor(logger, executors)
	ce.RegisterChain(&ActionChain{
		Name:       "stats-test",
		Steps:      []ChainStep{{Name: "s1", Action: ActionLog}},
		EntryPoint: "s1",
	})

	ce.Execute(context.Background(), "stats-test", makeAlertForChain(), logger)

	stats := ce.Stats()
	if stats["registered_chains"].(int) != 1 {
		t.Errorf("expected 1 registered chain, got %v", stats["registered_chains"])
	}
	if stats["total_executions"].(int) != 1 {
		t.Errorf("expected 1 execution, got %v", stats["total_executions"])
	}
}

func TestChainExecutor_DefaultEntryPoint(t *testing.T) {
	logger := zerolog.Nop()
	executors := map[ActionType]ActionExecutor{
		ActionLog: &mockExecutor{shouldFail: false},
	}

	ce := NewChainExecutor(logger, executors)

	// No explicit entry point — should default to first step
	chain := &ActionChain{
		Name:  "default-entry",
		Steps: []ChainStep{{Name: "first", Action: ActionLog}},
	}
	err := ce.RegisterChain(chain)
	if err != nil {
		t.Fatalf("RegisterChain failed: %v", err)
	}

	record, err := ce.Execute(context.Background(), "default-entry", makeAlertForChain(), logger)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if record.Status != "completed" {
		t.Errorf("expected completed, got %s", record.Status)
	}
}
