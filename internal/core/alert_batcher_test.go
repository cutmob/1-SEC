package core

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

func makeAlertForBatcher(module, sourceIP string, severity Severity) *Alert {
	return &Alert{
		ID:       uuid.New().String(),
		Module:   module,
		Severity: severity,
		Title:    "Test Alert",
		Metadata: map[string]interface{}{"source_ip": sourceIP},
	}
}

func TestAlertBatcher_BatchesAlerts(t *testing.T) {
	logger := zerolog.Nop()
	cfg := AlertBatcherConfig{
		WindowDuration: 200 * time.Millisecond,
		MaxBatchSize:   50,
		Enabled:        true,
	}

	batcher := NewAlertBatcher(logger, cfg)
	defer batcher.Stop()

	var flushed atomic.Int32
	batcher.AddHandler(func(batch *BatchedNotification) {
		flushed.Store(int32(batch.AlertCount))
	})

	// Ingest 5 alerts from same module+IP
	for i := 0; i < 5; i++ {
		batched := batcher.Ingest(makeAlertForBatcher("injection_shield", "10.0.0.1", SeverityHigh))
		if !batched {
			t.Error("expected alert to be batched")
		}
	}

	// Wait for window to flush
	time.Sleep(500 * time.Millisecond)

	if flushed.Load() != 5 {
		t.Errorf("expected batch of 5, got %d", flushed.Load())
	}
}

func TestAlertBatcher_FlushOnMaxSize(t *testing.T) {
	logger := zerolog.Nop()
	cfg := AlertBatcherConfig{
		WindowDuration: 10 * time.Second, // long window
		MaxBatchSize:   3,                // small batch
		Enabled:        true,
	}

	batcher := NewAlertBatcher(logger, cfg)
	defer batcher.Stop()

	var flushed atomic.Int32
	batcher.AddHandler(func(batch *BatchedNotification) {
		flushed.Store(int32(batch.AlertCount))
	})

	for i := 0; i < 3; i++ {
		batcher.Ingest(makeAlertForBatcher("network", "10.0.0.2", SeverityMedium))
	}

	time.Sleep(300 * time.Millisecond)

	if flushed.Load() != 3 {
		t.Errorf("expected flush at max size 3, got %d", flushed.Load())
	}
}

func TestAlertBatcher_SeparateBatches(t *testing.T) {
	logger := zerolog.Nop()
	cfg := AlertBatcherConfig{
		WindowDuration: 200 * time.Millisecond,
		MaxBatchSize:   50,
		Enabled:        true,
	}

	batcher := NewAlertBatcher(logger, cfg)
	defer batcher.Stop()

	var batchCount atomic.Int32
	batcher.AddHandler(func(batch *BatchedNotification) {
		batchCount.Add(1)
	})

	// Different modules should create separate batches
	batcher.Ingest(makeAlertForBatcher("module_a", "10.0.0.1", SeverityHigh))
	batcher.Ingest(makeAlertForBatcher("module_b", "10.0.0.1", SeverityHigh))

	time.Sleep(500 * time.Millisecond)

	if batchCount.Load() != 2 {
		t.Errorf("expected 2 separate batches, got %d", batchCount.Load())
	}
}

func TestAlertBatcher_Disabled(t *testing.T) {
	logger := zerolog.Nop()
	cfg := AlertBatcherConfig{Enabled: false}

	batcher := NewAlertBatcher(logger, cfg)
	defer batcher.Stop()

	batched := batcher.Ingest(makeAlertForBatcher("test", "10.0.0.1", SeverityHigh))
	if batched {
		t.Error("expected false when batcher is disabled")
	}
}

func TestAlertBatcher_SeverityTracking(t *testing.T) {
	logger := zerolog.Nop()
	cfg := AlertBatcherConfig{
		WindowDuration: 200 * time.Millisecond,
		MaxBatchSize:   50,
		Enabled:        true,
	}

	batcher := NewAlertBatcher(logger, cfg)
	defer batcher.Stop()

	var highestSev Severity
	batcher.AddHandler(func(batch *BatchedNotification) {
		highestSev = batch.HighestSev
	})

	batcher.Ingest(makeAlertForBatcher("test", "10.0.0.1", SeverityLow))
	batcher.Ingest(makeAlertForBatcher("test", "10.0.0.1", SeverityCritical))
	batcher.Ingest(makeAlertForBatcher("test", "10.0.0.1", SeverityMedium))

	time.Sleep(500 * time.Millisecond)

	if highestSev != SeverityCritical {
		t.Errorf("expected highest severity CRITICAL, got %s", highestSev.String())
	}
}

func TestAlertBatcher_Stats(t *testing.T) {
	logger := zerolog.Nop()
	cfg := AlertBatcherConfig{
		WindowDuration: 5 * time.Second,
		MaxBatchSize:   50,
		Enabled:        true,
	}

	batcher := NewAlertBatcher(logger, cfg)
	defer batcher.Stop()

	batcher.Ingest(makeAlertForBatcher("test", "10.0.0.1", SeverityHigh))

	stats := batcher.Stats()
	if stats["enabled"] != true {
		t.Error("expected enabled=true")
	}
	if stats["active_batches"].(int) != 1 {
		t.Errorf("expected 1 active batch, got %v", stats["active_batches"])
	}
}
