package core

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

// ---------------------------------------------------------------------------
// alert_batcher.go — batches and deduplicates notifications to prevent
// alert storms from flooding SOC channels.
//
// If injection_shield fires 50 alerts from the same IP in 10 seconds,
// the SOC gets ONE summary notification instead of 50 webhook calls.
//
// Design:
//   - Groups alerts by module+source_ip within a configurable window
//   - Flushes batches when window expires or batch hits max size
//   - Emits a BatchedNotification with alert count, severity summary, etc.
//   - Pure Go, zero external dependencies
// ---------------------------------------------------------------------------

// AlertBatcherConfig controls batching behavior.
type AlertBatcherConfig struct {
	WindowDuration time.Duration `yaml:"window_duration" json:"window_duration"`
	MaxBatchSize   int           `yaml:"max_batch_size" json:"max_batch_size"`
	Enabled        bool          `yaml:"enabled" json:"enabled"`
}

// DefaultAlertBatcherConfig returns sane defaults.
func DefaultAlertBatcherConfig() AlertBatcherConfig {
	return AlertBatcherConfig{
		WindowDuration: 30 * time.Second,
		MaxBatchSize:   50,
		Enabled:        true,
	}
}

// BatchedNotification is the summary emitted when a batch flushes.
type BatchedNotification struct {
	BatchID        string    `json:"batch_id"`
	Module         string    `json:"module"`
	SourceIP       string    `json:"source_ip"`
	AlertCount     int       `json:"alert_count"`
	HighestSev     Severity  `json:"highest_severity"`
	FirstSeen      time.Time `json:"first_seen"`
	LastSeen       time.Time `json:"last_seen"`
	SampleAlertIDs []string  `json:"sample_alert_ids"`
	SeverityCounts map[string]int `json:"severity_counts"`
}

// BatchHandler is called when a batch is flushed.
type BatchHandler func(batch *BatchedNotification)

type alertBatch struct {
	module     string
	sourceIP   string
	alerts     []*Alert
	highestSev Severity
	firstSeen  time.Time
	lastSeen   time.Time
	sevCounts  map[string]int
	timer      *time.Timer
}

// AlertBatcher groups alerts by module+source for batched notification.
type AlertBatcher struct {
	mu       sync.Mutex
	logger   zerolog.Logger
	cfg      AlertBatcherConfig
	batches  map[string]*alertBatch // key: "module:source_ip"
	handlers []BatchHandler
	ctx      context.Context
	cancel   context.CancelFunc
}

// NewAlertBatcher creates a new batcher.
func NewAlertBatcher(logger zerolog.Logger, cfg AlertBatcherConfig) *AlertBatcher {
	ctx, cancel := context.WithCancel(context.Background())
	return &AlertBatcher{
		logger:   logger.With().Str("component", "alert_batcher").Logger(),
		cfg:      cfg,
		batches:  make(map[string]*alertBatch),
		handlers: make([]BatchHandler, 0),
		ctx:      ctx,
		cancel:   cancel,
	}
}

// AddHandler registers a function to call when a batch flushes.
func (b *AlertBatcher) AddHandler(handler BatchHandler) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.handlers = append(b.handlers, handler)
}

// Ingest adds an alert to the appropriate batch.
// Returns true if the alert was batched (caller should skip individual notification).
// Returns false if batching is disabled (caller should notify normally).
func (b *AlertBatcher) Ingest(alert *Alert) bool {
	if !b.cfg.Enabled {
		return false
	}

	sourceIP, _ := alert.Metadata["source_ip"].(string)
	key := fmt.Sprintf("%s:%s", alert.Module, sourceIP)

	b.mu.Lock()
	defer b.mu.Unlock()

	batch, exists := b.batches[key]
	if !exists {
		batch = &alertBatch{
			module:    alert.Module,
			sourceIP:  sourceIP,
			alerts:    make([]*Alert, 0, b.cfg.MaxBatchSize),
			firstSeen: time.Now(),
			sevCounts: make(map[string]int),
		}
		batch.timer = time.AfterFunc(b.cfg.WindowDuration, func() {
			b.flush(key)
		})
		b.batches[key] = batch
	}

	batch.alerts = append(batch.alerts, alert)
	batch.lastSeen = time.Now()
	batch.sevCounts[alert.Severity.String()]++
	if alert.Severity > batch.highestSev {
		batch.highestSev = alert.Severity
	}

	// Flush immediately if batch is full
	if len(batch.alerts) >= b.cfg.MaxBatchSize {
		batch.timer.Stop()
		go b.flush(key)
	}

	return true
}

func (b *AlertBatcher) flush(key string) {
	b.mu.Lock()
	batch, exists := b.batches[key]
	if !exists {
		b.mu.Unlock()
		return
	}
	delete(b.batches, key)
	handlers := make([]BatchHandler, len(b.handlers))
	copy(handlers, b.handlers)
	b.mu.Unlock()

	if len(batch.alerts) == 0 {
		return
	}

	// Build sample alert IDs (first 5)
	sampleIDs := make([]string, 0, 5)
	for i, a := range batch.alerts {
		if i >= 5 {
			break
		}
		sampleIDs = append(sampleIDs, a.ID)
	}

	notification := &BatchedNotification{
		BatchID:        fmt.Sprintf("batch-%s-%d", key, time.Now().UnixMilli()),
		Module:         batch.module,
		SourceIP:       batch.sourceIP,
		AlertCount:     len(batch.alerts),
		HighestSev:     batch.highestSev,
		FirstSeen:      batch.firstSeen,
		LastSeen:       batch.lastSeen,
		SampleAlertIDs: sampleIDs,
		SeverityCounts: batch.sevCounts,
	}

	b.logger.Info().
		Str("module", batch.module).
		Str("source_ip", batch.sourceIP).
		Int("count", len(batch.alerts)).
		Str("highest", batch.highestSev.String()).
		Msg("alert batch flushed")

	for _, handler := range handlers {
		handler(notification)
	}
}

// Stats returns current batcher state.
func (b *AlertBatcher) Stats() map[string]interface{} {
	b.mu.Lock()
	defer b.mu.Unlock()

	activeBatches := make([]map[string]interface{}, 0, len(b.batches))
	for key, batch := range b.batches {
		activeBatches = append(activeBatches, map[string]interface{}{
			"key":         key,
			"alert_count": len(batch.alerts),
			"highest_sev": batch.highestSev.String(),
			"first_seen":  batch.firstSeen,
		})
	}

	return map[string]interface{}{
		"enabled":        b.cfg.Enabled,
		"window_seconds": b.cfg.WindowDuration.Seconds(),
		"max_batch_size": b.cfg.MaxBatchSize,
		"active_batches": len(b.batches),
		"batches":        activeBatches,
	}
}

// Stop cancels all pending batch timers.
func (b *AlertBatcher) Stop() {
	b.cancel()
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, batch := range b.batches {
		batch.timer.Stop()
	}
	b.logger.Info().Msg("alert batcher stopped")
}
