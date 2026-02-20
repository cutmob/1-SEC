package datapoisoning

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/1sec-project/1sec/internal/core"
	"github.com/rs/zerolog"
)

const ModuleName = "data_poisoning"

// Guard is the Data Poisoning Guard module providing training data integrity,
// RAG source verification, adversarial input detection, and model drift monitoring.
type Guard struct {
	logger       zerolog.Logger
	bus          *core.EventBus
	pipeline     *core.AlertPipeline
	cfg          *core.Config
	ctx          context.Context
	cancel       context.CancelFunc
	dataTracker  *DataIntegrityTracker
	ragVerifier  *RAGVerifier
	driftMonitor *ModelDriftMonitor
}

func New() *Guard { return &Guard{} }

func (g *Guard) Name() string { return ModuleName }
func (g *Guard) Description() string {
	return "Training data integrity validation, RAG source verification, adversarial input detection, and model weight drift monitoring"
}

func (g *Guard) Start(ctx context.Context, bus *core.EventBus, pipeline *core.AlertPipeline, cfg *core.Config) error {
	g.ctx, g.cancel = context.WithCancel(ctx)
	g.bus = bus
	g.pipeline = pipeline
	g.cfg = cfg
	g.logger = zerolog.New(zerolog.NewConsoleWriter()).With().Timestamp().Str("module", ModuleName).Logger()

	g.dataTracker = NewDataIntegrityTracker()
	g.ragVerifier = NewRAGVerifier()
	g.driftMonitor = NewModelDriftMonitor()

	g.logger.Info().Msg("data poisoning guard started")
	return nil
}

func (g *Guard) Stop() error {
	if g.cancel != nil {
		g.cancel()
	}
	return nil
}

func (g *Guard) HandleEvent(event *core.SecurityEvent) error {
	switch event.Type {
	case "training_data_update", "dataset_change", "data_ingestion":
		g.handleDataUpdate(event)
	case "rag_query", "rag_retrieval", "context_injection":
		g.handleRAGEvent(event)
	case "model_inference", "prediction":
		g.handleInference(event)
	case "model_update", "model_deploy", "weight_change":
		g.handleModelUpdate(event)
	}
	return nil
}

func (g *Guard) handleDataUpdate(event *core.SecurityEvent) {
	datasetID := getStringDetail(event, "dataset_id")
	source := getStringDetail(event, "source")
	hash := getStringDetail(event, "hash")
	recordCount := getIntDetail(event, "record_count")
	changePercent := getFloatDetail(event, "change_percent")

	if datasetID == "" {
		return
	}

	result := g.dataTracker.RecordUpdate(datasetID, source, hash, recordCount, changePercent)

	if result.IntegrityViolation {
		g.raiseAlert(event, core.SeverityCritical,
			"Training Data Integrity Violation",
			fmt.Sprintf("Dataset %s hash changed unexpectedly. Previous: %s, Current: %s. Source: %s",
				datasetID, truncate(result.PreviousHash, 16), truncate(hash, 16), source),
			"data_integrity_violation")
	}

	if result.AnomalousChange {
		g.raiseAlert(event, core.SeverityHigh,
			"Anomalous Training Data Change",
			fmt.Sprintf("Dataset %s changed by %.1f%% (%d records). This exceeds the normal change threshold. Possible data poisoning.",
				datasetID, changePercent, recordCount),
			"anomalous_data_change")
	}

	if result.UntrustedSource {
		g.raiseAlert(event, core.SeverityHigh,
			"Untrusted Data Source",
			fmt.Sprintf("Dataset %s updated from untrusted source: %s", datasetID, source),
			"untrusted_data_source")
	}
}

func (g *Guard) handleRAGEvent(event *core.SecurityEvent) {
	query := getStringDetail(event, "query")
	sources := getStringDetail(event, "sources")
	content := getStringDetail(event, "retrieved_content")

	if content == "" {
		return
	}

	result := g.ragVerifier.Verify(query, sources, content)

	if result.PoisonedContent {
		g.raiseAlert(event, core.SeverityCritical,
			"RAG Content Poisoning Detected",
			fmt.Sprintf("Retrieved RAG content contains injection patterns. Source: %s. Indicators: %s",
				sources, strings.Join(result.Indicators, ", ")),
			"rag_poisoning")
	}

	if result.UntrustedSource {
		g.raiseAlert(event, core.SeverityMedium,
			"RAG Untrusted Source",
			fmt.Sprintf("RAG retrieval from untrusted source: %s", sources),
			"rag_untrusted_source")
	}
}

func (g *Guard) handleInference(event *core.SecurityEvent) {
	modelID := getStringDetail(event, "model_id")
	confidence := getFloatDetail(event, "confidence")
	inputHash := getStringDetail(event, "input_hash")

	if modelID == "" {
		return
	}

	// Adversarial input detection: unusually low confidence or confidence oscillation
	if confidence > 0 && confidence < 0.1 {
		g.raiseAlert(event, core.SeverityMedium,
			"Potential Adversarial Input",
			fmt.Sprintf("Model %s returned very low confidence (%.4f) for input %s. May indicate adversarial perturbation.",
				modelID, confidence, truncate(inputHash, 16)),
			"adversarial_input")
	}

	g.driftMonitor.RecordPrediction(modelID, confidence)
}

func (g *Guard) handleModelUpdate(event *core.SecurityEvent) {
	modelID := getStringDetail(event, "model_id")
	version := getStringDetail(event, "version")
	weightHash := getStringDetail(event, "weight_hash")
	expectedHash := getStringDetail(event, "expected_hash")
	source := getStringDetail(event, "source")

	if modelID == "" {
		return
	}

	if weightHash != "" && expectedHash != "" && weightHash != expectedHash {
		g.raiseAlert(event, core.SeverityCritical,
			"Model Weight Tampering Detected",
			fmt.Sprintf("Model %s (v%s) weight hash mismatch. Expected: %s, Got: %s. Source: %s. Model may be backdoored.",
				modelID, version, truncate(expectedHash, 16), truncate(weightHash, 16), source),
			"model_tampering")
	}

	// Check drift
	drift := g.driftMonitor.CheckDrift(modelID)
	if drift.Significant {
		g.raiseAlert(event, core.SeverityHigh,
			"Model Drift Detected",
			fmt.Sprintf("Model %s showing significant prediction drift. Mean confidence shifted from %.4f to %.4f (delta: %.4f).",
				modelID, drift.BaselineMean, drift.CurrentMean, drift.Delta),
			"model_drift")
	}
}

func (g *Guard) raiseAlert(event *core.SecurityEvent, severity core.Severity, title, description, alertType string) {
	newEvent := core.NewSecurityEvent(ModuleName, alertType, severity, description)
	newEvent.SourceIP = event.SourceIP
	newEvent.Details["original_event_id"] = event.ID

	if g.bus != nil {
		_ = g.bus.PublishEvent(newEvent)
	}

	alert := core.NewAlert(newEvent, title, description)
	alert.Mitigations = []string{
		"Verify training data provenance and integrity",
		"Implement data validation pipelines with anomaly detection",
		"Use cryptographic signing for model weights and datasets",
		"Monitor model performance metrics for drift",
		"Validate RAG sources against a trusted allowlist",
	}
	if g.pipeline != nil {
		g.pipeline.Process(alert)
	}
}

// DataIntegrityTracker tracks dataset hashes and change patterns.
type DataIntegrityTracker struct {
	mu       sync.RWMutex
	datasets map[string]*datasetRecord
	trusted  map[string]bool
}

type datasetRecord struct {
	LastHash        string
	LastRecordCount int
	AvgChangeRate   float64
	UpdateCount     int
	LastUpdate      time.Time
}

type DataUpdateResult struct {
	IntegrityViolation bool
	AnomalousChange    bool
	UntrustedSource    bool
	PreviousHash       string
}

func NewDataIntegrityTracker() *DataIntegrityTracker {
	return &DataIntegrityTracker{
		datasets: make(map[string]*datasetRecord),
		trusted:  make(map[string]bool),
	}
}

func (dt *DataIntegrityTracker) RecordUpdate(datasetID, source, hash string, recordCount int, changePercent float64) DataUpdateResult {
	dt.mu.Lock()
	defer dt.mu.Unlock()

	result := DataUpdateResult{}

	rec, exists := dt.datasets[datasetID]
	if !exists {
		dt.datasets[datasetID] = &datasetRecord{
			LastHash: hash, LastRecordCount: recordCount,
			AvgChangeRate: changePercent, UpdateCount: 1,
			LastUpdate: time.Now(),
		}
		return result
	}

	result.PreviousHash = rec.LastHash

	// Integrity check: unexpected hash change
	if rec.LastHash != "" && hash != "" && rec.LastHash != hash {
		result.IntegrityViolation = true
	}

	// Anomalous change: change rate significantly exceeds average
	if rec.UpdateCount > 3 && changePercent > rec.AvgChangeRate*3 && changePercent > 10 {
		result.AnomalousChange = true
	}

	// Untrusted source
	if source != "" && len(dt.trusted) > 0 && !dt.trusted[source] {
		result.UntrustedSource = true
	}

	// Update record
	rec.AvgChangeRate = (rec.AvgChangeRate*float64(rec.UpdateCount) + changePercent) / float64(rec.UpdateCount+1)
	rec.UpdateCount++
	rec.LastHash = hash
	rec.LastRecordCount = recordCount
	rec.LastUpdate = time.Now()

	return result
}

// RAGVerifier checks RAG retrieval content for poisoning.
type RAGVerifier struct {
	injectionPatterns []string
	trustedSources    map[string]bool
}

type RAGResult struct {
	PoisonedContent bool
	UntrustedSource bool
	Indicators      []string
}

func NewRAGVerifier() *RAGVerifier {
	return &RAGVerifier{
		injectionPatterns: []string{
			"ignore previous instructions",
			"disregard all prior",
			"new system prompt",
			"IMPORTANT: override",
			"ADMIN: execute",
			"[SYSTEM]",
			"<|im_start|>system",
		},
		trustedSources: make(map[string]bool),
	}
}

func (rv *RAGVerifier) Verify(query, sources, content string) RAGResult {
	result := RAGResult{}
	contentLower := strings.ToLower(content)

	for _, pattern := range rv.injectionPatterns {
		if strings.Contains(contentLower, strings.ToLower(pattern)) {
			result.PoisonedContent = true
			result.Indicators = append(result.Indicators, fmt.Sprintf("injection pattern: %q", pattern))
		}
	}

	if sources != "" && len(rv.trustedSources) > 0 {
		for _, src := range strings.Split(sources, ",") {
			src = strings.TrimSpace(src)
			if src != "" && !rv.trustedSources[src] {
				result.UntrustedSource = true
				result.Indicators = append(result.Indicators, fmt.Sprintf("untrusted source: %s", src))
			}
		}
	}

	return result
}

// ModelDriftMonitor tracks model prediction patterns for drift detection.
type ModelDriftMonitor struct {
	mu     sync.RWMutex
	models map[string]*modelStats
}

type modelStats struct {
	baselineSum   float64
	baselineCount int
	currentSum    float64
	currentCount  int
	windowStart   time.Time
}

type DriftResult struct {
	Significant  bool
	BaselineMean float64
	CurrentMean  float64
	Delta        float64
}

func NewModelDriftMonitor() *ModelDriftMonitor {
	return &ModelDriftMonitor{models: make(map[string]*modelStats)}
}

func (dm *ModelDriftMonitor) RecordPrediction(modelID string, confidence float64) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	stats, exists := dm.models[modelID]
	if !exists {
		stats = &modelStats{windowStart: time.Now()}
		dm.models[modelID] = stats
	}

	now := time.Now()
	if now.Sub(stats.windowStart) > time.Hour {
		// Rotate: current becomes baseline
		if stats.currentCount > 0 {
			stats.baselineSum = stats.currentSum
			stats.baselineCount = stats.currentCount
		}
		stats.currentSum = 0
		stats.currentCount = 0
		stats.windowStart = now
	}

	stats.currentSum += confidence
	stats.currentCount++
}

func (dm *ModelDriftMonitor) CheckDrift(modelID string) DriftResult {
	dm.mu.RLock()
	defer dm.mu.RUnlock()

	result := DriftResult{}
	stats, exists := dm.models[modelID]
	if !exists || stats.baselineCount < 10 || stats.currentCount < 10 {
		return result
	}

	result.BaselineMean = stats.baselineSum / float64(stats.baselineCount)
	result.CurrentMean = stats.currentSum / float64(stats.currentCount)
	result.Delta = math.Abs(result.CurrentMean - result.BaselineMean)

	if result.Delta > 0.15 {
		result.Significant = true
	}

	return result
}

// HashData returns SHA-256 hex digest.
func HashData(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func getStringDetail(event *core.SecurityEvent, key string) string {
	if event.Details == nil {
		return ""
	}
	if val, ok := event.Details[key].(string); ok {
		return val
	}
	return ""
}

func getIntDetail(event *core.SecurityEvent, key string) int {
	if event.Details == nil {
		return 0
	}
	switch v := event.Details[key].(type) {
	case int:
		return v
	case float64:
		return int(v)
	}
	return 0
}

func getFloatDetail(event *core.SecurityEvent, key string) float64 {
	if event.Details == nil {
		return 0
	}
	switch v := event.Details[key].(type) {
	case float64:
		return v
	case int:
		return float64(v)
	}
	return 0
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
