package datapoisoning

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"regexp"
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
	webContentTracker *WebContentIntegrityTracker
}

func New() *Guard { return &Guard{} }

func (g *Guard) Name() string { return ModuleName }
func (g *Guard) EventTypes() []string {
	return []string{
		"training_update", "training_data_update", "dataset_update", "dataset_change", "data_ingestion",
		"rag_retrieval", "rag_query", "context_injection",
		"inference_result", "model_inference", "prediction",
		"model_update", "model_deploy", "weight_change",
		"model_download", "model_registry",
		// Agentic web content integrity (2026)
		"llms_txt_fetch", "markdown_endpoint_fetch",
	}
}
func (g *Guard) Description() string {
	return "Training data integrity validation, RAG source verification, adversarial input detection, model weight drift monitoring, and agentic web content integrity (llms.txt / markdown endpoint poisoning detection)"
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
	g.webContentTracker = NewWebContentIntegrityTracker()

	g.logger.Info().Msg("data poisoning guard started (+ agentic web content integrity)")
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
	case "model_download", "model_registry":
		g.handleModelSupplyChain(event)
	case "llms_txt_fetch", "markdown_endpoint_fetch":
		g.handleWebContentIntegrity(event)
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
	alert.Mitigations = getDataPoisoningMitigations(alertType)
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
			// Direct prompt injection
			"ignore previous instructions",
			"disregard all prior",
			"new system prompt",
			"IMPORTANT: override",
			"ADMIN: execute",
			"[SYSTEM]",
			"<|im_start|>system",
			// Indirect prompt injection via retrieved documents
			"ignore the above",
			"forget everything",
			"you are now",
			"act as if",
			"pretend you are",
			"switch to",
			"new instructions:",
			"override instructions",
			"do not follow previous",
			"discard prior context",
			// Delimiter injection
			"<|endoftext|>",
			"<|im_end|>",
			"### instruction",
			"[/INST]",
			"<<SYS>>",
			"</s>",
			// Data exfiltration via RAG
			"output all previous",
			"repeat the system prompt",
			"show me your instructions",
			"what are your rules",
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
	// Output distribution tracking (histogram buckets)
	baselineBuckets [10]int // confidence in [0,0.1), [0.1,0.2), ..., [0.9,1.0]
	currentBuckets  [10]int
}

type DriftResult struct {
	Significant       bool
	BaselineMean      float64
	CurrentMean       float64
	Delta             float64
	DistributionShift float64 // Jensen-Shannon divergence approximation
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
			stats.baselineBuckets = stats.currentBuckets
		}
		stats.currentSum = 0
		stats.currentCount = 0
		stats.currentBuckets = [10]int{}
		stats.windowStart = now
	}

	stats.currentSum += confidence
	stats.currentCount++

	// Track distribution bucket
	bucket := int(confidence * 10)
	if bucket >= 10 {
		bucket = 9
	}
	if bucket < 0 {
		bucket = 0
	}
	stats.currentBuckets[bucket]++
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

	// Distribution shift: simplified Jensen-Shannon divergence
	result.DistributionShift = jsDiv(stats.baselineBuckets[:], stats.baselineCount, stats.currentBuckets[:], stats.currentCount)

	if result.Delta > 0.15 || result.DistributionShift > 0.3 {
		result.Significant = true
	}

	return result
}

// jsDiv computes a simplified Jensen-Shannon divergence between two histograms.
func jsDiv(bBase []int, nBase int, bCurr []int, nCurr int) float64 {
	if nBase == 0 || nCurr == 0 {
		return 0
	}
	divergence := 0.0
	for i := 0; i < len(bBase); i++ {
		p := (float64(bBase[i]) + 1e-10) / float64(nBase)
		q := (float64(bCurr[i]) + 1e-10) / float64(nCurr)
		m := (p + q) / 2
		if p > 0 && m > 0 {
			divergence += p * math.Log2(p/m)
		}
		if q > 0 && m > 0 {
			divergence += q * math.Log2(q/m)
		}
	}
	return divergence / 2
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

// ===========================================================================
// Model Supply Chain Attack Detection (2025-2026)
// ===========================================================================

// handleModelSupplyChain detects supply chain attacks on model registries,
// including slopsquatting (AI-hallucinated package names registered by attackers),
// typosquatting on model hubs, and unsigned model downloads.
// Ref: OWASP LLM03:2025 — Supply Chain, extended to model registries.
// Ref: 2025-2026 research on slopsquatting attacks targeting AI model hubs.
func (g *Guard) handleModelSupplyChain(event *core.SecurityEvent) {
	modelName := getStringDetail(event, "model_name")
	registry := getStringDetail(event, "registry")
	hash := getStringDetail(event, "hash")
	signature := getStringDetail(event, "signature")
	downloads := getIntDetail(event, "download_count")
	author := getStringDetail(event, "author")
	createdDaysAgo := getIntDetail(event, "created_days_ago")

	if modelName == "" {
		return
	}

	// Unsigned model download
	if signature == "" && hash == "" {
		g.raiseAlert(event, core.SeverityHigh,
			"Unsigned Model Download",
			fmt.Sprintf("Model %s downloaded from %s without signature or hash verification. "+
				"Model weights could be backdoored.", modelName, registry),
			"unsigned_model")
	}

	// Newly created model with suspicious characteristics (slopsquatting indicator)
	if createdDaysAgo >= 0 && createdDaysAgo < 7 && downloads < 100 {
		g.raiseAlert(event, core.SeverityMedium,
			"Suspicious New Model on Registry",
			fmt.Sprintf("Model %s by %s on %s was created %d days ago with only %d downloads. "+
				"May be a slopsquatting or typosquatting attack.", modelName, author, registry, createdDaysAgo, downloads),
			"suspicious_model_registry")
	}

	// Known malicious model name patterns
	suspiciousPatterns := regexp.MustCompile("(?i)(backdoor|trojan|malicious|test-only|temp-model|_pwned|_evil)")
	if suspiciousPatterns.MatchString(modelName) {
		g.raiseAlert(event, core.SeverityCritical,
			"Suspicious Model Name Pattern",
			fmt.Sprintf("Model %s from %s has a suspicious name pattern indicating potential malicious intent.",
				modelName, registry),
			"malicious_model_name")
	}
}

// ===========================================================================
// Agentic Web Content Integrity (2026)
// ===========================================================================

// handleWebContentIntegrity tracks content hashes from llms.txt and markdown
// endpoints over time, detecting sudden changes that could indicate site
// compromise or content poisoning targeting AI agents.
func (g *Guard) handleWebContentIntegrity(event *core.SecurityEvent) {
	domain := getStringDetail(event, "domain")
	contentHash := getStringDetail(event, "content_hash")
	url := getStringDetail(event, "url")
	contentLength := getIntDetail(event, "content_length")
	agentID := getStringDetail(event, "agent_id")

	if domain == "" || contentHash == "" {
		return
	}

	result := g.webContentTracker.RecordContent(domain, url, contentHash, contentLength)

	if result.ContentChanged {
		severity := core.SeverityHigh
		if result.ChangePercent > 50 {
			severity = core.SeverityCritical
		}
		g.raiseAlert(event, severity,
			"llms.txt / Markdown Endpoint Content Changed",
			fmt.Sprintf("Content at %s (domain: %s) changed. Previous hash: %s, current: %s. "+
				"Size change: %d → %d bytes (%.1f%% delta). Agent: %s. "+
				"Sudden content changes on llms.txt or markdown endpoints may indicate "+
				"site compromise or targeted content poisoning for AI agents.",
				truncate(url, 100), domain,
				truncate(result.PreviousHash, 16), truncate(contentHash, 16),
				result.PreviousSize, contentLength, result.ChangePercent, agentID),
			"web_content_changed")
	}

	if result.RapidChanges {
		g.raiseAlert(event, core.SeverityHigh,
			"Rapid Content Changes on Agent-Facing Endpoint",
			fmt.Sprintf("Content at domain %s has changed %d times in %s. "+
				"Frequent content mutations on llms.txt/markdown endpoints are suspicious "+
				"and may indicate an active content poisoning campaign.",
				domain, result.ChangeCount, result.Window),
			"web_content_rapid_changes")
	}

	if result.NewDomain {
		g.raiseAlert(event, core.SeverityLow,
			"First llms.txt / Markdown Fetch from New Domain",
			fmt.Sprintf("Agent %s fetched content from new domain %s (%s). "+
				"Content hash: %s, size: %d bytes. Baseline established for integrity tracking.",
				agentID, domain, truncate(url, 100), truncate(contentHash, 16), contentLength),
			"web_content_new_domain")
	}
}

// WebContentIntegrityTracker tracks content hashes per domain over time.
type WebContentIntegrityTracker struct {
	mu      sync.RWMutex
	domains map[string]*webContentRecord
}

type webContentRecord struct {
	LastHash     string
	LastSize     int
	ChangeCount  int
	ChangeWindow time.Time
	FirstSeen    time.Time
	FetchCount   int
}

type WebContentResult struct {
	ContentChanged bool
	RapidChanges   bool
	NewDomain      bool
	PreviousHash   string
	PreviousSize   int
	ChangePercent  float64
	ChangeCount    int
	Window         string
}

func NewWebContentIntegrityTracker() *WebContentIntegrityTracker {
	return &WebContentIntegrityTracker{
		domains: make(map[string]*webContentRecord),
	}
}

func (wt *WebContentIntegrityTracker) RecordContent(domain, url, contentHash string, contentLength int) WebContentResult {
	wt.mu.Lock()
	defer wt.mu.Unlock()

	result := WebContentResult{}
	now := time.Now()

	rec, exists := wt.domains[domain]
	if !exists {
		wt.domains[domain] = &webContentRecord{
			LastHash:     contentHash,
			LastSize:     contentLength,
			ChangeWindow: now,
			FirstSeen:    now,
			FetchCount:   1,
		}
		result.NewDomain = true
		return result
	}

	rec.FetchCount++

	// Reset change window
	if now.Sub(rec.ChangeWindow) > time.Hour {
		rec.ChangeCount = 0
		rec.ChangeWindow = now
	}

	// Check for content change
	if rec.LastHash != "" && contentHash != "" && rec.LastHash != contentHash {
		result.ContentChanged = true
		result.PreviousHash = rec.LastHash
		result.PreviousSize = rec.LastSize

		// Calculate size change percentage
		if rec.LastSize > 0 {
			delta := float64(contentLength - rec.LastSize)
			if delta < 0 {
				delta = -delta
			}
			result.ChangePercent = (delta / float64(rec.LastSize)) * 100
		}

		rec.ChangeCount++
		rec.LastHash = contentHash
		rec.LastSize = contentLength
	}

	result.ChangeCount = rec.ChangeCount
	result.Window = now.Sub(rec.ChangeWindow).Round(time.Second).String()

	// Rapid changes: more than 3 content changes in an hour
	if rec.ChangeCount > 3 {
		result.RapidChanges = true
	}

	return result
}

// ===========================================================================
// Contextual Mitigations
// ===========================================================================

func getDataPoisoningMitigations(alertType string) []string {
	switch alertType {
	case "data_integrity_violation":
		return []string{
			"Verify training data provenance using cryptographic hashes",
			"Implement immutable audit logs for all dataset modifications",
			"Use content-addressable storage for training data",
			"Require multi-party approval for training data changes",
		}
	case "anomalous_data_change":
		return []string{
			"Investigate the source and nature of the anomalous data change",
			"Implement statistical anomaly detection on data ingestion pipelines",
			"Set change rate thresholds and alert on violations",
			"Maintain data lineage tracking for all training datasets",
		}
	case "untrusted_data_source":
		return []string{
			"Maintain an allowlist of trusted data sources",
			"Validate data source identity and integrity before ingestion",
			"Implement data quarantine for untrusted sources pending review",
		}
	case "rag_poisoning":
		return []string{
			"Scan RAG retrieval results for injection payloads before LLM consumption",
			"Implement content integrity checks on vector store entries",
			"Use separate safety classifiers for retrieved context",
			"Maintain allowlists for trusted RAG content sources",
		}
	case "rag_untrusted_source":
		return []string{
			"Validate RAG sources against a trusted allowlist",
			"Implement source reputation scoring for RAG retrievals",
			"Log and audit all RAG source access patterns",
		}
	case "adversarial_input":
		return []string{
			"Implement input validation and anomaly detection before model inference",
			"Use adversarial training to improve model robustness",
			"Monitor confidence distributions for signs of adversarial perturbation",
		}
	case "model_tampering":
		return []string{
			"Use cryptographic signing for model weights and verify before deployment",
			"Implement model integrity checks in the deployment pipeline",
			"Store model hashes in a tamper-proof registry",
			"Require multi-party approval for model deployments",
		}
	case "model_drift":
		return []string{
			"Monitor model performance metrics continuously for drift",
			"Implement automated model retraining triggers on drift detection",
			"Maintain baseline performance metrics for comparison",
			"Investigate root cause — drift may indicate data poisoning",
		}
	case "unsigned_model":
		return []string{
			"Require cryptographic signatures for all model downloads (OWASP LLM03:2025)",
			"Verify model hashes against a trusted registry before deployment",
			"Use model provenance tracking (e.g., SLSA for ML models)",
		}
	case "suspicious_model_registry":
		return []string{
			"Verify model author identity and reputation before downloading",
			"Check model download counts and community reviews",
			"Use only models from verified publishers on trusted registries",
			"Scan downloaded models for known backdoor patterns",
		}
	case "malicious_model_name":
		return []string{
			"Block download of models with suspicious name patterns",
			"Report suspicious models to the registry maintainers",
			"Implement model name validation against known-good patterns",
		}
	case "web_content_changed":
		return []string{
			"Investigate the content change — compare previous and current versions",
			"Verify the domain has not been compromised (check DNS, TLS cert, WHOIS)",
			"Quarantine the changed content until verified by a human operator",
			"Implement content signing for llms.txt endpoints to detect tampering",
		}
	case "web_content_rapid_changes":
		return []string{
			"Temporarily block agent access to the rapidly-changing endpoint",
			"Investigate whether the domain is under active attack",
			"Implement content change rate limits in the agent's fetch pipeline",
			"Alert the site owner about suspicious content mutation patterns",
		}
	case "web_content_new_domain":
		return []string{
			"Verify the new domain is legitimate and authorized for agent access",
			"Establish content baseline and monitor for future changes",
			"Add the domain to the agent's authorized domain list if appropriate",
		}
	default:
		return []string{
			"Verify training data provenance and integrity",
			"Implement data validation pipelines with anomaly detection",
			"Use cryptographic signing for model weights and datasets",
		}
	}
}
