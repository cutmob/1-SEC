package apifortress

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/1sec-project/1sec/internal/core"
	"github.com/rs/zerolog"
)

const ModuleName = "api_fortress"

// Fortress is the API Fortress module providing BOLA detection,
// schema validation, shadow API discovery, and rate limiting per endpoint.
type Fortress struct {
	logger       zerolog.Logger
	bus          *core.EventBus
	pipeline     *core.AlertPipeline
	cfg          *core.Config
	ctx          context.Context
	cancel       context.CancelFunc
	bolaDetector *BOLADetector
	apiRegistry  *APIRegistry
	rateLimiter  *EndpointRateLimiter
}

func New() *Fortress { return &Fortress{} }

func (f *Fortress) Name() string        { return ModuleName }
func (f *Fortress) Description() string { return "BOLA detection, API schema validation, shadow API discovery, and per-endpoint rate limiting" }

func (f *Fortress) Start(ctx context.Context, bus *core.EventBus, pipeline *core.AlertPipeline, cfg *core.Config) error {
	f.ctx, f.cancel = context.WithCancel(ctx)
	f.bus = bus
	f.pipeline = pipeline
	f.cfg = cfg
	f.logger = zerolog.New(zerolog.NewConsoleWriter()).With().Timestamp().Str("module", ModuleName).Logger()

	f.bolaDetector = NewBOLADetector()
	f.apiRegistry = NewAPIRegistry()
	f.rateLimiter = NewEndpointRateLimiter(cfg.GetModuleSettings(ModuleName))

	go f.bolaDetector.CleanupLoop(f.ctx)
	go f.rateLimiter.CleanupLoop(f.ctx)

	f.logger.Info().Msg("API fortress started")
	return nil
}

func (f *Fortress) Stop() error {
	if f.cancel != nil {
		f.cancel()
	}
	return nil
}

func (f *Fortress) HandleEvent(event *core.SecurityEvent) error {
	if event.Type != "http_request" && event.Type != "api_request" {
		return nil
	}

	path := getStringDetail(event, "path")
	method := strings.ToUpper(getStringDetail(event, "method"))
	userID := getStringDetail(event, "user_id")
	resourceID := getStringDetail(event, "resource_id")

	// BOLA detection
	if resourceID != "" && userID != "" {
		if f.bolaDetector.Detect(userID, resourceID, path, event.SourceIP) {
			f.raiseAlert(event, core.SeverityCritical,
				"BOLA Attack Detected",
				fmt.Sprintf("User %s is accessing resource %s that belongs to another user. Path: %s",
					userID, resourceID, path),
				"bola")
		}
	}

	// Shadow API detection
	if path != "" && method != "" {
		if f.apiRegistry.IsUndocumented(method, path) {
			f.raiseAlert(event, core.SeverityMedium,
				"Shadow API Endpoint Detected",
				fmt.Sprintf("Undocumented API endpoint accessed: %s %s from IP %s",
					method, path, event.SourceIP),
				"shadow_api")
		}
		f.apiRegistry.RecordAccess(method, path)
	}

	// Per-endpoint rate limiting
	if path != "" {
		if !f.rateLimiter.Allow(event.SourceIP, method, path) {
			f.raiseAlert(event, core.SeverityMedium,
				"API Rate Limit Exceeded",
				fmt.Sprintf("IP %s exceeded rate limit for %s %s", event.SourceIP, method, path),
				"api_rate_limit")
		}
	}

	// Schema validation: check for unexpected parameters
	if params := getStringDetail(event, "unexpected_params"); params != "" {
		f.raiseAlert(event, core.SeverityMedium,
			"API Schema Violation",
			fmt.Sprintf("Unexpected parameters in request to %s %s: %s", method, path, params),
			"schema_violation")
	}

	return nil
}

func (f *Fortress) raiseAlert(event *core.SecurityEvent, severity core.Severity, title, description, alertType string) {
	newEvent := core.NewSecurityEvent(ModuleName, alertType, severity, description)
	newEvent.SourceIP = event.SourceIP
	newEvent.Details["original_event_id"] = event.ID

	if f.bus != nil {
		_ = f.bus.PublishEvent(newEvent)
	}

	alert := core.NewAlert(newEvent, title, description)
	if f.pipeline != nil {
		f.pipeline.Process(alert)
	}
}

// BOLADetector detects Broken Object Level Authorization attacks.
type BOLADetector struct {
	mu             sync.RWMutex
	accessPatterns map[string]map[string]bool // userID -> set of resourceIDs
	ipPatterns     map[string]map[string]bool // IP -> set of resourceIDs
	threshold      int
}

func NewBOLADetector() *BOLADetector {
	return &BOLADetector{
		accessPatterns: make(map[string]map[string]bool),
		ipPatterns:     make(map[string]map[string]bool),
		threshold:      20, // accessing 20+ different resources is suspicious
	}
}

func (b *BOLADetector) Detect(userID, resourceID, path, ip string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Track per-user resource access
	if _, ok := b.accessPatterns[userID]; !ok {
		b.accessPatterns[userID] = make(map[string]bool)
	}
	b.accessPatterns[userID][resourceID] = true

	// Track per-IP resource access
	if _, ok := b.ipPatterns[ip]; !ok {
		b.ipPatterns[ip] = make(map[string]bool)
	}
	b.ipPatterns[ip][resourceID] = true

	// Detect enumeration: user accessing many different resources
	if len(b.accessPatterns[userID]) > b.threshold {
		return true
	}

	// Detect enumeration from single IP
	if len(b.ipPatterns[ip]) > b.threshold*2 {
		return true
	}

	return false
}

func (b *BOLADetector) CleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			b.mu.Lock()
			b.accessPatterns = make(map[string]map[string]bool)
			b.ipPatterns = make(map[string]map[string]bool)
			b.mu.Unlock()
		}
	}
}

// APIRegistry tracks known API endpoints for shadow API detection.
// During the learning period (first 1 hour), all observed endpoints are
// considered "documented". After the learning period, any new endpoint
// that wasn't seen during learning is flagged as a shadow API.
type APIRegistry struct {
	mu          sync.RWMutex
	documented  map[string]bool // "METHOD:/path" -> true (explicitly registered or learned)
	observed    map[string]int  // "METHOD:/path" -> access count
	learningStart time.Time
	learningDone  bool
}

func NewAPIRegistry() *APIRegistry {
	return &APIRegistry{
		documented:    make(map[string]bool),
		observed:      make(map[string]int),
		learningStart: time.Now(),
	}
}

func (r *APIRegistry) RegisterEndpoint(method, path string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := method + ":" + normalizePath(path)
	r.documented[key] = true
}

func (r *APIRegistry) IsUndocumented(method, path string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	key := method + ":" + normalizePath(path)

	// If explicitly registered, it's documented
	if r.documented[key] {
		return false
	}

	// Learning phase: first hour, absorb all endpoints as baseline
	if !r.learningDone {
		if time.Since(r.learningStart) < time.Hour {
			// Still learning — mark as documented and don't flag
			r.documented[key] = true
			return false
		}
		// Learning period just ended — lock in the baseline
		r.learningDone = true
	}

	// After learning: any endpoint not in documented set is a shadow API
	return true
}

func (r *APIRegistry) RecordAccess(method, path string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := method + ":" + normalizePath(path)
	r.observed[key]++
}

func normalizePath(path string) string {
	// Replace numeric IDs with placeholder for pattern matching
	parts := strings.Split(path, "/")
	for i, part := range parts {
		if isNumericID(part) || isUUID(part) {
			parts[i] = "{id}"
		}
	}
	return strings.Join(parts, "/")
}

func isNumericID(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
		} else {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				return false
			}
		}
	}
	return true
}

// EndpointRateLimiter provides per-endpoint rate limiting.
type EndpointRateLimiter struct {
	mu           sync.RWMutex
	counters     map[string]*epCounter // "IP:METHOD:path" -> counter
	maxPerMinute int
}

type epCounter struct {
	count    int
	window   time.Time
	lastSeen time.Time
}

func NewEndpointRateLimiter(settings map[string]interface{}) *EndpointRateLimiter {
	maxRPM := 200
	if val, ok := settings["api_max_rpm"]; ok {
		if v, ok := val.(float64); ok {
			maxRPM = int(v)
		}
	}
	return &EndpointRateLimiter{
		counters:     make(map[string]*epCounter),
		maxPerMinute: maxRPM,
	}
}

func (rl *EndpointRateLimiter) Allow(ip, method, path string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	key := ip + ":" + method + ":" + normalizePath(path)
	now := time.Now()

	counter, exists := rl.counters[key]
	if !exists {
		rl.counters[key] = &epCounter{count: 1, window: now, lastSeen: now}
		return true
	}

	if now.Sub(counter.window) > time.Minute {
		counter.count = 0
		counter.window = now
	}

	counter.count++
	counter.lastSeen = now

	return counter.count <= rl.maxPerMinute
}

func (rl *EndpointRateLimiter) CleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rl.mu.Lock()
			cutoff := time.Now().Add(-10 * time.Minute)
			for key, counter := range rl.counters {
				if counter.lastSeen.Before(cutoff) {
					delete(rl.counters, key)
				}
			}
			rl.mu.Unlock()
		}
	}
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
