package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/1sec-project/1sec/internal/core"
	"github.com/1sec-project/1sec/internal/modules/network"
	"github.com/rs/zerolog"
)

// Server is the 1SEC REST API server.
type Server struct {
	engine *core.Engine
	server *http.Server
	logger zerolog.Logger
}

// NewServer creates a new API server.
func NewServer(engine *core.Engine) *Server {
	s := &Server{
		engine: engine,
		logger: engine.Logger.With().Str("component", "api_server").Logger(),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/status", s.handleStatus)
	mux.HandleFunc("/api/v1/modules", s.handleModules)
	mux.HandleFunc("/api/v1/alerts", s.handleAlerts)
	mux.HandleFunc("/api/v1/alerts/", s.handleAlertByID)
	mux.HandleFunc("/api/v1/alerts/clear", s.handleAlertsClear)
	mux.HandleFunc("/api/v1/config", s.handleConfig)
	mux.HandleFunc("/api/v1/events", s.handleIngestEvent)
	mux.HandleFunc("/api/v1/logs", s.handleLogs)
	mux.HandleFunc("/api/v1/correlator", s.handleCorrelator)
	mux.HandleFunc("/api/v1/threats", s.handleThreats)
	mux.HandleFunc("/api/v1/rust", s.handleRustStatus)
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/api/v1/shutdown", s.handleShutdown)

	// Build middleware chain: CORS -> logging -> rate limit -> auth -> handler
	handler := corsMiddleware(
		loggingMiddleware(
			rateLimitMiddleware(
				authMiddleware(mux, engine.Config, s.logger),
				100, // 100 requests per second per IP
			),
			s.logger,
		),
		engine.Config.Server.CORSOrigins,
	)

	s.server = &http.Server{
		Addr:         fmt.Sprintf("%s:%d", engine.Config.Server.Host, engine.Config.Server.Port),
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return s
}

// Start begins serving the API.
func (s *Server) Start() error {
	s.logger.Info().Str("addr", s.server.Addr).Msg("API server starting")
	if s.engine.Config.AuthEnabled() {
		s.logger.Info().Int("keys", len(s.engine.Config.Server.APIKeys)).Msg("API authentication enabled")
	} else {
		s.logger.Warn().Msg("API authentication disabled — set api_keys in config or ONESEC_API_KEY env var")
	}
	go func() {
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.logger.Error().Err(err).Msg("API server error")
		}
	}()
	return nil
}

// Stop gracefully shuts down the API server.
func (s *Server) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.server.Shutdown(ctx)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().UTC(),
	})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	modules := make([]map[string]interface{}, 0)
	for _, mod := range s.engine.Registry.All() {
		modules = append(modules, map[string]interface{}{
			"name":        mod.Name(),
			"description": mod.Description(),
			"enabled":     s.engine.Config.IsModuleEnabled(mod.Name()),
		})
	}

	rustEngineStatus := "disabled"
	if s.engine.Config.RustEngine.Enabled {
		if s.engine.RustSidecar != nil && s.engine.RustSidecar.Running() {
			rustEngineStatus = "running"
		} else {
			rustEngineStatus = "enabled_not_running"
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"version":       "1.0.0",
		"status":        "running",
		"bus_connected": s.engine.Bus.IsConnected(),
		"modules_total": s.engine.Registry.Count(),
		"alerts_total":  s.engine.Pipeline.Count(),
		"rust_engine":   rustEngineStatus,
		"modules":       modules,
		"timestamp":     time.Now().UTC(),
	})
}

func (s *Server) handleModules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	modules := make([]map[string]interface{}, 0)
	for _, mod := range s.engine.Registry.All() {
		modules = append(modules, map[string]interface{}{
			"name":        mod.Name(),
			"description": mod.Description(),
			"enabled":     s.engine.Config.IsModuleEnabled(mod.Name()),
		})
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"modules": modules,
		"total":   len(modules),
	})
}

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	limitStr := r.URL.Query().Get("limit")
	limit := 100
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	severityStr := r.URL.Query().Get("min_severity")
	minSeverity := core.SeverityInfo
	switch severityStr {
	case "LOW":
		minSeverity = core.SeverityLow
	case "MEDIUM":
		minSeverity = core.SeverityMedium
	case "HIGH":
		minSeverity = core.SeverityHigh
	case "CRITICAL":
		minSeverity = core.SeverityCritical
	}

	alerts := s.engine.Pipeline.GetAlerts(minSeverity, limit)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"alerts": alerts,
		"total":  len(alerts),
	})
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Redact API keys from the response
	safeCfg := *s.engine.Config
	safeCfg.Server.APIKeys = nil
	writeJSON(w, http.StatusOK, safeCfg)
}

func (s *Server) handleIngestEvent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var event core.SecurityEvent
	// Limit body size to 1MB to prevent memory abuse
	limited := io.LimitReader(r.Body, 1<<20)
	if err := json.NewDecoder(limited).Decode(&event); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid event JSON: " + err.Error()})
		return
	}

	if event.ID == "" {
		event.ID = "ext-" + time.Now().Format("20060102150405.000")
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	if event.Source == "" {
		event.Source = "external"
	}

	if err := s.engine.Bus.PublishEvent(&event); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to publish event"})
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]string{
		"status":   "accepted",
		"event_id": event.ID,
	})
}

func (s *Server) handleShutdown(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "shutting_down",
		"message": "1SEC engine is shutting down gracefully",
	})
	go func() {
		time.Sleep(250 * time.Millisecond)
		s.logger.Info().Msg("shutdown requested via API")
		// Send SIGINT to self so the main signal handler performs full cleanup
		// (syslog stop, API server stop, engine shutdown) in the correct order.
		p, err := os.FindProcess(os.Getpid())
		if err != nil {
			s.logger.Error().Err(err).Msg("failed to find own process for shutdown signal")
			os.Exit(0)
		}
		if err := p.Signal(syscall.SIGINT); err != nil {
			s.logger.Error().Err(err).Msg("failed to send shutdown signal")
			os.Exit(0)
		}
	}()
}

// handleAlertByID handles GET/PATCH on /api/v1/alerts/{id}
func (s *Server) handleAlertByID(w http.ResponseWriter, r *http.Request) {
	// Extract alert ID from path: /api/v1/alerts/{id}
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/alerts/")
	alertID := strings.TrimSuffix(path, "/")
	if alertID == "" || alertID == "clear" {
		// Let the clear handler or alerts handler deal with it
		return
	}

	switch r.Method {
	case http.MethodGet:
		alert := s.engine.Pipeline.GetAlertByID(alertID)
		if alert == nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "alert not found"})
			return
		}
		writeJSON(w, http.StatusOK, alert)

	case http.MethodPatch:
		var body struct {
			Status string `json:"status"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
			return
		}
		status, ok := core.ParseAlertStatus(body.Status)
		if !ok {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "invalid status — use OPEN, ACKNOWLEDGED, RESOLVED, or FALSE_POSITIVE",
			})
			return
		}
		alert, found := s.engine.Pipeline.UpdateAlertStatus(alertID, status)
		if !found {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "alert not found"})
			return
		}
		writeJSON(w, http.StatusOK, alert)

	case http.MethodDelete:
		deleted := s.engine.Pipeline.DeleteAlert(alertID)
		if !deleted {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "alert not found"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted", "id": alertID})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleAlertsClear handles POST /api/v1/alerts/clear
func (s *Server) handleAlertsClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	count := s.engine.Pipeline.ClearAlerts()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "cleared",
		"cleared": count,
	})
}

// handleLogs streams recent log entries. The engine logs are captured in a ring buffer.
func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	limitStr := r.URL.Query().Get("limit")
	limit := 100
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	entries := s.engine.GetLogEntries(limit)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"logs":  entries,
		"total": len(entries),
	})
}

func (s *Server) handleCorrelator(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.engine.Correlator == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"status": "not_started",
		})
		return
	}
	writeJSON(w, http.StatusOK, s.engine.Correlator.Status())
}

func (s *Server) handleThreats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Find the network_guardian module and get its IP reputation data
	var threats []network.IPThreatInfo
	for _, mod := range s.engine.Registry.All() {
		if mod.Name() == "network_guardian" {
			if g, ok := mod.(*network.Guardian); ok {
				rep := g.GetIPReputation()
				if rep != nil {
					threats = rep.AllThreats()
				}
			}
			break
		}
	}

	if threats == nil {
		threats = []network.IPThreatInfo{}
	}

	blocked := 0
	for _, t := range threats {
		if t.Blocked {
			blocked++
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"threats":       threats,
		"total":         len(threats),
		"blocked_count": blocked,
	})
}

func (s *Server) handleRustStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	status := map[string]interface{}{
		"enabled": s.engine.Config.RustEngine.Enabled,
	}

	if !s.engine.Config.RustEngine.Enabled {
		status["status"] = "disabled"
	} else if s.engine.RustSidecar != nil && s.engine.RustSidecar.Running() {
		status["status"] = "running"
		status["binary"] = s.engine.Config.RustEngine.Binary
		status["workers"] = s.engine.Config.RustEngine.Workers
		status["buffer_size"] = s.engine.Config.RustEngine.BufferSize
		status["aho_corasick"] = s.engine.Config.RustEngine.AhoCorasickPrefilter
		status["capture_enabled"] = s.engine.Config.RustEngine.Capture.Enabled
		if s.engine.Config.RustEngine.Capture.Enabled {
			status["capture_interface"] = s.engine.Config.RustEngine.Capture.Interface
		}
	} else {
		status["status"] = "stopped"
	}

	writeJSON(w, http.StatusOK, status)
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

// authMiddleware enforces API key authentication on all endpoints except /health.
// Keys are read from config (server.api_keys) or env (ONESEC_API_KEY).
// If no keys are configured, all requests are allowed (open mode with warning logged on startup).
func authMiddleware(next http.Handler, cfg *core.Config, logger zerolog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Always allow health checks without auth
		if r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}

		// If no API keys configured, allow all (open mode)
		if !cfg.AuthEnabled() {
			next.ServeHTTP(w, r)
			return
		}

		// Extract key from Authorization header: "Bearer <key>"
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			// Also check X-API-Key header as fallback
			authHeader = r.Header.Get("X-API-Key")
			if authHeader == "" {
				writeJSON(w, http.StatusUnauthorized, map[string]string{
					"error": "missing authentication — provide Authorization: Bearer <key> or X-API-Key header",
				})
				return
			}
			// X-API-Key is the raw key
			if !cfg.ValidateAPIKey(authHeader) {
				logger.Warn().Str("path", r.URL.Path).Str("ip", r.RemoteAddr).Msg("invalid API key")
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "invalid API key"})
				return
			}
			next.ServeHTTP(w, r)
			return
		}

		// Parse "Bearer <key>"
		key := authHeader
		if strings.HasPrefix(authHeader, "Bearer ") {
			key = authHeader[7:]
		}

		if !cfg.ValidateAPIKey(key) {
			logger.Warn().Str("path", r.URL.Path).Str("ip", r.RemoteAddr).Msg("invalid API key")
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "invalid API key"})
			return
		}

		next.ServeHTTP(w, r)
	})
}

// rateLimitMiddleware implements a simple per-IP token bucket rate limiter.
type ipLimiter struct {
	mu      sync.Mutex
	buckets map[string]*tokenBucket
	rate    int
}

type tokenBucket struct {
	tokens    float64
	maxTokens float64
	lastTime  time.Time
}

func (b *tokenBucket) allow(rate float64) bool {
	now := time.Now()
	elapsed := now.Sub(b.lastTime).Seconds()
	b.lastTime = now
	b.tokens += elapsed * rate
	if b.tokens > b.maxTokens {
		b.tokens = b.maxTokens
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func rateLimitMiddleware(next http.Handler, requestsPerSecond int) http.Handler {
	limiter := &ipLimiter{
		buckets: make(map[string]*tokenBucket),
		rate:    requestsPerSecond,
	}

	// Cleanup stale buckets every 5 minutes
	go func() {
		for {
			time.Sleep(5 * time.Minute)
			limiter.mu.Lock()
			cutoff := time.Now().Add(-10 * time.Minute)
			for ip, bucket := range limiter.buckets {
				if bucket.lastTime.Before(cutoff) {
					delete(limiter.buckets, ip)
				}
			}
			limiter.mu.Unlock()
		}
	}()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip rate limiting for health checks
		if r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}

		ip := r.RemoteAddr
		if idx := strings.LastIndex(ip, ":"); idx != -1 {
			ip = ip[:idx]
		}

		limiter.mu.Lock()
		bucket, exists := limiter.buckets[ip]
		if !exists {
			bucket = &tokenBucket{
				tokens:    float64(requestsPerSecond),
				maxTokens: float64(requestsPerSecond * 2), // burst = 2x rate
				lastTime:  time.Now(),
			}
			limiter.buckets[ip] = bucket
		}
		allowed := bucket.allow(float64(requestsPerSecond))
		limiter.mu.Unlock()

		if !allowed {
			w.Header().Set("Retry-After", "1")
			writeJSON(w, http.StatusTooManyRequests, map[string]string{
				"error": "rate limit exceeded — try again shortly",
			})
			return
		}

		next.ServeHTTP(w, r)
	})
}

func corsMiddleware(next http.Handler, allowedOrigins []string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		allowed := "*"
		if len(allowedOrigins) > 0 {
			allowed = ""
			for _, o := range allowedOrigins {
				if o == "*" || o == origin {
					allowed = origin
					break
				}
			}
			if allowed == "" {
				// Origin not in allow list — skip CORS headers
				next.ServeHTTP(w, r)
				return
			}
		}
		w.Header().Set("Access-Control-Allow-Origin", allowed)
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")
		if len(allowedOrigins) > 0 && allowedOrigins[0] != "*" {
			w.Header().Set("Vary", "Origin")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func loggingMiddleware(next http.Handler, logger zerolog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		logger.Debug().
			Str("method", r.Method).
			Str("path", r.URL.Path).
			Dur("duration", time.Since(start)).
			Msg("request")
	})
}
