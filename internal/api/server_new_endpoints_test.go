package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/1sec-project/1sec/internal/core"
	"github.com/rs/zerolog"
)

// ─── Status endpoint — uptime field ──────────────────────────────────────────

func TestHandleStatus_ContainsUptimeSecs(t *testing.T) {
	engine := testEngine()
	engine.SetStartTimeForTest(time.Now().Add(-10 * time.Second))

	s := newTestServer(engine)
	req := authedReq(httptest.NewRequest(http.MethodGet, "/api/v1/status", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var body map[string]interface{}
	json.NewDecoder(w.Body).Decode(&body)

	uptime, ok := body["uptime_secs"].(float64)
	if !ok {
		t.Fatal("expected uptime_secs in status response")
	}
	if uptime < 5 {
		t.Errorf("expected uptime >= 5s, got %v", uptime)
	}
}

func TestHandleStatus_ContainsCloudField(t *testing.T) {
	engine := testEngine()
	s := newTestServer(engine)
	req := authedReq(httptest.NewRequest(http.MethodGet, "/api/v1/status", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	var body map[string]interface{}
	json.NewDecoder(w.Body).Decode(&body)

	cloud, ok := body["cloud"].(string)
	if !ok {
		t.Fatal("expected cloud field in status response")
	}
	if cloud != "disabled" {
		t.Errorf("expected cloud=disabled, got %q", cloud)
	}
}

func TestHandleStatus_ContainsEnforcementField(t *testing.T) {
	engine := testEngine()
	s := newTestServer(engine)
	req := authedReq(httptest.NewRequest(http.MethodGet, "/api/v1/status", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	var body map[string]interface{}
	json.NewDecoder(w.Body).Decode(&body)

	enforcement, ok := body["enforcement"].(map[string]interface{})
	if !ok {
		t.Fatal("expected enforcement map in status response")
	}
	if enforcement["enabled"] != false {
		t.Errorf("expected enforcement.enabled=false, got %v", enforcement["enabled"])
	}
}

// ─── Escalation status endpoint ──────────────────────────────────────────────

func TestHandleEscalationStatus_NilEscalation(t *testing.T) {
	engine := testEngine()
	// engine.Escalation is nil by default in test helper
	s := newTestServer(engine)
	req := authedReq(httptest.NewRequest(http.MethodGet, "/api/v1/escalation/status", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var body map[string]interface{}
	json.NewDecoder(w.Body).Decode(&body)
	if body["enabled"] != false {
		t.Errorf("expected enabled=false when escalation is nil, got %v", body["enabled"])
	}
}

func TestHandleEscalationStatus_WithEscalation(t *testing.T) {
	engine := testEngine()
	logger := zerolog.Nop()
	cfg := core.DefaultEscalationConfig()
	cfg.Enabled = true
	engine.Escalation = core.NewEscalationManager(logger, cfg, engine.Pipeline)
	defer engine.Escalation.Stop()

	s := newTestServer(engine)
	req := authedReq(httptest.NewRequest(http.MethodGet, "/api/v1/escalation/status", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var body map[string]interface{}
	json.NewDecoder(w.Body).Decode(&body)
	if body["enabled"] != true {
		t.Errorf("expected enabled=true, got %v", body["enabled"])
	}
	if body["tracked_alerts"] == nil {
		t.Error("expected tracked_alerts field")
	}
}

func TestHandleEscalationStatus_WithTrackedAlert(t *testing.T) {
	engine := testEngine()
	logger := zerolog.Nop()
	cfg := core.EscalationConfig{
		Enabled: true,
		Timeouts: map[string]core.EscalationTimer{
			"HIGH": {Timeout: 10 * time.Minute, EscalateTo: "CRITICAL", MaxEscalations: 1},
		},
	}
	engine.Escalation = core.NewEscalationManager(logger, cfg, engine.Pipeline)
	defer engine.Escalation.Stop()

	// Track an alert
	ev := core.NewSecurityEvent("test", "test_type", core.SeverityHigh, "test")
	alert := core.NewAlert(ev, "Test Alert", "desc")
	engine.Pipeline.Process(alert)
	engine.Escalation.Track(alert)

	s := newTestServer(engine)
	req := authedReq(httptest.NewRequest(http.MethodGet, "/api/v1/escalation/status", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	var body map[string]interface{}
	json.NewDecoder(w.Body).Decode(&body)

	tracked := body["tracked_alerts"].(float64)
	if tracked != 1 {
		t.Errorf("expected 1 tracked alert, got %v", tracked)
	}

	alerts, ok := body["alerts"].([]interface{})
	if !ok || len(alerts) != 1 {
		t.Fatalf("expected 1 alert in list, got %v", alerts)
	}
	a := alerts[0].(map[string]interface{})
	if a["module"] != "test" {
		t.Errorf("expected module=test, got %v", a["module"])
	}
	if a["severity"] != "HIGH" {
		t.Errorf("expected severity=HIGH, got %v", a["severity"])
	}
}

func TestHandleEscalationStatus_MethodNotAllowed(t *testing.T) {
	s := newTestServer(testEngine())
	req := authedReq(httptest.NewRequest(http.MethodPost, "/api/v1/escalation/status", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

// ─── Metrics endpoint ────────────────────────────────────────────────────────

func TestHandleMetrics_MethodNotAllowed(t *testing.T) {
	s := newTestServer(testEngine())
	req := authedReq(httptest.NewRequest(http.MethodPost, "/api/v1/metrics", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

// ─── Correlator endpoint ─────────────────────────────────────────────────────

func TestHandleCorrelator_NilCorrelator(t *testing.T) {
	engine := testEngine()
	// engine.Correlator is nil by default
	s := newTestServer(engine)
	req := authedReq(httptest.NewRequest(http.MethodGet, "/api/v1/correlator", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var body map[string]interface{}
	json.NewDecoder(w.Body).Decode(&body)
	if body["status"] != "not_started" {
		t.Errorf("expected status=not_started, got %v", body["status"])
	}
}

func TestHandleCorrelator_WithCorrelator(t *testing.T) {
	engine := testEngine()
	logger := zerolog.Nop()
	engine.Correlator = core.NewThreatCorrelator(logger, engine.Pipeline, nil)

	s := newTestServer(engine)
	req := authedReq(httptest.NewRequest(http.MethodGet, "/api/v1/correlator", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var body map[string]interface{}
	json.NewDecoder(w.Body).Decode(&body)
	if body["active_sources"] == nil {
		t.Error("expected active_sources field")
	}
	if body["chain_count"] == nil {
		t.Error("expected chain_count field")
	}
	chains := body["chain_count"].(float64)
	if chains == 0 {
		t.Error("expected non-zero chain_count (built-in chain definitions)")
	}
}

func TestHandleCorrelator_MethodNotAllowed(t *testing.T) {
	s := newTestServer(testEngine())
	req := authedReq(httptest.NewRequest(http.MethodPost, "/api/v1/correlator", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

// ─── Archive status endpoint ─────────────────────────────────────────────────

func TestHandleArchiveStatus_NilArchiver(t *testing.T) {
	engine := testEngine()
	s := newTestServer(engine)
	req := authedReq(httptest.NewRequest(http.MethodGet, "/api/v1/archive/status", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var body map[string]interface{}
	json.NewDecoder(w.Body).Decode(&body)
	if body["enabled"] != false {
		t.Errorf("expected enabled=false when archiver is nil, got %v", body["enabled"])
	}
}

func TestHandleArchiveStatus_MethodNotAllowed(t *testing.T) {
	s := newTestServer(testEngine())
	req := authedReq(httptest.NewRequest(http.MethodPost, "/api/v1/archive/status", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

// ─── Rust status endpoint ────────────────────────────────────────────────────

func TestHandleRustStatus_Disabled(t *testing.T) {
	engine := testEngine()
	s := newTestServer(engine)
	req := authedReq(httptest.NewRequest(http.MethodGet, "/api/v1/rust", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var body map[string]interface{}
	json.NewDecoder(w.Body).Decode(&body)
	if body["enabled"] != false {
		t.Errorf("expected enabled=false, got %v", body["enabled"])
	}
	if body["status"] != "disabled" {
		t.Errorf("expected status=disabled, got %v", body["status"])
	}
}

func TestHandleRustStatus_MethodNotAllowed(t *testing.T) {
	s := newTestServer(testEngine())
	req := authedReq(httptest.NewRequest(http.MethodPost, "/api/v1/rust", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

// ─── Event schemas endpoint ──────────────────────────────────────────────────

func TestHandleEventSchemas_GET(t *testing.T) {
	s := newTestServer(testEngine())
	req := authedReq(httptest.NewRequest(http.MethodGet, "/api/v1/event-schemas", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var body map[string]interface{}
	json.NewDecoder(w.Body).Decode(&body)
	if body["schemas"] == nil {
		t.Error("expected schemas field")
	}
	total := body["total"].(float64)
	if total == 0 {
		t.Error("expected non-zero schema count")
	}
}

func TestHandleEventSchemas_WithCategoryFilter(t *testing.T) {
	s := newTestServer(testEngine())
	req := authedReq(httptest.NewRequest(http.MethodGet, "/api/v1/event-schemas?category=auth", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var body map[string]interface{}
	json.NewDecoder(w.Body).Decode(&body)
	schemas, ok := body["schemas"].([]interface{})
	if !ok {
		t.Fatal("expected schemas array")
	}
	// All returned schemas should be in the auth category
	for _, s := range schemas {
		schema := s.(map[string]interface{})
		if schema["category"] != "auth" {
			t.Errorf("expected category=auth, got %v", schema["category"])
		}
	}
}

func TestHandleEventSchemas_MethodNotAllowed(t *testing.T) {
	s := newTestServer(testEngine())
	req := authedReq(httptest.NewRequest(http.MethodPost, "/api/v1/event-schemas", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

// ─── Threats endpoint ────────────────────────────────────────────────────────

func TestHandleThreats_NoNetworkGuardian(t *testing.T) {
	engine := testEngine()
	s := newTestServer(engine)
	req := authedReq(httptest.NewRequest(http.MethodGet, "/api/v1/threats", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var body map[string]interface{}
	json.NewDecoder(w.Body).Decode(&body)
	total := body["total"].(float64)
	if total != 0 {
		t.Errorf("expected 0 threats without network_guardian, got %v", total)
	}
}

func TestHandleThreats_MethodNotAllowed(t *testing.T) {
	s := newTestServer(testEngine())
	req := authedReq(httptest.NewRequest(http.MethodPost, "/api/v1/threats", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

// ─── Metrics endpoint — GET response structure ───────────────────────────────

func TestHandleMetrics_GET_ResponseStructure(t *testing.T) {
	engine := testEngine()
	s := newTestServer(engine)
	req := authedReq(httptest.NewRequest(http.MethodGet, "/api/v1/metrics", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var body map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Bus metrics should be present (empty map since no bus is wired)
	if body["bus"] == nil {
		t.Error("expected bus field in metrics response")
	}

	// Routing metrics should be present
	routing, ok := body["routing"].(map[string]interface{})
	if !ok {
		t.Fatal("expected routing map in metrics response")
	}
	// Registry always returns these keys
	if routing["events_routed"] == nil {
		t.Error("expected events_routed in routing metrics")
	}
	if routing["events_dropped"] == nil {
		t.Error("expected events_dropped in routing metrics")
	}
}

// ─── Status endpoint — nil Bus safety ────────────────────────────────────────

func TestHandleStatus_NilBus(t *testing.T) {
	engine := testEngine()
	// engine.Bus is nil by default in test helper
	s := newTestServer(engine)
	req := authedReq(httptest.NewRequest(http.MethodGet, "/api/v1/status", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var body map[string]interface{}
	json.NewDecoder(w.Body).Decode(&body)

	// bus_connected should be false, not panic
	if body["bus_connected"] != false {
		t.Errorf("expected bus_connected=false with nil bus, got %v", body["bus_connected"])
	}
}

func TestHandleStatus_MethodNotAllowed(t *testing.T) {
	s := newTestServer(testEngine())
	req := authedReq(httptest.NewRequest(http.MethodPost, "/api/v1/status", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

// ─── Health endpoint — nil Bus safety ────────────────────────────────────────

func TestHandleHealth_NilBus(t *testing.T) {
	engine := testEngine()
	s := newTestServer(engine)
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	// Should not panic; bus_connected should be false
	if w.Code != http.StatusOK && w.Code != http.StatusServiceUnavailable {
		t.Fatalf("unexpected status = %d", w.Code)
	}

	var body map[string]interface{}
	json.NewDecoder(w.Body).Decode(&body)
	if body["bus_connected"] != false {
		t.Errorf("expected bus_connected=false with nil bus, got %v", body["bus_connected"])
	}
}

// ─── Metrics endpoint — nil Bus safety ───────────────────────────────────────

func TestHandleMetrics_NilBus(t *testing.T) {
	engine := testEngine()
	// engine.Bus is nil
	s := newTestServer(engine)
	req := authedReq(httptest.NewRequest(http.MethodGet, "/api/v1/metrics", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var body map[string]interface{}
	json.NewDecoder(w.Body).Decode(&body)

	// Bus should return empty map, not nil/panic
	bus, ok := body["bus"].(map[string]interface{})
	if !ok {
		t.Fatal("expected bus to be a map (even if empty)")
	}
	_ = bus // just checking it doesn't panic
}

// ─── Escalation — disabled config returns disabled ───────────────────────────

func TestHandleEscalationStatus_DisabledConfig(t *testing.T) {
	engine := testEngine()
	logger := zerolog.Nop()
	cfg := core.DefaultEscalationConfig() // Enabled: false
	engine.Escalation = core.NewEscalationManager(logger, cfg, engine.Pipeline)
	defer engine.Escalation.Stop()

	s := newTestServer(engine)
	req := authedReq(httptest.NewRequest(http.MethodGet, "/api/v1/escalation/status", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var body map[string]interface{}
	json.NewDecoder(w.Body).Decode(&body)

	// EscalationManager exists but config says disabled
	if body["enabled"] != false {
		t.Errorf("expected enabled=false for disabled config, got %v", body["enabled"])
	}
	// tracked_alerts should be 0
	tracked, ok := body["tracked_alerts"].(float64)
	if !ok {
		t.Fatal("expected tracked_alerts field")
	}
	if tracked != 0 {
		t.Errorf("expected 0 tracked alerts, got %v", tracked)
	}
}

// ─── Status — modules list ───────────────────────────────────────────────────

func TestHandleStatus_ModulesList(t *testing.T) {
	engine := testEngine()
	s := newTestServer(engine)
	req := authedReq(httptest.NewRequest(http.MethodGet, "/api/v1/status", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	var body map[string]interface{}
	json.NewDecoder(w.Body).Decode(&body)

	modules, ok := body["modules"].([]interface{})
	if !ok {
		t.Fatal("expected modules array in status response")
	}
	// testEngine has no modules registered, so list should be empty
	if len(modules) != 0 {
		t.Errorf("expected 0 modules in test engine, got %d", len(modules))
	}

	// modules_total should match
	total, ok := body["modules_total"].(float64)
	if !ok {
		t.Fatal("expected modules_total field")
	}
	if int(total) != 0 {
		t.Errorf("expected modules_total=0, got %v", total)
	}
}

// ─── Status — rust engine field ──────────────────────────────────────────────

func TestHandleStatus_RustEngineDisabled(t *testing.T) {
	engine := testEngine()
	s := newTestServer(engine)
	req := authedReq(httptest.NewRequest(http.MethodGet, "/api/v1/status", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	var body map[string]interface{}
	json.NewDecoder(w.Body).Decode(&body)

	if body["rust_engine"] != "disabled" {
		t.Errorf("expected rust_engine=disabled, got %v", body["rust_engine"])
	}
}

// ─── Enforce config endpoint ─────────────────────────────────────────────────

func TestHandleEnforceConfig_GET_NoEnforcement(t *testing.T) {
	engine := testEngine()
	s := newTestServer(engine)
	req := authedReq(httptest.NewRequest(http.MethodGet, "/api/v1/enforce/config", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var body map[string]interface{}
	json.NewDecoder(w.Body).Decode(&body)
	if body["enabled"] != false {
		t.Errorf("expected enabled=false, got %v", body["enabled"])
	}
}

func TestHandleEnforceConfig_GET_WithEnforcement(t *testing.T) {
	engine := testEngine()
	engine.Config.Enforcement = &core.EnforcementConfig{
		Enabled: true,
		DryRun:  true,
		Preset:  "balanced",
		ApprovalGate: core.ApprovalGateConfig{
			Enabled:          true,
			RequireApproval:  []string{"kill_process", "quarantine_file"},
			AutoApproveAbove: "CRITICAL",
		},
	}
	logger := zerolog.Nop()
	engine.ResponseEngine = core.NewResponseEngine(logger, nil, engine.Pipeline, engine.Config)

	s := newTestServer(engine)
	req := authedReq(httptest.NewRequest(http.MethodGet, "/api/v1/enforce/config", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var body map[string]interface{}
	json.NewDecoder(w.Body).Decode(&body)

	if body["enabled"] != true {
		t.Errorf("expected enabled=true, got %v", body["enabled"])
	}
	if body["dry_run"] != true {
		t.Errorf("expected dry_run=true, got %v", body["dry_run"])
	}
	if body["preset"] != "balanced" {
		t.Errorf("expected preset=balanced, got %v", body["preset"])
	}

	ag, ok := body["approval_gate"].(map[string]interface{})
	if !ok {
		t.Fatal("expected approval_gate map")
	}
	if ag["enabled"] != true {
		t.Errorf("expected approval_gate.enabled=true, got %v", ag["enabled"])
	}
	if ag["auto_approve_above"] != "CRITICAL" {
		t.Errorf("expected auto_approve_above=CRITICAL, got %v", ag["auto_approve_above"])
	}

	// Should include valid_presets and valid_actions
	if body["valid_presets"] == nil {
		t.Error("expected valid_presets field")
	}
	if body["valid_actions"] == nil {
		t.Error("expected valid_actions field")
	}
}

func TestHandleEnforceConfig_POST_SetDryRun(t *testing.T) {
	engine := testEngine()
	engine.Config.Enforcement = &core.EnforcementConfig{
		Enabled: true,
		DryRun:  false,
	}

	s := newTestServer(engine)
	payload := `{"dry_run": true}`
	req := authedReq(httptest.NewRequest(http.MethodPost, "/api/v1/enforce/config", strings.NewReader(payload)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var body map[string]interface{}
	json.NewDecoder(w.Body).Decode(&body)
	if body["status"] != "updated" {
		t.Errorf("expected status=updated, got %v", body["status"])
	}

	// Verify the config was actually changed
	if !engine.Config.Enforcement.GetDryRun() {
		t.Error("expected dry_run to be true after POST")
	}
}

func TestHandleEnforceConfig_POST_SetAutoApproveAbove(t *testing.T) {
	engine := testEngine()
	engine.Config.Enforcement = &core.EnforcementConfig{
		Enabled: true,
		ApprovalGate: core.ApprovalGateConfig{
			Enabled:          true,
			RequireApproval:  []string{"kill_process"},
			AutoApproveAbove: "",
		},
	}

	s := newTestServer(engine)
	payload := `{"auto_approve_above": "HIGH"}`
	req := authedReq(httptest.NewRequest(http.MethodPost, "/api/v1/enforce/config", strings.NewReader(payload)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	if engine.Config.Enforcement.ApprovalGate.AutoApproveAbove != "HIGH" {
		t.Errorf("expected auto_approve_above=HIGH, got %q", engine.Config.Enforcement.ApprovalGate.AutoApproveAbove)
	}
}

func TestHandleEnforceConfig_POST_InvalidAutoApproveAbove(t *testing.T) {
	engine := testEngine()
	engine.Config.Enforcement = &core.EnforcementConfig{Enabled: true}

	s := newTestServer(engine)
	payload := `{"auto_approve_above": "BOGUS"}`
	req := authedReq(httptest.NewRequest(http.MethodPost, "/api/v1/enforce/config", strings.NewReader(payload)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestHandleEnforceConfig_POST_UpdateRequireApproval(t *testing.T) {
	engine := testEngine()
	engine.Config.Enforcement = &core.EnforcementConfig{
		Enabled: true,
		ApprovalGate: core.ApprovalGateConfig{
			Enabled:         true,
			RequireApproval: []string{"kill_process"},
		},
	}

	s := newTestServer(engine)
	payload := `{"require_approval": ["kill_process", "disable_user", "quarantine_file"]}`
	req := authedReq(httptest.NewRequest(http.MethodPost, "/api/v1/enforce/config", strings.NewReader(payload)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	if len(engine.Config.Enforcement.ApprovalGate.RequireApproval) != 3 {
		t.Errorf("expected 3 require_approval entries, got %d", len(engine.Config.Enforcement.ApprovalGate.RequireApproval))
	}
}

func TestHandleEnforceConfig_POST_InvalidAction(t *testing.T) {
	engine := testEngine()
	engine.Config.Enforcement = &core.EnforcementConfig{
		Enabled: true,
		ApprovalGate: core.ApprovalGateConfig{Enabled: true},
	}

	s := newTestServer(engine)
	payload := `{"require_approval": ["kill_process", "nuke_from_orbit"]}`
	req := authedReq(httptest.NewRequest(http.MethodPost, "/api/v1/enforce/config", strings.NewReader(payload)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestHandleEnforceConfig_MethodNotAllowed(t *testing.T) {
	s := newTestServer(testEngine())
	req := authedReq(httptest.NewRequest(http.MethodDelete, "/api/v1/enforce/config", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

func TestHandleEnforceConfig_POST_NoEnforcement(t *testing.T) {
	engine := testEngine()
	// No enforcement configured
	s := newTestServer(engine)
	payload := `{"dry_run": true}`
	req := authedReq(httptest.NewRequest(http.MethodPost, "/api/v1/enforce/config", strings.NewReader(payload)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}
