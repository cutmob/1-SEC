package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/1sec-project/1sec/internal/core"
	"github.com/rs/zerolog"
)

// ─── Helpers ─────────────────────────────────────────────────────────────────

func testEngineWithEnforcement(preset string, dryRun bool) *core.Engine {
	cfg := core.DefaultConfig()
	cfg.RustEngine.Enabled = false
	cfg.Enforcement = &core.EnforcementConfig{
		Enabled: true,
		DryRun:  dryRun,
		Preset:  preset,
	}
	logger := zerolog.Nop()
	pipeline := core.NewAlertPipeline(logger, 1000)

	engine := &core.Engine{
		Config:         cfg,
		Registry:       core.NewModuleRegistry(logger),
		Pipeline:       pipeline,
		Logger:         logger,
		ResponseEngine: core.NewResponseEngine(logger, nil, pipeline, cfg),
	}
	return engine
}

func testEngineNoEnforcement() *core.Engine {
	cfg := core.DefaultConfig()
	cfg.RustEngine.Enabled = false
	logger := zerolog.Nop()
	return &core.Engine{
		Config:   cfg,
		Registry: core.NewModuleRegistry(logger),
		Pipeline: core.NewAlertPipeline(logger, 1000),
		Logger:   logger,
	}
}

// ─── Enforce Status ──────────────────────────────────────────────────────────

func TestHandleEnforceStatus_WithEnforcement(t *testing.T) {
	s := newTestServer(testEngineWithEnforcement("balanced", true))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/enforce/status", nil)
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var body map[string]interface{}
	json.NewDecoder(w.Body).Decode(&body)

	if body["enabled"] != true {
		t.Errorf("expected enabled=true, got %v", body["enabled"])
	}
	if body["dry_run"] != true {
		t.Errorf("expected dry_run=true, got %v", body["dry_run"])
	}
	if body["stats"] == nil {
		t.Error("expected stats in response")
	}
}

func TestHandleEnforceStatus_NoEnforcement(t *testing.T) {
	s := newTestServer(testEngineNoEnforcement())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/enforce/status", nil)
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var body map[string]interface{}
	json.NewDecoder(w.Body).Decode(&body)
	if body["enabled"] != false {
		t.Errorf("expected enabled=false when no enforcement, got %v", body["enabled"])
	}
}

func TestHandleEnforceStatus_MethodNotAllowed(t *testing.T) {
	s := newTestServer(testEngineWithEnforcement("balanced", true))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/enforce/status", nil)
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

// ─── Enforce Policies ────────────────────────────────────────────────────────

func TestHandleEnforcePolicies_WithEnforcement(t *testing.T) {
	s := newTestServer(testEngineWithEnforcement("balanced", true))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/enforce/policies", nil)
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var body map[string]interface{}
	json.NewDecoder(w.Body).Decode(&body)
	policies, ok := body["policies"].(map[string]interface{})
	if !ok {
		t.Fatal("expected policies map in response")
	}
	if len(policies) == 0 {
		t.Error("expected non-empty policies from balanced preset")
	}
}

func TestHandleEnforcePolicies_NoEnforcement(t *testing.T) {
	s := newTestServer(testEngineNoEnforcement())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/enforce/policies", nil)
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var body map[string]interface{}
	json.NewDecoder(w.Body).Decode(&body)
	policies, _ := body["policies"].(map[string]interface{})
	if len(policies) != 0 {
		t.Errorf("expected empty policies when no enforcement, got %d", len(policies))
	}
}

// ─── Enforce History ─────────────────────────────────────────────────────────

func TestHandleEnforceHistory_Empty(t *testing.T) {
	s := newTestServer(testEngineWithEnforcement("balanced", true))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/enforce/history", nil)
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var body map[string]interface{}
	json.NewDecoder(w.Body).Decode(&body)
	records, _ := body["records"].([]interface{})
	if len(records) != 0 {
		t.Errorf("expected empty history, got %d records", len(records))
	}
}

func TestHandleEnforceHistory_NoEnforcement(t *testing.T) {
	s := newTestServer(testEngineNoEnforcement())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/enforce/history", nil)
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestHandleEnforceHistory_WithLimitParam(t *testing.T) {
	s := newTestServer(testEngineWithEnforcement("balanced", true))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/enforce/history?limit=5", nil)
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestHandleEnforceHistory_WithModuleFilter(t *testing.T) {
	s := newTestServer(testEngineWithEnforcement("balanced", true))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/enforce/history?module=injection_shield", nil)
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

// ─── Enforce Dry-Run Toggle ──────────────────────────────────────────────────

func TestHandleEnforceDryRun_On(t *testing.T) {
	s := newTestServer(testEngineWithEnforcement("balanced", false))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/enforce/dry-run/on", nil)
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var body map[string]interface{}
	json.NewDecoder(w.Body).Decode(&body)
	if body["dry_run"] != true {
		t.Errorf("expected dry_run=true after toggling on, got %v", body["dry_run"])
	}
}

func TestHandleEnforceDryRun_Off(t *testing.T) {
	s := newTestServer(testEngineWithEnforcement("balanced", true))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/enforce/dry-run/off", nil)
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var body map[string]interface{}
	json.NewDecoder(w.Body).Decode(&body)
	if body["dry_run"] != false {
		t.Errorf("expected dry_run=false after toggling off, got %v", body["dry_run"])
	}
}

func TestHandleEnforceDryRun_InvalidMode(t *testing.T) {
	s := newTestServer(testEngineWithEnforcement("balanced", true))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/enforce/dry-run/maybe", nil)
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestHandleEnforceDryRun_NoEnforcement(t *testing.T) {
	s := newTestServer(testEngineNoEnforcement())
	req := httptest.NewRequest(http.MethodPost, "/api/v1/enforce/dry-run/on", nil)
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestHandleEnforceDryRun_MethodNotAllowed(t *testing.T) {
	s := newTestServer(testEngineWithEnforcement("balanced", true))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/enforce/dry-run/on", nil)
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

// ─── Enforce Policy Enable/Disable ───────────────────────────────────────────

func TestHandleEnforcePolicyAction_Enable(t *testing.T) {
	s := newTestServer(testEngineWithEnforcement("balanced", true))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/enforce/policies/injection_shield/enable", nil)
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var body map[string]interface{}
	json.NewDecoder(w.Body).Decode(&body)
	if body["enabled"] != true {
		t.Errorf("expected enabled=true, got %v", body["enabled"])
	}
}

func TestHandleEnforcePolicyAction_Disable(t *testing.T) {
	s := newTestServer(testEngineWithEnforcement("balanced", true))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/enforce/policies/injection_shield/disable", nil)
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var body map[string]interface{}
	json.NewDecoder(w.Body).Decode(&body)
	if body["enabled"] != false {
		t.Errorf("expected enabled=false, got %v", body["enabled"])
	}
}

func TestHandleEnforcePolicyAction_NotFound(t *testing.T) {
	s := newTestServer(testEngineWithEnforcement("balanced", true))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/enforce/policies/nonexistent_module/enable", nil)
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestHandleEnforcePolicyAction_InvalidAction(t *testing.T) {
	s := newTestServer(testEngineWithEnforcement("balanced", true))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/enforce/policies/injection_shield/restart", nil)
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestHandleEnforcePolicyAction_NoEnforcement(t *testing.T) {
	s := newTestServer(testEngineNoEnforcement())
	req := httptest.NewRequest(http.MethodPost, "/api/v1/enforce/policies/injection_shield/enable", nil)
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestHandleEnforcePolicyAction_MethodNotAllowed(t *testing.T) {
	s := newTestServer(testEngineWithEnforcement("balanced", true))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/enforce/policies/injection_shield/enable", nil)
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

// ─── Enforce Test ────────────────────────────────────────────────────────────

func TestHandleEnforceTest_KnownModule(t *testing.T) {
	s := newTestServer(testEngineWithEnforcement("balanced", true))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/enforce/test/injection_shield?severity=HIGH", nil)
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var body map[string]interface{}
	json.NewDecoder(w.Body).Decode(&body)

	if body["module"] != "injection_shield" {
		t.Errorf("expected module=injection_shield, got %v", body["module"])
	}
	actions, _ := body["actions"].([]interface{})
	if len(actions) == 0 {
		t.Error("expected at least one matching action for HIGH severity on injection_shield")
	}
}

func TestHandleEnforceTest_CriticalSeverity(t *testing.T) {
	s := newTestServer(testEngineWithEnforcement("balanced", true))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/enforce/test/ransomware?severity=CRITICAL", nil)
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var body map[string]interface{}
	json.NewDecoder(w.Body).Decode(&body)
	actions, _ := body["actions"].([]interface{})
	// Balanced ransomware has 3 actions, all at HIGH — CRITICAL should match all
	if len(actions) < 2 {
		t.Errorf("expected multiple matching actions for CRITICAL ransomware, got %d", len(actions))
	}
}

func TestHandleEnforceTest_LowSeverity_NoMatch(t *testing.T) {
	s := newTestServer(testEngineWithEnforcement("balanced", true))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/enforce/test/injection_shield?severity=LOW", nil)
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var body map[string]interface{}
	json.NewDecoder(w.Body).Decode(&body)
	actions, _ := body["actions"].([]interface{})
	// Balanced injection_shield has min_severity HIGH — LOW should not match
	if len(actions) != 0 {
		t.Errorf("expected no matching actions for LOW severity, got %d", len(actions))
	}
}

func TestHandleEnforceTest_UnknownModule_FallsBackToWildcard(t *testing.T) {
	s := newTestServer(testEngineWithEnforcement("balanced", true))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/enforce/test/unknown_module?severity=CRITICAL", nil)
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var body map[string]interface{}
	json.NewDecoder(w.Body).Decode(&body)
	// Should fall back to wildcard policy
	actions, _ := body["actions"].([]interface{})
	if len(actions) == 0 {
		t.Error("expected wildcard policy to match for unknown module with CRITICAL severity")
	}
}

func TestHandleEnforceTest_NoEnforcement(t *testing.T) {
	s := newTestServer(testEngineNoEnforcement())
	req := httptest.NewRequest(http.MethodPost, "/api/v1/enforce/test/injection_shield?severity=HIGH", nil)
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestHandleEnforceTest_MethodNotAllowed(t *testing.T) {
	s := newTestServer(testEngineWithEnforcement("balanced", true))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/enforce/test/injection_shield", nil)
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}
