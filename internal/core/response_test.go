package core

import (
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

// ─── Helpers ────────────────────────────────────────────────────────────────

func testResponseEngine(t *testing.T, cfg *Config) *ResponseEngine {
	t.Helper()
	logger := zerolog.Nop()
	pipeline := NewAlertPipeline(logger, 1000)
	return NewResponseEngine(logger, nil, pipeline, cfg)
}

func enforcementConfig(preset string, dryRun bool) *Config {
	cfg := DefaultConfig()
	cfg.Enforcement = &EnforcementConfig{
		Enabled: true,
		DryRun:  dryRun,
		Preset:  preset,
	}
	return cfg
}

func testAlertWithIP(module, ip string, severity Severity) *Alert {
	event := NewSecurityEvent(module, "test_type", severity, "test summary")
	event.SourceIP = ip
	return NewAlert(event, "Test Alert", "Test description")
}

// ─── NewResponseEngine ──────────────────────────────────────────────────────

func TestNewResponseEngine_LoadsPresetPolicies(t *testing.T) {
	re := testResponseEngine(t, enforcementConfig("balanced", true))

	policies := re.GetPolicies()
	if len(policies) == 0 {
		t.Fatal("expected policies to be loaded from balanced preset")
	}

	// Balanced preset should have all 16 modules + wildcard + ai_analysis_engine = 18
	if len(policies) < 17 {
		t.Errorf("expected at least 17 policies from balanced preset, got %d", len(policies))
	}

	// Verify a specific module exists
	if _, ok := policies["injection_shield"]; !ok {
		t.Error("expected injection_shield policy in balanced preset")
	}
	if _, ok := policies["*"]; !ok {
		t.Error("expected wildcard policy in balanced preset")
	}
}

func TestNewResponseEngine_DisabledEnforcement(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enforcement = &EnforcementConfig{Enabled: false, Preset: "balanced"}
	re := testResponseEngine(t, cfg)

	policies := re.GetPolicies()
	if len(policies) != 0 {
		t.Errorf("disabled enforcement should load no policies, got %d", len(policies))
	}
}

func TestNewResponseEngine_NilEnforcement(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enforcement = nil
	re := testResponseEngine(t, cfg)

	policies := re.GetPolicies()
	if len(policies) != 0 {
		t.Errorf("nil enforcement should load no policies, got %d", len(policies))
	}
}

func TestNewResponseEngine_RegistersAllExecutors(t *testing.T) {
	re := testResponseEngine(t, enforcementConfig("lax", true))

	expectedActions := []ActionType{
		ActionBlockIP, ActionKillProcess, ActionQuarantineFile,
		ActionDropConnection, ActionDisableUser, ActionWebhook,
		ActionCommand, ActionLog,
	}
	for _, action := range expectedActions {
		if _, ok := re.executors[action]; !ok {
			t.Errorf("missing executor for action type: %s", action)
		}
	}
}

// ─── Policy overlay (user overrides preset) ─────────────────────────────────

func TestResponseEngine_UserPoliciesOverridePreset(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enforcement = &EnforcementConfig{
		Enabled: true,
		DryRun:  true,
		Preset:  "lax",
		Policies: map[string]ResponsePolicyYAML{
			"injection_shield": {
				Enabled:          true,
				MinSeverity:      "MEDIUM",
				CooldownSeconds:  10,
				MaxActionsPerMin: 100,
				Actions: []ResponseRuleYAML{
					{Action: "block_ip", MinSeverity: "MEDIUM", Description: "Custom block"},
				},
			},
		},
	}

	re := testResponseEngine(t, cfg)
	policies := re.GetPolicies()

	p, ok := policies["injection_shield"]
	if !ok {
		t.Fatal("expected injection_shield policy")
	}

	// Should have the user's custom values, not the lax preset's
	if p.MinSeverity != SeverityMedium {
		t.Errorf("expected MEDIUM min severity from user override, got %s", p.MinSeverity.String())
	}
	if len(p.Actions) != 1 {
		t.Errorf("expected 1 action from user override, got %d", len(p.Actions))
	}
	if p.Actions[0].Action != ActionBlockIP {
		t.Errorf("expected block_ip action from user override, got %s", p.Actions[0].Action)
	}

	// Other modules should still have lax preset values
	if _, ok := policies["network_guardian"]; !ok {
		t.Error("expected network_guardian from lax preset to still be present")
	}
}

// ─── handleAlert — dry run ──────────────────────────────────────────────────

func TestResponseEngine_HandleAlert_DryRun(t *testing.T) {
	re := testResponseEngine(t, enforcementConfig("balanced", true))

	alert := testAlertWithIP("injection_shield", "10.0.0.1", SeverityHigh)
	re.handleAlert(alert)

	records := re.GetRecords(100, "")
	if len(records) == 0 {
		t.Fatal("expected at least one response record in dry-run mode")
	}

	for _, r := range records {
		if r.Status != ActionStatusDryRun {
			t.Errorf("expected DRY_RUN status, got %s", r.Status)
		}
	}
}

// ─── handleAlert — severity below threshold ─────────────────────────────────

func TestResponseEngine_HandleAlert_BelowSeverityThreshold(t *testing.T) {
	re := testResponseEngine(t, enforcementConfig("balanced", true))

	// Balanced preset has min_severity HIGH for injection_shield
	alert := testAlertWithIP("injection_shield", "10.0.0.1", SeverityLow)
	re.handleAlert(alert)

	records := re.GetRecords(100, "")
	if len(records) != 0 {
		t.Errorf("expected no records for LOW severity alert (threshold is HIGH), got %d", len(records))
	}
}

// ─── handleAlert — wildcard policy fallback ─────────────────────────────────

func TestResponseEngine_HandleAlert_WildcardFallback(t *testing.T) {
	re := testResponseEngine(t, enforcementConfig("balanced", true))

	// Use a module name that doesn't have a specific policy
	alert := testAlertWithIP("unknown_module", "10.0.0.1", SeverityCritical)
	re.handleAlert(alert)

	records := re.GetRecords(100, "")
	if len(records) == 0 {
		t.Error("expected wildcard policy to catch unknown module alerts")
	}
}

// ─── handleAlert — disabled policy ──────────────────────────────────────────

func TestResponseEngine_HandleAlert_DisabledPolicy(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enforcement = &EnforcementConfig{
		Enabled: true,
		DryRun:  true,
		Policies: map[string]ResponsePolicyYAML{
			"test_module": {
				Enabled:     false,
				MinSeverity: "LOW",
				Actions: []ResponseRuleYAML{
					{Action: "log_only", MinSeverity: "LOW"},
				},
			},
		},
	}

	re := testResponseEngine(t, cfg)
	alert := testAlertWithIP("test_module", "10.0.0.1", SeverityCritical)
	re.handleAlert(alert)

	records := re.GetRecords(100, "")
	if len(records) != 0 {
		t.Errorf("expected no records for disabled policy, got %d", len(records))
	}
}

// ─── Allow list ─────────────────────────────────────────────────────────────

func TestResponseEngine_HandleAlert_AllowList(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enforcement = &EnforcementConfig{
		Enabled:         true,
		DryRun:          true,
		GlobalAllowList: []string{"10.0.0.1"},
		Policies: map[string]ResponsePolicyYAML{
			"test_module": {
				Enabled:     true,
				MinSeverity: "LOW",
				Actions: []ResponseRuleYAML{
					{Action: "log_only", MinSeverity: "LOW"},
				},
			},
		},
	}

	re := testResponseEngine(t, cfg)
	alert := testAlertWithIP("test_module", "10.0.0.1", SeverityCritical)
	re.handleAlert(alert)

	records := re.GetRecords(100, "")
	if len(records) != 0 {
		t.Errorf("expected no records for allow-listed IP, got %d", len(records))
	}
}

func TestResponseEngine_HandleAlert_PerModuleAllowList(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enforcement = &EnforcementConfig{
		Enabled: true,
		DryRun:  true,
		Policies: map[string]ResponsePolicyYAML{
			"test_module": {
				Enabled:     true,
				MinSeverity: "LOW",
				AllowList:   []string{"192.168.1.100"},
				Actions: []ResponseRuleYAML{
					{Action: "log_only", MinSeverity: "LOW"},
				},
			},
		},
	}

	re := testResponseEngine(t, cfg)

	// Allowed IP — should be skipped
	alert := testAlertWithIP("test_module", "192.168.1.100", SeverityCritical)
	re.handleAlert(alert)
	if len(re.GetRecords(100, "")) != 0 {
		t.Error("expected no records for per-module allow-listed IP")
	}

	// Different IP — should trigger
	alert2 := testAlertWithIP("test_module", "192.168.1.200", SeverityCritical)
	re.handleAlert(alert2)
	if len(re.GetRecords(100, "")) == 0 {
		t.Error("expected records for non-allow-listed IP")
	}
}

// ─── Cooldown ───────────────────────────────────────────────────────────────

func TestResponseEngine_Cooldown(t *testing.T) {
	// Cooldowns are only set after a successful (non-dry-run) execution.
	// In dry-run mode, cooldowns are NOT set, so we test with a log_only
	// executor which succeeds immediately without side effects.
	cfg := DefaultConfig()
	cfg.Enforcement = &EnforcementConfig{
		Enabled: true,
		DryRun:  false, // live mode so cooldowns are set on success
		Policies: map[string]ResponsePolicyYAML{
			"test_module": {
				Enabled:          true,
				MinSeverity:      "LOW",
				CooldownSeconds:  3600, // 1 hour
				MaxActionsPerMin: 100,
				Actions: []ResponseRuleYAML{
					{Action: "log_only", MinSeverity: "LOW"},
				},
			},
		},
	}

	re := testResponseEngine(t, cfg)

	// First alert — should succeed (log_only always succeeds)
	alert1 := testAlertWithIP("test_module", "10.0.0.1", SeverityHigh)
	re.handleAlert(alert1)

	records := re.GetRecords(100, "")
	successCount := 0
	for _, r := range records {
		if r.Status == ActionStatusSuccess {
			successCount++
		}
	}
	if successCount != 1 {
		t.Errorf("expected 1 success record from first alert, got %d", successCount)
	}

	// Second alert same target — should be on cooldown
	alert2 := testAlertWithIP("test_module", "10.0.0.1", SeverityHigh)
	re.handleAlert(alert2)

	records = re.GetRecords(100, "")
	cooldownCount := 0
	for _, r := range records {
		if r.Status == ActionStatusCooldown {
			cooldownCount++
		}
	}
	if cooldownCount != 1 {
		t.Errorf("expected 1 cooldown record from second alert, got %d", cooldownCount)
	}
}

// ─── Rate limiting ──────────────────────────────────────────────────────────

func TestResponseEngine_RateLimit(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enforcement = &EnforcementConfig{
		Enabled: true,
		DryRun:  true,
		Policies: map[string]ResponsePolicyYAML{
			"test_module": {
				Enabled:          true,
				MinSeverity:      "LOW",
				CooldownSeconds:  0, // no cooldown
				MaxActionsPerMin: 2,
				Actions: []ResponseRuleYAML{
					{Action: "log_only", MinSeverity: "LOW"},
				},
			},
		},
	}

	re := testResponseEngine(t, cfg)

	// Fire 5 alerts — only 2 should succeed (rate limit)
	for i := 0; i < 5; i++ {
		alert := testAlertWithIP("test_module", "10.0.0."+string(rune('1'+i)), SeverityHigh)
		re.handleAlert(alert)
	}

	records := re.GetRecords(100, "")
	dryRunCount := 0
	skippedCount := 0
	for _, r := range records {
		switch r.Status {
		case ActionStatusDryRun:
			dryRunCount++
		case ActionStatusSkipped:
			skippedCount++
		}
	}

	if dryRunCount != 2 {
		t.Errorf("expected 2 dry-run records (rate limit=2), got %d", dryRunCount)
	}
	if skippedCount != 3 {
		t.Errorf("expected 3 skipped records, got %d", skippedCount)
	}
}

// ─── SetPolicyEnabled / SetDryRun ───────────────────────────────────────────

func TestResponseEngine_SetPolicyEnabled(t *testing.T) {
	re := testResponseEngine(t, enforcementConfig("balanced", true))

	if !re.SetPolicyEnabled("injection_shield", false) {
		t.Error("expected SetPolicyEnabled to return true for existing module")
	}

	policies := re.GetPolicies()
	if policies["injection_shield"].Enabled {
		t.Error("expected injection_shield to be disabled")
	}

	if re.SetPolicyEnabled("nonexistent_module", true) {
		t.Error("expected SetPolicyEnabled to return false for nonexistent module")
	}
}

func TestResponseEngine_SetDryRun(t *testing.T) {
	re := testResponseEngine(t, enforcementConfig("balanced", false))

	if !re.SetDryRun("injection_shield", true) {
		t.Error("expected SetDryRun to return true for existing module")
	}

	policies := re.GetPolicies()
	if !policies["injection_shield"].DryRun {
		t.Error("expected injection_shield dry_run to be true")
	}

	if re.SetDryRun("nonexistent_module", true) {
		t.Error("expected SetDryRun to return false for nonexistent module")
	}
}

// ─── Stats ──────────────────────────────────────────────────────────────────

func TestResponseEngine_Stats(t *testing.T) {
	re := testResponseEngine(t, enforcementConfig("balanced", true))

	// Fire some alerts to generate records
	alert := testAlertWithIP("injection_shield", "10.0.0.1", SeverityHigh)
	re.handleAlert(alert)

	stats := re.Stats()
	if stats["total_policies"] == nil {
		t.Error("expected total_policies in stats")
	}
	if stats["total_records"] == nil {
		t.Error("expected total_records in stats")
	}
	if stats["by_status"] == nil {
		t.Error("expected by_status in stats")
	}
	if stats["by_module"] == nil {
		t.Error("expected by_module in stats")
	}
	if stats["by_action"] == nil {
		t.Error("expected by_action in stats")
	}

	totalRecords, ok := stats["total_records"].(int)
	if !ok || totalRecords == 0 {
		t.Error("expected at least 1 record in stats")
	}
}

// ─── GetRecords filtering ───────────────────────────────────────────────────

func TestResponseEngine_GetRecords_ModuleFilter(t *testing.T) {
	re := testResponseEngine(t, enforcementConfig("balanced", true))

	re.handleAlert(testAlertWithIP("injection_shield", "10.0.0.1", SeverityHigh))
	re.handleAlert(testAlertWithIP("network_guardian", "10.0.0.2", SeverityHigh))

	allRecords := re.GetRecords(100, "")
	if len(allRecords) == 0 {
		t.Fatal("expected records")
	}

	injRecords := re.GetRecords(100, "injection_shield")
	netRecords := re.GetRecords(100, "network_guardian")

	for _, r := range injRecords {
		if r.Module != "injection_shield" {
			t.Errorf("expected injection_shield module, got %s", r.Module)
		}
	}
	for _, r := range netRecords {
		if r.Module != "network_guardian" {
			t.Errorf("expected network_guardian module, got %s", r.Module)
		}
	}

	if len(injRecords)+len(netRecords) != len(allRecords) {
		t.Errorf("filtered records should sum to total: %d + %d != %d",
			len(injRecords), len(netRecords), len(allRecords))
	}
}

func TestResponseEngine_GetRecords_Limit(t *testing.T) {
	re := testResponseEngine(t, enforcementConfig("balanced", true))

	// Generate several records
	for i := 0; i < 10; i++ {
		re.handleAlert(testAlertWithIP("injection_shield", "10.0.0.1", SeverityCritical))
	}

	records := re.GetRecords(3, "")
	if len(records) > 3 {
		t.Errorf("expected at most 3 records with limit=3, got %d", len(records))
	}
}

// ─── Record eviction ────────────────────────────────────────────────────────

func TestResponseEngine_RecordEviction(t *testing.T) {
	cfg := enforcementConfig("lax", true)
	re := testResponseEngine(t, cfg)
	re.maxRecords = 20

	// Generate more records than maxRecords
	for i := 0; i < 30; i++ {
		re.handleAlert(testAlertWithIP("injection_shield", "10.0.0.1", SeverityCritical))
	}

	records := re.GetRecords(100, "")
	if len(records) > 20 {
		t.Errorf("expected at most 20 records after eviction, got %d", len(records))
	}
}

// ─── Concurrent access ─────────────────────────────────────────────────────

func TestResponseEngine_ConcurrentAccess(t *testing.T) {
	re := testResponseEngine(t, enforcementConfig("balanced", true))

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(3)
		go func() {
			defer wg.Done()
			re.handleAlert(testAlertWithIP("injection_shield", "10.0.0.1", SeverityHigh))
		}()
		go func() {
			defer wg.Done()
			re.GetRecords(10, "")
		}()
		go func() {
			defer wg.Done()
			re.Stats()
		}()
	}
	wg.Wait()
}

// ─── resolveTarget ──────────────────────────────────────────────────────────

func TestResponseEngine_ResolveTarget(t *testing.T) {
	re := testResponseEngine(t, enforcementConfig("lax", true))
	rule := ResponseRule{Action: ActionLog}

	// source_ip takes priority
	alert := &Alert{
		ID:       "a1",
		Module:   "test",
		Metadata: map[string]interface{}{"source_ip": "10.0.0.1", "process_id": "1234"},
	}
	if target := re.resolveTarget(alert, rule); target != "10.0.0.1" {
		t.Errorf("expected source_ip, got %s", target)
	}

	// Falls back to process_id
	alert2 := &Alert{
		ID:       "a2",
		Module:   "test",
		Metadata: map[string]interface{}{"process_id": "5678"},
	}
	if target := re.resolveTarget(alert2, rule); target != "5678" {
		t.Errorf("expected process_id, got %s", target)
	}

	// Falls back to file_path
	alert3 := &Alert{
		ID:       "a3",
		Module:   "test",
		Metadata: map[string]interface{}{"file_path": "/tmp/malware.bin"},
	}
	if target := re.resolveTarget(alert3, rule); target != "/tmp/malware.bin" {
		t.Errorf("expected file_path, got %s", target)
	}

	// Falls back to alert ID
	alert4 := &Alert{
		ID:       "a4",
		Module:   "test",
		Metadata: map[string]interface{}{},
	}
	if target := re.resolveTarget(alert4, rule); target != "a4" {
		t.Errorf("expected alert ID, got %s", target)
	}
}

// ─── isAllowListed ──────────────────────────────────────────────────────────

func TestResponseEngine_IsAllowListed(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enforcement = &EnforcementConfig{
		Enabled:         true,
		GlobalAllowList: []string{"1.2.3.4"},
	}
	re := testResponseEngine(t, cfg)

	policy := &ResponsePolicy{
		AllowList: []string{"5.6.7.8"},
	}

	if !re.isAllowListed(policy, "1.2.3.4") {
		t.Error("expected global allow list to match")
	}
	if !re.isAllowListed(policy, "5.6.7.8") {
		t.Error("expected per-module allow list to match")
	}
	if re.isAllowListed(policy, "9.9.9.9") {
		t.Error("expected non-listed IP to not match")
	}
	if re.isAllowListed(policy, "") {
		t.Error("expected empty IP to not match")
	}
}

// ─── Cooldown internals ─────────────────────────────────────────────────────

func TestResponseEngine_CooldownInternals(t *testing.T) {
	re := testResponseEngine(t, enforcementConfig("lax", true))

	key := "test:block_ip:10.0.0.1"

	// Not on cooldown initially
	if re.isOnCooldown(key, 5*time.Minute) {
		t.Error("expected no cooldown initially")
	}

	// Set cooldown
	re.setCooldown(key, 5*time.Minute)

	// Now on cooldown
	if !re.isOnCooldown(key, 5*time.Minute) {
		t.Error("expected to be on cooldown after setCooldown")
	}

	// Zero cooldown always returns false
	if re.isOnCooldown(key, 0) {
		t.Error("zero cooldown should never be on cooldown")
	}
}

// ─── Rate limit internals ───────────────────────────────────────────────────

func TestResponseEngine_RateLimitInternals(t *testing.T) {
	re := testResponseEngine(t, enforcementConfig("lax", true))

	// Zero max = unlimited
	if !re.checkRateLimit("test", 0) {
		t.Error("zero max should always allow")
	}

	// Should allow up to max
	if !re.checkRateLimit("test", 2) {
		t.Error("first call should be allowed")
	}
	if !re.checkRateLimit("test", 2) {
		t.Error("second call should be allowed")
	}
	if re.checkRateLimit("test", 2) {
		t.Error("third call should be denied (limit=2)")
	}
}

// ─── FindRecord ─────────────────────────────────────────────────────────────

func TestResponseEngine_FindRecord_Found(t *testing.T) {
	re := testResponseEngine(t, enforcementConfig("balanced", true))

	alert := testAlertWithIP("injection_shield", "10.0.0.1", SeverityHigh)
	re.handleAlert(alert)

	records := re.GetRecords(1, "")
	if len(records) == 0 {
		t.Fatal("expected at least one record")
	}

	found := re.FindRecord(records[0].ID)
	if found == nil {
		t.Fatal("expected FindRecord to return a record")
	}
	if found.ID != records[0].ID {
		t.Errorf("expected ID %s, got %s", records[0].ID, found.ID)
	}
	if found.Module != "injection_shield" {
		t.Errorf("expected module injection_shield, got %s", found.Module)
	}
}

func TestResponseEngine_FindRecord_NotFound(t *testing.T) {
	re := testResponseEngine(t, enforcementConfig("balanced", true))

	found := re.FindRecord("nonexistent-id")
	if found != nil {
		t.Error("expected nil for nonexistent record ID")
	}
}

func TestResponseEngine_FindRecord_EmptyRecords(t *testing.T) {
	re := testResponseEngine(t, enforcementConfig("balanced", true))

	found := re.FindRecord("any-id")
	if found != nil {
		t.Error("expected nil when no records exist")
	}
}

func TestResponseEngine_FindRecord_ConcurrentAccess(t *testing.T) {
	re := testResponseEngine(t, enforcementConfig("balanced", true))

	// Generate some records
	for i := 0; i < 10; i++ {
		re.handleAlert(testAlertWithIP("injection_shield", "10.0.0.1", SeverityCritical))
	}

	records := re.GetRecords(10, "")
	if len(records) == 0 {
		t.Fatal("expected records")
	}

	// Concurrent FindRecord + handleAlert
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			re.FindRecord(records[0].ID)
		}()
		go func() {
			defer wg.Done()
			re.handleAlert(testAlertWithIP("injection_shield", "10.0.0.1", SeverityHigh))
		}()
	}
	wg.Wait()
}

// ─── HandleAlertForTest (exported wrapper) ──────────────────────────────────

func TestResponseEngine_HandleAlertForTest(t *testing.T) {
	re := testResponseEngine(t, enforcementConfig("balanced", true))

	alert := testAlertWithIP("injection_shield", "10.0.0.1", SeverityHigh)
	re.HandleAlertForTest(alert)

	records := re.GetRecords(100, "")
	if len(records) == 0 {
		t.Fatal("expected HandleAlertForTest to generate records")
	}
}
