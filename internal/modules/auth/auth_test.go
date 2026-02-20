package auth

import (
	"context"
	"fmt"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/1sec-project/1sec/internal/core"
	"github.com/rs/zerolog"
)

// ─── Helpers ─────────────────────────────────────────────────────────────────

type capturingPipeline struct {
	pipeline *core.AlertPipeline
	mu       sync.Mutex
	alerts   []*core.Alert
}

func makeCapturingPipeline() *capturingPipeline {
	cp := &capturingPipeline{}
	cp.pipeline = core.NewAlertPipeline(zerolog.Nop(), 10000)
	cp.pipeline.AddHandler(func(a *core.Alert) {
		cp.mu.Lock()
		cp.alerts = append(cp.alerts, a)
		cp.mu.Unlock()
	})
	return cp
}

func (cp *capturingPipeline) count() int {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	return len(cp.alerts)
}

func (cp *capturingPipeline) hasAlertType(alertType string) bool {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	for _, a := range cp.alerts {
		if a.Type == alertType {
			return true
		}
	}
	return false
}

func startedModule(t *testing.T) *Fortress {
	t.Helper()
	f := New()
	cfg := core.DefaultConfig()
	if err := f.Start(context.Background(), nil, nil, cfg); err != nil {
		t.Fatalf("Fortress.Start() error: %v", err)
	}
	return f
}

func startedModuleWithPipeline(t *testing.T, cp *capturingPipeline) *Fortress {
	t.Helper()
	f := New()
	cfg := core.DefaultConfig()
	if err := f.Start(context.Background(), nil, cp.pipeline, cfg); err != nil {
		t.Fatalf("Fortress.Start() error: %v", err)
	}
	return f
}

// ─── Module Interface ─────────────────────────────────────────────────────────

func TestFortress_Name(t *testing.T) {
	f := New()
	if f.Name() != ModuleName {
		t.Errorf("Name() = %q, want %q", f.Name(), ModuleName)
	}
}

func TestFortress_Description(t *testing.T) {
	f := New()
	if f.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

func TestFortress_Start_Stop(t *testing.T) {
	f := New()
	cfg := core.DefaultConfig()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := f.Start(ctx, nil, nil, cfg); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	if f.loginTracker == nil {
		t.Error("loginTracker should be initialized after Start")
	}
	if f.sessionMon == nil {
		t.Error("sessionMon should be initialized after Start")
	}
	if f.oauthMon == nil {
		t.Error("oauthMon should be initialized after Start")
	}
	if f.sprayDet == nil {
		t.Error("sprayDet should be initialized after Start")
	}
	if err := f.Stop(); err != nil {
		t.Fatalf("Stop() error: %v", err)
	}
}

// ─── LoginTracker ─────────────────────────────────────────────────────────────

func TestLoginTracker_RecordFailure_BruteForce(t *testing.T) {
	lt := NewLoginTracker(5, 50, 5*time.Minute)

	var result LoginResult
	for i := 0; i < 5; i++ {
		result = lt.RecordFailure("10.0.0.1", "admin")
	}

	if !result.BruteForce {
		t.Error("expected BruteForce after maxPerMinute failures")
	}
	if result.FailureCount != 5 {
		t.Errorf("FailureCount = %d, want 5", result.FailureCount)
	}
}

func TestLoginTracker_RecordFailure_CredentialStuffing(t *testing.T) {
	lt := NewLoginTracker(1000, 3, 5*time.Minute) // high brute force threshold, low stuffing

	for i := 0; i < 3; i++ {
		lt.RecordFailure("10.0.0.1", fmt.Sprintf("user%d", i))
	}
	result := lt.RecordFailure("10.0.0.1", "userd")

	if !result.CredentialStuffing {
		t.Error("expected CredentialStuffing after stuffingThreshold unique users")
	}
	if result.UniqueUsers < 3 {
		t.Errorf("UniqueUsers = %d, want >= 3", result.UniqueUsers)
	}
}

func TestLoginTracker_RecordFailure_WindowReset(t *testing.T) {
	lt := NewLoginTracker(5, 50, 5*time.Minute)

	// Record some failures
	for i := 0; i < 3; i++ {
		lt.RecordFailure("10.0.0.1", "admin")
	}

	// Manipulate the window to simulate time passing
	lt.mu.Lock()
	rec, _ := lt.failures.Get("10.0.0.1")
	rec.window = time.Now().Add(-2 * time.Minute) // push window back >1 minute
	lt.mu.Unlock()

	// New failure should start fresh window
	result := lt.RecordFailure("10.0.0.1", "admin")
	if result.FailureCount != 1 {
		t.Errorf("FailureCount after window reset = %d, want 1", result.FailureCount)
	}
}

func TestLoginTracker_IsLockedOut(t *testing.T) {
	lt := NewLoginTracker(3, 50, 5*time.Minute)

	// Trigger brute force to create lockout
	for i := 0; i < 3; i++ {
		lt.RecordFailure("10.0.0.1", "admin")
	}

	if !lt.IsLockedOut("10.0.0.1") {
		t.Error("expected IP to be locked out after brute force")
	}
	if lt.IsLockedOut("10.0.0.2") {
		t.Error("unrelated IP should not be locked out")
	}
}

func TestLoginTracker_WasRecentlyBlocked(t *testing.T) {
	lt := NewLoginTracker(3, 50, 5*time.Minute)

	// Trigger brute force
	for i := 0; i < 3; i++ {
		lt.RecordFailure("10.0.0.1", "admin")
	}

	if !lt.WasRecentlyBlocked("10.0.0.1") {
		t.Error("expected WasRecentlyBlocked to be true after brute force")
	}
	if lt.WasRecentlyBlocked("10.0.0.2") {
		t.Error("unrelated IP should not be recently blocked")
	}
}

func TestLoginTracker_ClearFailures(t *testing.T) {
	lt := NewLoginTracker(5, 50, 5*time.Minute)

	lt.RecordFailure("10.0.0.1", "admin")
	lt.RecordFailure("10.0.0.1", "admin")
	lt.ClearFailures("10.0.0.1", "admin")

	// After clearing, a new failure should start at count 1
	result := lt.RecordFailure("10.0.0.1", "admin")
	if result.FailureCount != 1 {
		t.Errorf("FailureCount after clear = %d, want 1", result.FailureCount)
	}
}

func TestLoginTracker_RecordMFAFailure(t *testing.T) {
	lt := NewLoginTracker(10, 50, 5*time.Minute)

	for i := 1; i <= 5; i++ {
		count := lt.RecordMFAFailure("10.0.0.1")
		if count != i {
			t.Errorf("RecordMFAFailure() call %d = %d, want %d", i, count, i)
		}
	}
}

// ─── SessionMonitor ───────────────────────────────────────────────────────────

func TestSessionMonitor_RegisterAndCheck(t *testing.T) {
	sm := NewSessionMonitor()
	sm.RegisterSession("sess-1", "alice", "10.0.0.1", "US", "Mozilla/5.0")

	// Same IP, same UA — no anomaly
	anomaly := sm.CheckAnomaly("sess-1", "10.0.0.1", "US", "Mozilla/5.0")
	if anomaly.IPChanged || anomaly.UAChanged || anomaly.ImpossibleTravel {
		t.Error("expected no anomaly for same IP and UA")
	}
}

func TestSessionMonitor_IPChange(t *testing.T) {
	sm := NewSessionMonitor()
	sm.RegisterSession("sess-2", "alice", "10.0.0.1", "US", "Mozilla/5.0")

	anomaly := sm.CheckAnomaly("sess-2", "192.168.1.1", "US", "Mozilla/5.0")
	if !anomaly.IPChanged {
		t.Error("expected IPChanged when IP differs")
	}
	if anomaly.OriginalIP != "10.0.0.1" {
		t.Errorf("OriginalIP = %q, want %q", anomaly.OriginalIP, "10.0.0.1")
	}
}

func TestSessionMonitor_UAChange(t *testing.T) {
	sm := NewSessionMonitor()
	sm.RegisterSession("sess-3", "alice", "10.0.0.1", "US", "Mozilla/5.0")

	anomaly := sm.CheckAnomaly("sess-3", "10.0.0.1", "US", "Chrome/120")
	if !anomaly.UAChanged {
		t.Error("expected UAChanged when user-agent differs")
	}
	if anomaly.OriginalUA != "Mozilla/5.0" {
		t.Errorf("OriginalUA = %q, want %q", anomaly.OriginalUA, "Mozilla/5.0")
	}
}

func TestSessionMonitor_ImpossibleTravel(t *testing.T) {
	sm := NewSessionMonitor()
	sm.RegisterSession("sess-4", "alice", "10.0.0.1", "US", "Mozilla/5.0")

	// Check from a very different country immediately (within the same second)
	anomaly := sm.CheckAnomaly("sess-4", "203.0.113.1", "JP", "Mozilla/5.0")
	if !anomaly.ImpossibleTravel {
		t.Error("expected ImpossibleTravel for US->JP with near-zero time delta")
	}
}

// ─── OAuthMonitor ─────────────────────────────────────────────────────────────

func TestOAuthMonitor_ConsentPhishing(t *testing.T) {
	om := NewOAuthMonitor()

	// 3+ dangerous scopes + 3+ grants in 1 hour
	scopes := "mail.read mail.send files.readwrite.all"
	for i := 0; i < 3; i++ {
		om.Analyze("10.0.0.1", "app-evil", "EvilApp", scopes, fmt.Sprintf("user%d", i), "authorization_code", "https://evil.com/callback")
	}
	result := om.Analyze("10.0.0.1", "app-evil", "EvilApp", scopes, "userd", "authorization_code", "https://evil.com/callback")

	if !result.ConsentPhishing {
		t.Error("expected ConsentPhishing with 3+ dangerous scopes and 3+ grants")
	}
}

func TestOAuthMonitor_ExcessiveScopes(t *testing.T) {
	om := NewOAuthMonitor()

	// 4+ dangerous scopes
	scopes := "mail.read mail.send mail.readwrite files.readwrite.all"
	result := om.Analyze("10.0.0.1", "app-greedy", "GreedyApp", scopes, "alice", "authorization_code", "https://app.com/cb")

	if !result.ExcessiveScopes {
		t.Error("expected ExcessiveScopes with 4+ dangerous scopes")
	}
}

func TestOAuthMonitor_ExcessiveScopes_TotalCount(t *testing.T) {
	om := NewOAuthMonitor()

	// 8+ total scopes (even if not all dangerous)
	scopes := "scope1 scope2 scope3 scope4 scope5 scope6 scope7 scope8"
	result := om.Analyze("10.0.0.1", "app-many", "ManyScopes", scopes, "alice", "authorization_code", "https://app.com/cb")

	if !result.ExcessiveScopes {
		t.Error("expected ExcessiveScopes with 8+ total scopes")
	}
}

func TestOAuthMonitor_TokenAbuse(t *testing.T) {
	om := NewOAuthMonitor()

	// Rapid grants to many users: >20 grants, >10 unique users
	for i := 0; i < 25; i++ {
		om.Analyze("10.0.0.1", "app-abuse", "AbuseApp", "mail.read", fmt.Sprintf("user%d", i), "authorization_code", "https://app.com/cb")
	}
	result := om.Analyze("10.0.0.1", "app-abuse", "AbuseApp", "mail.read", "userZ", "authorization_code", "https://app.com/cb")

	if !result.TokenAbuse {
		t.Error("expected TokenAbuse with rapid grants to many users")
	}
}

func TestOAuthMonitor_TrackTokenUsage_MultiIP(t *testing.T) {
	om := NewOAuthMonitor()

	om.TrackTokenUsage("token-1", "10.0.0.1", "alice", "read")
	om.TrackTokenUsage("token-1", "10.0.0.2", "alice", "read")
	result := om.TrackTokenUsage("token-1", "10.0.0.3", "alice", "read")

	if !result.MultiIPUsage {
		t.Error("expected MultiIPUsage with 3+ IPs")
	}
	if result.IPCount < 3 {
		t.Errorf("IPCount = %d, want >= 3", result.IPCount)
	}
	if result.OriginalIP != "10.0.0.1" {
		t.Errorf("OriginalIP = %q, want %q", result.OriginalIP, "10.0.0.1")
	}
}

func TestOAuthMonitor_TrackTokenUsage_AnomalousAction(t *testing.T) {
	om := NewOAuthMonitor()

	// Build up 6 known actions
	actions := []string{"read", "list", "search", "view", "download", "export"}
	for _, a := range actions {
		om.TrackTokenUsage("token-2", "10.0.0.1", "alice", a)
	}

	// New action after 5+ known actions
	result := om.TrackTokenUsage("token-2", "10.0.0.1", "alice", "delete_all")
	if !result.AnomalousAction {
		t.Error("expected AnomalousAction for new action after 5+ known actions")
	}
}

// ─── PasswordSprayDetector ────────────────────────────────────────────────────

func TestPasswordSprayDetector_Distributed(t *testing.T) {
	ps := NewPasswordSprayDetector()

	// 7 IPs, 3 attempts each = 21 total, avg 3.0 per IP (<=3 threshold)
	// Each IP targets different users to get 10+ unique users
	for i := 0; i < 7; i++ {
		ip := fmt.Sprintf("10.0.0.%d", i+1)
		for j := 0; j < 3; j++ {
			ps.RecordFailure(ip, fmt.Sprintf("user%d", j+i*3))
		}
	}

	result := ps.Check()
	if !result.Detected {
		t.Error("expected spray detection with 5+ IPs, 10+ users, low avg attempts")
	}
	if result.UniqueIPs < 5 {
		t.Errorf("UniqueIPs = %d, want >= 5", result.UniqueIPs)
	}
}

func TestPasswordSprayDetector_SingleIP(t *testing.T) {
	ps := NewPasswordSprayDetector()

	// Single IP targeting 20+ users
	for i := 0; i < 22; i++ {
		ps.RecordFailure("10.0.0.1", fmt.Sprintf("user%d", i))
	}

	result := ps.Check()
	if !result.Detected {
		t.Error("expected spray detection for single IP targeting 20+ users")
	}
}

func TestPasswordSprayDetector_BelowThreshold(t *testing.T) {
	ps := NewPasswordSprayDetector()

	// Only 10 attempts — below the 20 minimum
	for i := 0; i < 10; i++ {
		ps.RecordFailure("10.0.0.1", fmt.Sprintf("user%d", i))
	}

	result := ps.Check()
	if result.Detected {
		t.Error("expected no detection with <20 total attempts")
	}
}

// ─── HandleEvent Integration ──────────────────────────────────────────────────

func TestFortress_HandleEvent_LoginFailure(t *testing.T) {
	cp := makeCapturingPipeline()
	f := startedModuleWithPipeline(t, cp)
	defer f.Stop()

	// Send enough failures to trigger brute force (default maxPerMinute=10)
	for i := 0; i < 10; i++ {
		ev := core.NewSecurityEvent("test", "login_failure", core.SeverityInfo, "login failed")
		ev.Details["username"] = "admin"
		ev.SourceIP = "10.0.0.1"
		f.HandleEvent(ev)
	}

	if cp.count() == 0 {
		t.Error("expected alert after brute force threshold")
	}
	if !cp.hasAlertType("brute_force") {
		t.Error("expected brute_force alert type")
	}
}

func TestFortress_HandleEvent_LoginSuccess_PostBruteForce(t *testing.T) {
	cp := makeCapturingPipeline()
	f := startedModuleWithPipeline(t, cp)
	defer f.Stop()

	// Trigger brute force first
	for i := 0; i < 10; i++ {
		ev := core.NewSecurityEvent("test", "login_failure", core.SeverityInfo, "login failed")
		ev.Details["username"] = "admin"
		ev.SourceIP = "10.0.0.1"
		f.HandleEvent(ev)
	}

	initialCount := cp.count()

	// Now successful login from same IP
	ev := core.NewSecurityEvent("test", "login_success", core.SeverityInfo, "login success")
	ev.Details["username"] = "admin"
	ev.Details["session_id"] = "sess-123"
	ev.SourceIP = "10.0.0.1"
	f.HandleEvent(ev)

	if cp.count() <= initialCount {
		t.Error("expected post_bruteforce_login alert after successful login following brute force")
	}
	if !cp.hasAlertType("post_bruteforce_login") {
		t.Error("expected post_bruteforce_login alert type")
	}
}

func TestFortress_HandleEvent_MFAFatigue(t *testing.T) {
	cp := makeCapturingPipeline()
	f := startedModuleWithPipeline(t, cp)
	defer f.Stop()

	// Send >10 push MFA failures
	for i := 0; i < 12; i++ {
		ev := core.NewSecurityEvent("test", "mfa_attempt", core.SeverityInfo, "MFA attempt")
		ev.Details["success"] = "false"
		ev.Details["method"] = "push"
		ev.SourceIP = "10.0.0.1"
		f.HandleEvent(ev)
	}

	if !cp.hasAlertType("mfa_fatigue") {
		t.Error("expected mfa_fatigue alert after >10 push MFA failures")
	}
}

// ─── Utility Functions ────────────────────────────────────────────────────────

func TestHaversineDistance(t *testing.T) {
	// New York (US) to Tokyo (JP) ≈ 10,838 km
	nyLat, nyLon := 40.7128, -74.0060
	tokyoLat, tokyoLon := 35.6762, 139.6503

	dist := haversineDistance(nyLat, nyLon, tokyoLat, tokyoLon)
	if dist < 10000 || dist > 11500 {
		t.Errorf("haversineDistance(NY, Tokyo) = %.0f km, want ~10838 km", dist)
	}

	// Same point should be 0
	dist = haversineDistance(nyLat, nyLon, nyLat, nyLon)
	if dist > 0.01 {
		t.Errorf("haversineDistance(same point) = %f, want ~0", dist)
	}
}

func TestCountryCentroid(t *testing.T) {
	// Known country
	lat, lon, ok := countryCentroid("US")
	if !ok {
		t.Fatal("countryCentroid(US) should return ok=true")
	}
	if math.Abs(lat-39.8) > 0.1 || math.Abs(lon-(-98.5)) > 0.1 {
		t.Errorf("countryCentroid(US) = (%.1f, %.1f), want (39.8, -98.5)", lat, lon)
	}

	// Unknown country
	_, _, ok = countryCentroid("XX")
	if ok {
		t.Error("countryCentroid(XX) should return ok=false")
	}
}

func TestGetIntSetting(t *testing.T) {
	settings := map[string]interface{}{
		"int_val":   42,
		"float_val": float64(99),
	}

	if v := getIntSetting(settings, "int_val", 0); v != 42 {
		t.Errorf("getIntSetting(int_val) = %d, want 42", v)
	}
	if v := getIntSetting(settings, "float_val", 0); v != 99 {
		t.Errorf("getIntSetting(float_val) = %d, want 99", v)
	}
	if v := getIntSetting(settings, "missing", 7); v != 7 {
		t.Errorf("getIntSetting(missing) = %d, want 7", v)
	}
	if v := getIntSetting(nil, "any", 5); v != 5 {
		t.Errorf("getIntSetting(nil map) = %d, want 5", v)
	}
}

// Compile-time interface check
var _ core.Module = (*Fortress)(nil)
