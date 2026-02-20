package network

import (
	"sync"
	"testing"
	"time"

	"context"

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

func (cp *capturingPipeline) alertTitles() []string {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	titles := make([]string, len(cp.alerts))
	for i, a := range cp.alerts {
		titles[i] = a.Title
	}
	return titles
}

func startedModule(t *testing.T) *Guardian {
	t.Helper()
	g := New()
	cfg := core.DefaultConfig()
	if err := g.Start(context.Background(), nil, nil, cfg); err != nil {
		t.Fatalf("Guardian.Start() error: %v", err)
	}
	return g
}

func startedModuleWithPipeline(t *testing.T, cp *capturingPipeline) *Guardian {
	t.Helper()
	g := New()
	cfg := core.DefaultConfig()
	if err := g.Start(context.Background(), nil, cp.pipeline, cfg); err != nil {
		t.Fatalf("Guardian.Start() error: %v", err)
	}
	return g
}

// ─── Module Interface ─────────────────────────────────────────────────────────

func TestGuardian_Name(t *testing.T) {
	g := New()
	if g.Name() != ModuleName {
		t.Errorf("Name() = %q, want %q", g.Name(), ModuleName)
	}
}

func TestGuardian_Description(t *testing.T) {
	g := New()
	if g.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

func TestGuardian_Start_Stop(t *testing.T) {
	g := New()
	cfg := core.DefaultConfig()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := g.Start(ctx, nil, nil, cfg); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	if g.rateLimiter == nil {
		t.Error("rateLimiter should be initialized")
	}
	if g.ipReputation == nil {
		t.Error("ipReputation should be initialized")
	}
	if g.geoFence == nil {
		t.Error("geoFence should be initialized")
	}
	if g.dnsTunnelDet == nil {
		t.Error("dnsTunnelDet should be initialized")
	}
	if g.c2Detector == nil {
		t.Error("c2Detector should be initialized")
	}
	if g.lateralMon == nil {
		t.Error("lateralMon should be initialized")
	}
	if g.portScanDet == nil {
		t.Error("portScanDet should be initialized")
	}
	if err := g.Stop(); err != nil {
		t.Fatalf("Stop() error: %v", err)
	}
}

// ─── RateLimiter ──────────────────────────────────────────────────────────────

func TestRateLimiter_Allow(t *testing.T) {
	rl := NewRateLimiter(100, 10)
	// First request should be allowed
	if !rl.Allow("10.0.0.1") {
		t.Error("first request should be allowed")
	}
}

func TestRateLimiter_BurstExceeded(t *testing.T) {
	rl := NewRateLimiter(1000, 5)
	for i := 0; i < 5; i++ {
		rl.Allow("10.0.0.1")
	}
	// 6th request in same second should be blocked
	if rl.Allow("10.0.0.1") {
		t.Error("expected burst limit to block 6th request")
	}
}

func TestRateLimiter_DifferentIPs(t *testing.T) {
	rl := NewRateLimiter(1000, 5)
	for i := 0; i < 5; i++ {
		rl.Allow("10.0.0.1")
	}
	// Different IP should still be allowed
	if !rl.Allow("10.0.0.2") {
		t.Error("different IP should not be affected by other IP's burst")
	}
}

func TestRateLimiter_DDoSDetection(t *testing.T) {
	rl := NewRateLimiter(10, 100)
	// DDoS threshold = maxPerMinute * 10 = 100
	for i := 0; i < 150; i++ {
		rl.RecordRequest("10.0.0.1")
	}
	if !rl.DetectDDoS() {
		t.Error("expected DDoS detection after exceeding threshold")
	}
}

func TestRateLimiter_NoDDoS(t *testing.T) {
	rl := NewRateLimiter(1000, 100)
	rl.RecordRequest("10.0.0.1")
	if rl.DetectDDoS() {
		t.Error("should not detect DDoS with single request")
	}
}

func TestRateLimiter_CurrentRate(t *testing.T) {
	rl := NewRateLimiter(1000, 100)
	for i := 0; i < 5; i++ {
		rl.RecordRequest("10.0.0.1")
	}
	if rl.CurrentRate() != 5 {
		t.Errorf("CurrentRate() = %d, want 5", rl.CurrentRate())
	}
}

// ─── IPReputation ─────────────────────────────────────────────────────────────

func TestIPReputation_AddAndCheck(t *testing.T) {
	rep := NewIPReputation()
	rep.AddMalicious("1.2.3.4", "5.6.7.8")

	if !rep.IsMalicious("1.2.3.4") {
		t.Error("expected 1.2.3.4 to be malicious")
	}
	if !rep.IsMalicious("5.6.7.8") {
		t.Error("expected 5.6.7.8 to be malicious")
	}
	if rep.IsMalicious("10.0.0.1") {
		t.Error("10.0.0.1 should not be malicious")
	}
}

func TestIPReputation_BogonDetection(t *testing.T) {
	rep := NewIPReputation()
	bogons := []string{
		"0.0.0.1",       // 0.0.0.0/8
		"100.64.0.1",    // 100.64.0.0/10
		"192.0.2.1",     // 192.0.2.0/24 (TEST-NET-1)
		"198.51.100.1",  // 198.51.100.0/24 (TEST-NET-2)
		"203.0.113.1",   // 203.0.113.0/24 (TEST-NET-3)
		"240.0.0.1",     // 240.0.0.0/4
	}
	for _, ip := range bogons {
		if !rep.IsMalicious(ip) {
			t.Errorf("expected bogon IP %s to be flagged", ip)
		}
	}
}

func TestIPReputation_ValidIPs(t *testing.T) {
	rep := NewIPReputation()
	valid := []string{"8.8.8.8", "1.1.1.1", "142.250.80.46"}
	for _, ip := range valid {
		if rep.IsMalicious(ip) {
			t.Errorf("valid IP %s should not be flagged", ip)
		}
	}
}

func TestIPReputation_InvalidIP(t *testing.T) {
	rep := NewIPReputation()
	if rep.IsMalicious("not-an-ip") {
		t.Error("invalid IP string should not be flagged")
	}
}

// ─── GeoFence ─────────────────────────────────────────────────────────────────

func TestGeoFence_BlockMode(t *testing.T) {
	gf := NewGeoFence(map[string]interface{}{
		"blocked_countries": "CN,RU,KP",
	})
	if !gf.IsBlockedCountry("CN") {
		t.Error("CN should be blocked")
	}
	if !gf.IsBlockedCountry("RU") {
		t.Error("RU should be blocked")
	}
	if gf.IsBlockedCountry("US") {
		t.Error("US should not be blocked")
	}
}

func TestGeoFence_AllowMode(t *testing.T) {
	gf := NewGeoFence(map[string]interface{}{
		"geo_mode":          "allow",
		"allowed_countries": "US,CA,GB",
	})
	if gf.IsBlockedCountry("US") {
		t.Error("US should be allowed")
	}
	if !gf.IsBlockedCountry("CN") {
		t.Error("CN should be blocked in allow mode")
	}
}

func TestGeoFence_EmptyCountry(t *testing.T) {
	gf := NewGeoFence(map[string]interface{}{
		"blocked_countries": "CN",
	})
	if gf.IsBlockedCountry("") {
		t.Error("empty country should not be blocked")
	}
}

func TestGeoFence_CaseInsensitive(t *testing.T) {
	gf := NewGeoFence(map[string]interface{}{
		"blocked_countries": "cn,ru",
	})
	if !gf.IsBlockedCountry("CN") {
		t.Error("CN should be blocked (case insensitive)")
	}
	if !gf.IsBlockedCountry("cn") {
		t.Error("cn should be blocked (case insensitive)")
	}
}

// ─── DNSTunnelDetector ────────────────────────────────────────────────────────

func TestDNSTunnelDetector_DGADetection(t *testing.T) {
	d := NewDNSTunnelDetector()
	// High entropy domain that looks like DGA
	result := d.Analyze("10.0.0.1", "xkjhqwerty8z9plm.evil.com", "A", 0)
	if !result.DGA {
		t.Error("expected DGA detection for high-entropy domain")
	}
}

func TestDNSTunnelDetector_NormalDomain(t *testing.T) {
	d := NewDNSTunnelDetector()
	result := d.Analyze("10.0.0.1", "www.google.com", "A", 0)
	if result.DGA {
		t.Error("google.com should not be flagged as DGA")
	}
	if result.Tunneling {
		t.Error("single query should not be flagged as tunneling")
	}
}

func TestDNSTunnelDetector_Exfiltration(t *testing.T) {
	d := NewDNSTunnelDetector()
	// Build up query volume
	for i := 0; i < 60; i++ {
		d.Analyze("10.0.0.1", "data.evil.com", "TXT", 600)
	}
	result := d.Analyze("10.0.0.1", "data.evil.com", "TXT", 600)
	if !result.Exfiltration {
		t.Error("expected exfiltration detection for high-volume TXT queries")
	}
}

// ─── C2Detector ───────────────────────────────────────────────────────────────

func TestC2Detector_SuspiciousPort(t *testing.T) {
	c := NewC2Detector()
	result := c.Analyze("10.0.0.1", "evil.com", 4444, "tcp", 100, 200, 1000)
	// Single connection won't trigger beaconing but should flag suspicious port
	if !result.SuspiciousPort {
		t.Error("expected SuspiciousPort for port 4444")
	}
}

func TestC2Detector_NonStandardPort(t *testing.T) {
	c := NewC2Detector()
	result := c.Analyze("10.0.0.1", "server.com", 9999, "http", 100, 200, 1000)
	if !result.SuspiciousPort {
		t.Error("expected SuspiciousPort for non-standard HTTP port 9999")
	}
}

func TestC2Detector_StandardPort(t *testing.T) {
	c := NewC2Detector()
	result := c.Analyze("10.0.0.1", "server.com", 443, "https", 100, 200, 1000)
	if result.SuspiciousPort {
		t.Error("port 443 for HTTPS should not be suspicious")
	}
}

// ─── LateralMovementMonitor ───────────────────────────────────────────────────

func TestLateralMovementMonitor_PassTheHash(t *testing.T) {
	lm := NewLateralMovementMonitor()
	// Need 3+ targets with NTLM auth
	lm.Analyze("10.0.0.1", "10.0.0.2", "admin", "pth", "ntlm", "", "", "", "smb_connection", "")
	lm.Analyze("10.0.0.1", "10.0.0.3", "admin", "pth", "ntlm", "", "", "", "smb_connection", "")
	result := lm.Analyze("10.0.0.1", "10.0.0.4", "admin", "pth", "ntlm", "", "", "", "smb_connection", "")
	if !result.PassTheHash {
		t.Error("expected PassTheHash with 3+ NTLM targets")
	}
	if result.TargetCount < 3 {
		t.Errorf("TargetCount = %d, want >= 3", result.TargetCount)
	}
}

func TestLateralMovementMonitor_PassTheTicket(t *testing.T) {
	lm := NewLateralMovementMonitor()
	result := lm.Analyze("10.0.0.1", "10.0.0.2", "admin", "pass_the_ticket", "kerberos", "TGS", "", "", "lateral_movement", "")
	if !result.PassTheTicket {
		t.Error("expected PassTheTicket detection")
	}
}

func TestLateralMovementMonitor_Kerberoasting(t *testing.T) {
	lm := NewLateralMovementMonitor()
	for i := 0; i < 5; i++ {
		lm.Analyze("10.0.0.1", "", "admin", "", "", "TGS", "rc4", "svc", "tgs_request", "")
	}
	result := lm.Analyze("10.0.0.1", "", "admin", "", "", "TGS", "rc4", "svc", "tgs_request", "")
	if !result.Kerberoasting {
		t.Error("expected Kerberoasting with 5+ RC4 TGS requests")
	}
}

func TestLateralMovementMonitor_GoldenTicket(t *testing.T) {
	lm := NewLateralMovementMonitor()
	result := lm.Analyze("10.0.0.1", "10.0.0.2", "admin", "golden_ticket", "kerberos", "TGT", "", "", "lateral_movement", "720h")
	if !result.GoldenTicket {
		t.Error("expected GoldenTicket detection")
	}
	if result.TicketLifetime != "720h" {
		t.Errorf("TicketLifetime = %q, want %q", result.TicketLifetime, "720h")
	}
}

func TestLateralMovementMonitor_DCSync(t *testing.T) {
	lm := NewLateralMovementMonitor()
	result := lm.Analyze("10.0.0.1", "10.0.0.2", "admin", "dcsync", "", "", "", "DRS_GetNCChanges", "lateral_movement", "")
	if !result.DCSync {
		t.Error("expected DCSync detection")
	}
}

func TestLateralMovementMonitor_LateralSpread(t *testing.T) {
	lm := NewLateralMovementMonitor()
	for i := 0; i < 5; i++ {
		lm.Analyze("10.0.0.1", "10.0.0."+string(rune('2'+i)), "admin", "", "", "", "", "", "smb_connection", "")
	}
	result := lm.Analyze("10.0.0.1", "10.0.0.99", "admin", "", "", "", "", "", "smb_connection", "")
	if !result.LateralSpread {
		t.Error("expected LateralSpread with 5+ targets")
	}
}

// ─── PortScanDetector ─────────────────────────────────────────────────────────

func TestPortScanDetector_HorizontalScan(t *testing.T) {
	ps := NewPortScanDetector()
	var result PortScanResult
	for i := 0; i < 15; i++ {
		result = ps.Record("10.0.0.1", "10.0.0."+string(rune('a'+i)), 22)
	}
	if !result.HorizontalScan {
		t.Error("expected HorizontalScan with 10+ hosts on same port")
	}
}

func TestPortScanDetector_VerticalScan(t *testing.T) {
	ps := NewPortScanDetector()
	var result PortScanResult
	for port := 1; port <= 25; port++ {
		result = ps.Record("10.0.0.1", "10.0.0.2", port)
	}
	if !result.VerticalScan {
		t.Error("expected VerticalScan with 20+ ports on same host")
	}
}

func TestPortScanDetector_NoScan(t *testing.T) {
	ps := NewPortScanDetector()
	result := ps.Record("10.0.0.1", "10.0.0.2", 80)
	if result.HorizontalScan || result.VerticalScan || result.StealthScan {
		t.Error("single connection should not trigger any scan detection")
	}
}

// ─── HandleEvent Integration ──────────────────────────────────────────────────

func TestGuardian_HandleEvent_MaliciousIP(t *testing.T) {
	cp := makeCapturingPipeline()
	g := startedModuleWithPipeline(t, cp)
	defer g.Stop()

	g.ipReputation.AddMalicious("1.2.3.4")

	ev := core.NewSecurityEvent("test", "generic_request", core.SeverityInfo, "request")
	ev.SourceIP = "1.2.3.4"

	g.HandleEvent(ev)

	titles := cp.alertTitles()
	found := false
	for _, title := range titles {
		if title == "Malicious IP Detected" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'Malicious IP Detected' alert, got: %v", titles)
	}
}

func TestGuardian_HandleEvent_GeoFence(t *testing.T) {
	cp := makeCapturingPipeline()
	g := New()
	cfg := core.DefaultConfig()
	cfg.Modules[ModuleName] = core.ModuleConfig{
		Enabled: true,
		Settings: map[string]interface{}{
			"blocked_countries": "CN",
		},
	}
	g.Start(context.Background(), nil, cp.pipeline, cfg)
	defer g.Stop()

	ev := core.NewSecurityEvent("test", "generic_request", core.SeverityInfo, "request")
	ev.SourceIP = "8.8.8.8"
	ev.Details["country"] = "CN"

	g.HandleEvent(ev)

	titles := cp.alertTitles()
	found := false
	for _, title := range titles {
		if title == "Geo-Fence Violation" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'Geo-Fence Violation' alert, got: %v", titles)
	}
}

func TestGuardian_HandleEvent_DNSQuery(t *testing.T) {
	cp := makeCapturingPipeline()
	g := startedModuleWithPipeline(t, cp)
	defer g.Stop()

	// Build up enough queries for exfiltration detection
	for i := 0; i < 60; i++ {
		ev := core.NewSecurityEvent("test", "dns_query", core.SeverityInfo, "dns query")
		ev.SourceIP = "10.0.0.5"
		ev.Details["domain"] = "data.evil.com"
		ev.Details["query_type"] = "TXT"
		ev.Details["response_size"] = 600
		g.HandleEvent(ev)
	}

	titles := cp.alertTitles()
	found := false
	for _, title := range titles {
		if title == "DNS Data Exfiltration Suspected" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected DNS exfiltration alert, got: %v", titles)
	}
}

func TestGuardian_HandleEvent_PortScan(t *testing.T) {
	cp := makeCapturingPipeline()
	g := startedModuleWithPipeline(t, cp)
	defer g.Stop()

	for port := 1; port <= 25; port++ {
		ev := core.NewSecurityEvent("test", "port_scan", core.SeverityInfo, "scan")
		ev.SourceIP = "10.0.0.99"
		ev.Details["dest_port"] = port
		ev.DestIP = "10.0.0.2"
		g.HandleEvent(ev)
	}

	titles := cp.alertTitles()
	found := false
	for _, title := range titles {
		if title == "Vertical Port Scan Detected" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'Vertical Port Scan Detected' alert, got: %v", titles)
	}
}

func TestGuardian_HandleEvent_LateralMovement(t *testing.T) {
	cp := makeCapturingPipeline()
	g := startedModuleWithPipeline(t, cp)
	defer g.Stop()

	for i := 0; i < 6; i++ {
		ev := core.NewSecurityEvent("test", "smb_connection", core.SeverityInfo, "smb")
		ev.SourceIP = "10.0.0.1"
		ev.DestIP = "10.0.0." + string(rune('2'+i))
		ev.Details["technique"] = "pth"
		ev.Details["auth_protocol"] = "ntlm"
		ev.Details["username"] = "admin"
		g.HandleEvent(ev)
	}

	if cp.count() == 0 {
		t.Error("expected lateral movement alerts")
	}
}

func TestGuardian_HandleEvent_Amplification(t *testing.T) {
	cp := makeCapturingPipeline()
	g := startedModuleWithPipeline(t, cp)
	defer g.Stop()

	ev := core.NewSecurityEvent("test", "amplification_attack", core.SeverityInfo, "amp attack")
	ev.SourceIP = "10.0.0.1"
	ev.Details["protocol"] = "DNS"
	ev.Details["amplification_factor"] = 60.0
	ev.Details["reflector_ip"] = "8.8.8.8"
	ev.Details["bytes_received"] = 1000000

	g.HandleEvent(ev)

	titles := cp.alertTitles()
	found := false
	for _, title := range titles {
		if title == "Amplification/Reflection Attack Detected" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected amplification attack alert, got: %v", titles)
	}
}

func TestGuardian_HandleEvent_EmptySourceIP(t *testing.T) {
	g := startedModule(t)
	defer g.Stop()

	ev := core.NewSecurityEvent("test", "generic_request", core.SeverityInfo, "request")
	ev.SourceIP = ""

	if err := g.HandleEvent(ev); err != nil {
		t.Fatalf("HandleEvent() should not error on empty source IP: %v", err)
	}
}

// ─── Helper Functions ─────────────────────────────────────────────────────────

func TestShannonEntropy(t *testing.T) {
	if e := shannonEntropy(""); e != 0 {
		t.Errorf("shannonEntropy('') = %f, want 0", e)
	}
	// "aaaa" = 0 entropy
	if e := shannonEntropy("aaaa"); e != 0 {
		t.Errorf("shannonEntropy('aaaa') = %f, want 0", e)
	}
	// "ab" repeated = 1 bit
	e := shannonEntropy("abababababababababab")
	if e < 0.9 || e > 1.1 {
		t.Errorf("shannonEntropy('abab...') = %f, want ~1.0", e)
	}
}

func TestConsonantRatio(t *testing.T) {
	if r := consonantRatio(""); r != 0 {
		t.Errorf("consonantRatio('') = %f, want 0", r)
	}
	// "bcdfg" = all consonants = 1.0
	if r := consonantRatio("bcdfg"); r != 1.0 {
		t.Errorf("consonantRatio('bcdfg') = %f, want 1.0", r)
	}
	// "aeiou" = all vowels = 0.0
	if r := consonantRatio("aeiou"); r != 0.0 {
		t.Errorf("consonantRatio('aeiou') = %f, want 0.0", r)
	}
}

func TestIsCommonDomain(t *testing.T) {
	if !isCommonDomain("google.com") {
		t.Error("google.com should be common")
	}
	if isCommonDomain("evil-malware.com") {
		t.Error("evil-malware.com should not be common")
	}
}

func TestIsNonStandardPort(t *testing.T) {
	if isNonStandardPort(443, "https") {
		t.Error("443/https should be standard")
	}
	if !isNonStandardPort(9999, "http") {
		t.Error("9999/http should be non-standard")
	}
	if isNonStandardPort(22, "ssh") {
		t.Error("22/ssh should be standard")
	}
	// Unknown protocol
	if isNonStandardPort(12345, "custom") {
		t.Error("unknown protocol should not be flagged as non-standard")
	}
}

func TestTruncateList(t *testing.T) {
	items := []string{"a", "b", "c", "d", "e"}
	result := truncateList(items, 3)
	if result != "a, b, c (+2 more)" {
		t.Errorf("truncateList = %q, want 'a, b, c (+2 more)'", result)
	}
	result = truncateList(items, 10)
	if result != "a, b, c, d, e" {
		t.Errorf("truncateList = %q, want 'a, b, c, d, e'", result)
	}
}

func TestAvgFloat(t *testing.T) {
	if avgFloat(nil) != 0 {
		t.Error("avgFloat(nil) should be 0")
	}
	if avgFloat([]int{10, 20, 30}) != 20 {
		t.Errorf("avgFloat([10,20,30]) = %f, want 20", avgFloat([]int{10, 20, 30}))
	}
}

func TestStdDevInt64(t *testing.T) {
	if stdDevInt64(nil) != 0 {
		t.Error("stdDevInt64(nil) should be 0")
	}
	if stdDevInt64([]int64{5}) != 0 {
		t.Error("stdDevInt64 of single element should be 0")
	}
	// All same values = 0 stddev
	if stdDevInt64([]int64{10, 10, 10}) != 0 {
		t.Error("stdDevInt64 of identical values should be 0")
	}
}

// ─── Compile-time interface check ─────────────────────────────────────────────

var _ core.Module = (*Guardian)(nil)

// Suppress unused import
var _ = time.Now

// ─── Dynamic IP Threat Scoring ────────────────────────────────────────────────

func TestIPReputation_RecordThreat_BelowThreshold(t *testing.T) {
	rep := NewIPReputation()
	// Single threat from one module should not auto-block
	blocked := rep.RecordThreat("10.0.0.1", "injection_shield", core.SeverityHigh)
	if blocked {
		t.Error("should not auto-block from single module")
	}
	if rep.IsMalicious("10.0.0.1") {
		t.Error("IP should not be malicious yet")
	}
}

func TestIPReputation_RecordThreat_AutoBlock(t *testing.T) {
	rep := NewIPReputation()
	// Accumulate 30 points from injection_shield (3x CRITICAL = 60 points)
	rep.RecordThreat("10.0.0.1", "injection_shield", core.SeverityCritical)
	rep.RecordThreat("10.0.0.1", "injection_shield", core.SeverityCritical)
	rep.RecordThreat("10.0.0.1", "injection_shield", core.SeverityCritical)

	// Still not blocked — only 1 module
	if rep.IsMalicious("10.0.0.1") {
		t.Error("should not auto-block from single module even with high points")
	}

	// Now add a second module — should trigger auto-block (60 points + 20 = 80, 2 modules)
	blocked := rep.RecordThreat("10.0.0.1", "auth_fortress", core.SeverityCritical)
	if !blocked {
		t.Error("expected auto-block after 2 modules and 80 points")
	}
	if !rep.IsMalicious("10.0.0.1") {
		t.Error("IP should be malicious after auto-block")
	}
}

func TestIPReputation_RecordThreat_DifferentIPs_Independent(t *testing.T) {
	rep := NewIPReputation()
	rep.RecordThreat("10.0.0.1", "injection_shield", core.SeverityCritical)
	rep.RecordThreat("10.0.0.1", "auth_fortress", core.SeverityCritical)
	rep.RecordThreat("10.0.0.1", "network_guardian", core.SeverityCritical)

	// IP1 should be blocked
	if !rep.IsMalicious("10.0.0.1") {
		t.Error("10.0.0.1 should be blocked")
	}

	// IP2 should NOT be blocked
	if rep.IsMalicious("10.0.0.2") {
		t.Error("10.0.0.2 should not be blocked")
	}
}

func TestIPReputation_GetThreatScore(t *testing.T) {
	rep := NewIPReputation()
	rep.RecordThreat("10.0.0.1", "injection_shield", core.SeverityHigh)   // 10 points
	rep.RecordThreat("10.0.0.1", "injection_shield", core.SeverityMedium) // 5 points
	rep.RecordThreat("10.0.0.1", "auth_fortress", core.SeverityLow)       // 2 points

	points, modules := rep.GetThreatScore("10.0.0.1")
	if points != 17 {
		t.Errorf("expected 17 points, got %d", points)
	}
	if modules != 2 {
		t.Errorf("expected 2 modules, got %d", modules)
	}
}

func TestIPReputation_GetThreatScore_Unknown(t *testing.T) {
	rep := NewIPReputation()
	points, modules := rep.GetThreatScore("unknown-ip")
	if points != 0 || modules != 0 {
		t.Errorf("expected 0/0 for unknown IP, got %d/%d", points, modules)
	}
}

func TestIPReputation_CleanupScores(t *testing.T) {
	rep := NewIPReputation()
	rep.RecordThreat("10.0.0.1", "injection_shield", core.SeverityHigh)

	// Verify score exists
	points, _ := rep.GetThreatScore("10.0.0.1")
	if points == 0 {
		t.Fatal("expected non-zero points before cleanup")
	}

	// Wait a tiny bit then cleanup with very short maxAge
	time.Sleep(2 * time.Millisecond)
	rep.CleanupScores(1 * time.Millisecond)

	points, _ = rep.GetThreatScore("10.0.0.1")
	if points != 0 {
		t.Errorf("expected 0 points after cleanup, got %d", points)
	}
}

func TestIPReputation_SeverityScoring(t *testing.T) {
	// Test each severity level's point value
	cases := []struct {
		severity core.Severity
		expected int
	}{
		{core.SeverityCritical, 20},
		{core.SeverityHigh, 10},
		{core.SeverityMedium, 5},
		{core.SeverityLow, 2},
		{core.SeverityInfo, 1},
	}

	for _, tc := range cases {
		rep2 := NewIPReputation()
		rep2.RecordThreat("test-ip", "test_module", tc.severity)
		points, _ := rep2.GetThreatScore("test-ip")
		if points != tc.expected {
			t.Errorf("severity %s: expected %d points, got %d", tc.severity.String(), tc.expected, points)
		}
	}
}

func TestGuardian_HandleEvent_DynamicIPScoring(t *testing.T) {
	cp := makeCapturingPipeline()
	g := startedModuleWithPipeline(t, cp)
	defer g.Stop()

	// Send multiple high-severity events from different modules to the same IP
	// The network guardian should score them and eventually auto-block
	for i := 0; i < 3; i++ {
		event := core.NewSecurityEvent("injection_shield", "injection_detected", core.SeverityCritical,
			"SQLi detected")
		event.SourceIP = "10.99.99.99"
		_ = g.HandleEvent(event)
	}

	// Now send from a second module to trigger the 2-module requirement
	event := core.NewSecurityEvent("auth_fortress", "brute_force", core.SeverityCritical,
		"Brute force detected")
	event.SourceIP = "10.99.99.99"
	_ = g.HandleEvent(event)

	// Check that a dynamic_ip_block alert was generated
	cp.mu.Lock()
	defer cp.mu.Unlock()
	found := false
	for _, a := range cp.alerts {
		if a.Type == "dynamic_ip_block" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected dynamic_ip_block alert after cross-module scoring")
	}
}
