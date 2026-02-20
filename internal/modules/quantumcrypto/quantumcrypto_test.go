package quantumcrypto

import (
	"context"
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

func (cp *capturingPipeline) alertTitles() []string {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	titles := make([]string, len(cp.alerts))
	for i, a := range cp.alerts {
		titles[i] = a.Title
	}
	return titles
}

func startedModule(t *testing.T) *Monitor {
	t.Helper()
	m := New()
	cfg := core.DefaultConfig()
	if err := m.Start(context.Background(), nil, nil, cfg); err != nil {
		t.Fatalf("Monitor.Start() error: %v", err)
	}
	return m
}

func startedModuleWithPipeline(t *testing.T, cp *capturingPipeline) *Monitor {
	t.Helper()
	m := New()
	cfg := core.DefaultConfig()
	if err := m.Start(context.Background(), nil, cp.pipeline, cfg); err != nil {
		t.Fatalf("Monitor.Start() error: %v", err)
	}
	return m
}

// ─── Module Interface ─────────────────────────────────────────────────────────

func TestMonitor_Name(t *testing.T) {
	m := New()
	if m.Name() != ModuleName {
		t.Errorf("Name() = %q, want %q", m.Name(), ModuleName)
	}
}

func TestMonitor_Description(t *testing.T) {
	m := New()
	if m.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

func TestMonitor_Start_Stop(t *testing.T) {
	m := New()
	cfg := core.DefaultConfig()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := m.Start(ctx, nil, nil, cfg); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	if m.inventory == nil {
		t.Error("inventory should be initialized")
	}
	if m.tlsAuditor == nil {
		t.Error("tlsAuditor should be initialized")
	}
	if m.hndlDet == nil {
		t.Error("hndlDet should be initialized")
	}
	if err := m.Stop(); err != nil {
		t.Fatalf("Stop() error: %v", err)
	}
}

// ─── TLSAuditor ───────────────────────────────────────────────────────────────

func TestTLSAuditor_WeakVersions(t *testing.T) {
	ta := NewTLSAuditor()
	weakVersions := []string{"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "ssl2", "ssl3", "tls1.0", "tls1.1"}
	for _, v := range weakVersions {
		findings := ta.Audit(v, "", "")
		found := false
		for _, f := range findings {
			if f.AlertType == "weak_tls_version" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected weak_tls_version for %q", v)
		}
	}
}

func TestTLSAuditor_StrongVersions(t *testing.T) {
	ta := NewTLSAuditor()
	strongVersions := []string{"TLSv1.2", "TLSv1.3"}
	for _, v := range strongVersions {
		findings := ta.Audit(v, "", "")
		for _, f := range findings {
			if f.AlertType == "weak_tls_version" {
				t.Errorf("TLS %s should not be flagged as weak", v)
			}
		}
	}
}

func TestTLSAuditor_WeakCiphers(t *testing.T) {
	ta := NewTLSAuditor()
	weakCiphers := []string{
		"TLS_RSA_WITH_RC4_128_SHA",
		"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
		"TLS_RSA_WITH_NULL_SHA",
		"TLS_RSA_EXPORT_WITH_RC4_40_MD5",
		"TLS_DH_anon_WITH_AES_128_CBC_SHA",
	}
	for _, c := range weakCiphers {
		findings := ta.Audit("TLSv1.2", c, "")
		found := false
		for _, f := range findings {
			if f.AlertType == "weak_cipher" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected weak_cipher for %q", c)
		}
	}
}

func TestTLSAuditor_StrongCipher(t *testing.T) {
	ta := NewTLSAuditor()
	findings := ta.Audit("TLSv1.3", "TLS_AES_256_GCM_SHA384", "X25519")
	for _, f := range findings {
		if f.AlertType == "weak_cipher" {
			t.Error("TLS_AES_256_GCM_SHA384 should not be flagged as weak")
		}
	}
}

func TestTLSAuditor_WeakKeyExchange(t *testing.T) {
	ta := NewTLSAuditor()
	weakKE := []string{"RSA", "DHE-1024", "DH-1024"}
	for _, ke := range weakKE {
		findings := ta.Audit("TLSv1.2", "TLS_AES_128_GCM_SHA256", ke)
		found := false
		for _, f := range findings {
			if f.AlertType == "weak_key_exchange" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected weak_key_exchange for %q", ke)
		}
	}
}

// ─── classifyQuantumVulnerability ─────────────────────────────────────────────

func TestClassifyQuantumVulnerability_Broken(t *testing.T) {
	broken := []string{"RSA", "ECDSA", "ECDH", "ECDHE", "DSA", "DH", "Ed25519", "X25519"}
	for _, algo := range broken {
		v := classifyQuantumVulnerability(algo, 2048)
		if !v.Vulnerable {
			t.Errorf("expected %s to be quantum-vulnerable", algo)
		}
		if v.Recommendation == "" {
			t.Errorf("expected recommendation for %s", algo)
		}
	}
}

func TestClassifyQuantumVulnerability_PQCSafe(t *testing.T) {
	safe := []string{"ML-KEM", "ML-DSA", "SLH-DSA", "Kyber", "Dilithium", "SPHINCS+", "Falcon"}
	for _, algo := range safe {
		v := classifyQuantumVulnerability(algo, 0)
		if v.Vulnerable {
			t.Errorf("%s should not be quantum-vulnerable", algo)
		}
	}
}

func TestClassifyQuantumVulnerability_SymmetricWeak(t *testing.T) {
	v := classifyQuantumVulnerability("AES", 128)
	if !v.Vulnerable {
		t.Error("AES-128 should be quantum-vulnerable (Grover's algorithm)")
	}
	if v.Severity != core.SeverityLow {
		t.Errorf("AES-128 severity = %v, want Low", v.Severity)
	}
}

func TestClassifyQuantumVulnerability_SymmetricStrong(t *testing.T) {
	v := classifyQuantumVulnerability("AES", 256)
	if v.Vulnerable {
		t.Error("AES-256 should be quantum-safe")
	}
}

func TestClassifyQuantumVulnerability_Unknown(t *testing.T) {
	v := classifyQuantumVulnerability("UnknownAlgo", 256)
	if v.Vulnerable {
		t.Error("unknown algorithm should not be flagged as vulnerable")
	}
}

// ─── isWeakKeySize ────────────────────────────────────────────────────────────

func TestIsWeakKeySize(t *testing.T) {
	tests := []struct {
		algo    string
		keySize int
		want    bool
	}{
		{"RSA", 1024, true},
		{"RSA", 2048, false},
		{"RSA", 4096, false},
		{"ECDSA", 128, true},
		{"ECDSA", 256, false},
		{"AES", 64, true},
		{"AES", 128, false},
		{"AES", 256, false},
		{"RSA", 0, false},  // zero key size = not weak
		{"RSA", -1, false}, // negative = not weak
	}
	for _, tc := range tests {
		got := isWeakKeySize(tc.algo, tc.keySize)
		if got != tc.want {
			t.Errorf("isWeakKeySize(%q, %d) = %v, want %v", tc.algo, tc.keySize, got, tc.want)
		}
	}
}

// ─── CryptoInventory ──────────────────────────────────────────────────────────

func TestCryptoInventory_RecordUsage(t *testing.T) {
	ci := NewCryptoInventory()
	ci.RecordUsage("encryption", "AES-256-GCM", "api-server")
	ci.RecordUsage("encryption", "AES-256-GCM", "api-server")
	ci.RecordUsage("encryption", "AES-256-GCM", "web-server")

	ci.mu.RLock()
	defer ci.mu.RUnlock()

	entry, ok := ci.entries["encryption:AES-256-GCM"]
	if !ok {
		t.Fatal("expected entry for encryption:AES-256-GCM")
	}
	if entry.UsageCount != 3 {
		t.Errorf("UsageCount = %d, want 3", entry.UsageCount)
	}
	if len(entry.Components) != 2 {
		t.Errorf("Components count = %d, want 2", len(entry.Components))
	}
}

// ─── HNDLDetector ─────────────────────────────────────────────────────────────

func TestHNDLDetector_BulkCapture(t *testing.T) {
	h := NewHNDLDetector()
	var result HNDLResult
	// Send 150 events with 5MB each = 750MB total
	for i := 0; i < 150; i++ {
		result = h.Analyze("10.0.0.1", "10.0.0.2", 5*1024*1024, "tls", "RSA_AES_128", "RSA", "mirror")
	}
	if !result.BulkCapture {
		t.Error("expected BulkCapture for >500MB and 100+ events")
	}
}

func TestHNDLDetector_HNDLSuspected(t *testing.T) {
	h := NewHNDLDetector()
	var result HNDLResult
	// Send traffic to many destinations with quantum-vulnerable ciphers
	for i := 0; i < 50; i++ {
		dest := "10.0.0." + string(rune('1'+i%26))
		result = h.Analyze("10.0.0.1", dest, 10*1024*1024, "tls", "ECDHE_RSA_AES_128", "ECDHE", "tap")
	}
	if !result.HNDLSuspected {
		t.Error("expected HNDLSuspected for high volume + quantum-vulnerable + broad targeting")
	}
}

func TestHNDLDetector_SmallTraffic(t *testing.T) {
	h := NewHNDLDetector()
	result := h.Analyze("10.0.0.1", "10.0.0.2", 1024, "tls", "AES_256_GCM", "X25519", "")
	if result.HNDLSuspected {
		t.Error("small traffic should not trigger HNDL")
	}
	if result.BulkCapture {
		t.Error("small traffic should not trigger BulkCapture")
	}
}

func TestHNDLDetector_CleanupLoop(t *testing.T) {
	h := NewHNDLDetector()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		h.CleanupLoop(ctx)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("CleanupLoop did not exit after context cancellation")
	}
}

// ─── formatBytes ──────────────────────────────────────────────────────────────

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		input int64
		want  string
	}{
		{0, "0 B"},
		{500, "500 B"},
		{1024, "1.0 KB"},
		{1024 * 1024, "1.0 MB"},
		{1024 * 1024 * 1024, "1.0 GB"},
	}
	for _, tc := range tests {
		got := formatBytes(tc.input)
		if got != tc.want {
			t.Errorf("formatBytes(%d) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

// ─── HandleEvent Integration ──────────────────────────────────────────────────

func TestMonitor_HandleEvent_WeakTLS(t *testing.T) {
	cp := makeCapturingPipeline()
	m := startedModuleWithPipeline(t, cp)
	defer m.Stop()

	ev := core.NewSecurityEvent("test", "tls_handshake", core.SeverityInfo, "TLS handshake")
	ev.Details["tls_version"] = "SSLv3"
	ev.Details["cipher_suite"] = "TLS_RSA_WITH_RC4_128_SHA"
	ev.Details["key_exchange"] = "RSA"
	ev.Details["server_name"] = "legacy.example.com"
	ev.SourceIP = "10.0.0.1"

	m.HandleEvent(ev)

	if cp.count() == 0 {
		t.Error("expected alerts for weak TLS configuration")
	}
	// Should have at least: weak version, weak cipher, weak key exchange
	if cp.count() < 3 {
		t.Errorf("expected at least 3 alerts, got %d", cp.count())
	}
}

func TestMonitor_HandleEvent_QuantumVulnerableCrypto(t *testing.T) {
	cp := makeCapturingPipeline()
	m := startedModuleWithPipeline(t, cp)
	defer m.Stop()

	ev := core.NewSecurityEvent("test", "crypto_usage", core.SeverityInfo, "crypto usage")
	ev.Details["algorithm"] = "RSA"
	ev.Details["key_size"] = 2048
	ev.Details["purpose"] = "encryption"
	ev.Details["component"] = "payment-service"
	ev.SourceIP = "10.0.0.1"

	m.HandleEvent(ev)

	titles := cp.alertTitles()
	found := false
	for _, title := range titles {
		if title == "Quantum-Vulnerable Cryptography Detected" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected quantum-vulnerable crypto alert, got: %v", titles)
	}
}

func TestMonitor_HandleEvent_WeakKeySize(t *testing.T) {
	cp := makeCapturingPipeline()
	m := startedModuleWithPipeline(t, cp)
	defer m.Stop()

	ev := core.NewSecurityEvent("test", "crypto_usage", core.SeverityInfo, "crypto usage")
	ev.Details["algorithm"] = "RSA"
	ev.Details["key_size"] = 1024
	ev.Details["purpose"] = "signing"
	ev.Details["component"] = "auth-service"
	ev.SourceIP = "10.0.0.1"

	m.HandleEvent(ev)

	titles := cp.alertTitles()
	foundWeak := false
	for _, title := range titles {
		if title == "Weak Cryptographic Key Size" {
			foundWeak = true
			break
		}
	}
	if !foundWeak {
		t.Errorf("expected weak key size alert, got: %v", titles)
	}
}

func TestMonitor_HandleEvent_CertExpiry(t *testing.T) {
	cp := makeCapturingPipeline()
	m := startedModuleWithPipeline(t, cp)
	defer m.Stop()

	ev := core.NewSecurityEvent("test", "cert_expiry", core.SeverityInfo, "cert expiry")
	ev.Details["domain"] = "api.example.com"
	ev.Details["days_until_expiry"] = 3
	ev.Details["key_algorithm"] = "RSA"
	ev.Details["key_size"] = 2048
	ev.Details["issuer"] = "Let's Encrypt"
	ev.SourceIP = "10.0.0.1"

	m.HandleEvent(ev)

	titles := cp.alertTitles()
	found := false
	for _, title := range titles {
		if title == "Certificate Expiring Soon" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected cert expiry alert, got: %v", titles)
	}
}

func TestMonitor_HandleEvent_CryptoInventoryScan(t *testing.T) {
	cp := makeCapturingPipeline()
	m := startedModuleWithPipeline(t, cp)
	defer m.Stop()

	ev := core.NewSecurityEvent("test", "crypto_scan", core.SeverityInfo, "crypto scan")
	ev.Details["total_algorithms"] = 20
	ev.Details["vulnerable_count"] = 15
	ev.Details["pqc_ready_count"] = 2
	ev.SourceIP = "10.0.0.1"

	m.HandleEvent(ev)

	titles := cp.alertTitles()
	found := false
	for _, title := range titles {
		if title == "Quantum-Vulnerable Crypto Inventory Report" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected crypto inventory report alert, got: %v", titles)
	}
}

func TestMonitor_HandleEvent_HNDL(t *testing.T) {
	cp := makeCapturingPipeline()
	m := startedModuleWithPipeline(t, cp)
	defer m.Stop()

	// Send enough traffic to trigger bulk capture
	for i := 0; i < 150; i++ {
		ev := core.NewSecurityEvent("test", "traffic_capture", core.SeverityInfo, "capture")
		ev.SourceIP = "10.0.0.1"
		ev.DestIP = "10.0.0.2"
		ev.Details["bytes_transferred"] = 5 * 1024 * 1024
		ev.Details["cipher_suite"] = "ECDHE_RSA_AES_128"
		ev.Details["key_exchange"] = "ECDHE"
		ev.Details["capture_type"] = "mirror"
		m.HandleEvent(ev)
	}

	if cp.count() == 0 {
		t.Error("expected HNDL/bulk capture alerts")
	}
}

func TestMonitor_HandleEvent_EmptyAlgorithm(t *testing.T) {
	m := startedModule(t)
	defer m.Stop()

	ev := core.NewSecurityEvent("test", "crypto_usage", core.SeverityInfo, "crypto usage")
	ev.Details["algorithm"] = ""
	ev.SourceIP = "10.0.0.1"

	if err := m.HandleEvent(ev); err != nil {
		t.Fatalf("HandleEvent() should not error on empty algorithm: %v", err)
	}
}

// ─── Compile-time interface check ─────────────────────────────────────────────

var _ core.Module = (*Monitor)(nil)
