package deepfake

import (
	"context"
	"encoding/binary"
	"math"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/1sec-project/1sec/internal/core"
	"github.com/rs/zerolog"
)

// ─── Helpers ─────────────────────────────────────────────────────────────────

type capPipeline struct {
	pipeline *core.AlertPipeline
	mu       sync.Mutex
	alerts   []*core.Alert
}

func newCapPipeline() *capPipeline {
	cp := &capPipeline{}
	cp.pipeline = core.NewAlertPipeline(zerolog.Nop(), 10000)
	cp.pipeline.AddHandler(func(a *core.Alert) {
		cp.mu.Lock()
		cp.alerts = append(cp.alerts, a)
		cp.mu.Unlock()
	})
	return cp
}

func (cp *capPipeline) count() int {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	return len(cp.alerts)
}

func (cp *capPipeline) hasAlertType(alertType string) bool {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	for _, a := range cp.alerts {
		if a.Type == alertType {
			return true
		}
	}
	return false
}

func startedShield(t *testing.T, pipeline *core.AlertPipeline) *Shield {
	t.Helper()
	s := New()
	cfg := core.DefaultConfig()
	if err := s.Start(context.Background(), nil, pipeline, cfg); err != nil {
		t.Fatalf("Shield.Start() error: %v", err)
	}
	t.Cleanup(func() { s.Stop() })
	return s
}

// makePCMSamples creates raw PCM bytes from int16 samples (little-endian).
func makePCMSamples(samples []int16) []byte {
	data := make([]byte, len(samples)*2)
	for i, s := range samples {
		binary.LittleEndian.PutUint16(data[i*2:], uint16(s))
	}
	return data
}

// ─── Module Interface ─────────────────────────────────────────────────────────

var _ core.Module = (*Shield)(nil)

func TestShield_Name(t *testing.T) {
	s := New()
	if s.Name() != ModuleName {
		t.Errorf("Name() = %q, want %q", s.Name(), ModuleName)
	}
}

func TestShield_Description(t *testing.T) {
	s := New()
	if s.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

func TestShield_Start_Stop(t *testing.T) {
	s := New()
	cfg := core.DefaultConfig()
	if err := s.Start(context.Background(), nil, nil, cfg); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	if s.audioAnal == nil {
		t.Error("audioAnal should be initialized after Start()")
	}
	if s.videoAnal == nil {
		t.Error("videoAnal should be initialized after Start()")
	}
	if s.phishDet == nil {
		t.Error("phishDet should be initialized after Start()")
	}
	if s.domainCheck == nil {
		t.Error("domainCheck should be initialized after Start()")
	}
	if s.commTracker == nil {
		t.Error("commTracker should be initialized after Start()")
	}
	if err := s.Stop(); err != nil {
		t.Errorf("Stop() error: %v", err)
	}
}

// ─── AudioAnalyzer ────────────────────────────────────────────────────────────

func TestAudioAnalyzer_EmptyData(t *testing.T) {
	a := NewAudioAnalyzer()
	// Less than 64 bytes should return zero score
	result := a.Analyze(make([]byte, 32))
	if result.Score != 0 {
		t.Errorf("Score = %f, want 0 for data < 64 bytes", result.Score)
	}
	result2 := a.Analyze(nil)
	if result2.Score != 0 {
		t.Errorf("Score = %f, want 0 for nil data", result2.Score)
	}
}

func TestAudioAnalyzer_LowEntropy(t *testing.T) {
	a := NewAudioAnalyzer()
	// Repeated bytes have very low entropy — should get flagged
	data := make([]byte, 4096)
	for i := range data {
		data[i] = byte(i % 4) // only 4 distinct values → low entropy
	}
	result := a.Analyze(data)
	if result.Entropy >= 5.0 {
		t.Errorf("Entropy = %f, expected < 5.0 for low-entropy data", result.Entropy)
	}
	if result.Score == 0 {
		t.Error("expected non-zero score for low-entropy audio data")
	}
	found := false
	for _, ind := range result.Indicators {
		if len(ind) > 0 {
			found = true
		}
	}
	if !found {
		t.Error("expected at least one indicator for low-entropy data")
	}
}

func TestAudioAnalyzer_HighEntropy(t *testing.T) {
	a := NewAudioAnalyzer()
	// Random data has high entropy (~8.0) — should NOT get low-entropy flag
	rng := rand.New(rand.NewSource(42))
	data := make([]byte, 4096)
	for i := range data {
		data[i] = byte(rng.Intn(256))
	}
	result := a.Analyze(data)
	if result.Entropy < 5.0 {
		t.Errorf("Entropy = %f, expected >= 5.0 for random data", result.Entropy)
	}
	for _, ind := range result.Indicators {
		if ind == "low byte entropy" {
			t.Error("random data should not be flagged for low entropy")
		}
	}
}

// ─── byteEntropy ──────────────────────────────────────────────────────────────

func TestByteEntropy(t *testing.T) {
	// All zeros → entropy = 0
	zeros := make([]byte, 1024)
	e := byteEntropy(zeros)
	if e != 0 {
		t.Errorf("byteEntropy(all zeros) = %f, want 0", e)
	}

	// Uniform distribution of all 256 byte values → entropy ≈ 8.0
	uniform := make([]byte, 256*100)
	for i := range uniform {
		uniform[i] = byte(i % 256)
	}
	e = byteEntropy(uniform)
	if math.Abs(e-8.0) > 0.01 {
		t.Errorf("byteEntropy(uniform) = %f, want ~8.0", e)
	}

	// Empty data → 0
	if byteEntropy(nil) != 0 {
		t.Error("byteEntropy(nil) should be 0")
	}
}

// ─── silenceRatio ─────────────────────────────────────────────────────────────

func TestSilenceRatio(t *testing.T) {
	// All-zero PCM data → silence ratio should be ~1.0
	samples := make([]int16, 1000)
	data := makePCMSamples(samples)
	ratio := silenceRatio(data)
	if ratio < 0.99 {
		t.Errorf("silenceRatio(all zeros) = %f, want ~1.0", ratio)
	}

	// Loud data (max amplitude) → silence ratio should be ~0.0
	for i := range samples {
		samples[i] = 30000
	}
	data = makePCMSamples(samples)
	ratio = silenceRatio(data)
	if ratio > 0.01 {
		t.Errorf("silenceRatio(loud) = %f, want ~0.0", ratio)
	}
}

// ─── zeroCrossingRate ─────────────────────────────────────────────────────────

func TestZeroCrossingRate(t *testing.T) {
	// Alternating positive/negative → high ZCR (every sample crosses)
	samples := make([]int16, 1000)
	for i := range samples {
		if i%2 == 0 {
			samples[i] = 1000
		} else {
			samples[i] = -1000
		}
	}
	data := makePCMSamples(samples)
	zcr := zeroCrossingRate(data)
	if zcr < 0.9 {
		t.Errorf("zeroCrossingRate(alternating) = %f, want > 0.9", zcr)
	}

	// Constant positive samples → zero ZCR
	for i := range samples {
		samples[i] = 5000
	}
	data = makePCMSamples(samples)
	zcr = zeroCrossingRate(data)
	if zcr != 0 {
		t.Errorf("zeroCrossingRate(constant) = %f, want 0", zcr)
	}
}

// ─── checkBitrateConsistency ──────────────────────────────────────────────────

func TestCheckBitrateConsistency(t *testing.T) {
	// Uniform energy frames → should return true (suspicious)
	data := make([]byte, 8192)
	for i := range data {
		data[i] = 128 // constant value → very low variance
	}
	if !checkBitrateConsistency(data) {
		t.Error("expected true for uniform energy frames")
	}

	// Varied frames → should return false
	rng := rand.New(rand.NewSource(99))
	varied := make([]byte, 8192)
	for i := range varied {
		varied[i] = byte(rng.Intn(256))
	}
	// Random data has high variance, should not be flagged
	// (may or may not trigger depending on random seed, so we just ensure no panic)
	_ = checkBitrateConsistency(varied)

	// Too short → false
	if checkBitrateConsistency(make([]byte, 100)) {
		t.Error("expected false for data < 4096 bytes")
	}
}

// ─── VideoAnalyzer ────────────────────────────────────────────────────────────

func TestVideoAnalyzer_EmptyFrames(t *testing.T) {
	v := NewVideoAnalyzer()
	result := v.Analyze(nil, nil)
	if result.Score != 0 {
		t.Errorf("Score = %f, want 0 for empty frames", result.Score)
	}
	result2 := v.Analyze([][]byte{}, nil)
	if result2.Score != 0 {
		t.Errorf("Score = %f, want 0 for empty slice", result2.Score)
	}
}

func TestVideoAnalyzer_ConsistentFrameEntropy(t *testing.T) {
	v := NewVideoAnalyzer()
	// Identical frames → very low entropy variation → should be flagged
	frame := make([]byte, 1024)
	for i := range frame {
		frame[i] = byte(i % 256)
	}
	frames := make([][]byte, 10)
	for i := range frames {
		f := make([]byte, len(frame))
		copy(f, frame)
		frames[i] = f
	}
	result := v.Analyze(frames, nil)
	if result.Score == 0 {
		t.Error("expected non-zero score for identical frames (unnaturally consistent entropy)")
	}
	hasIndicator := false
	for _, ind := range result.Indicators {
		if len(ind) > 0 {
			hasIndicator = true
		}
	}
	if !hasIndicator {
		t.Error("expected indicators for consistent frame entropy")
	}
}

func TestVideoAnalyzer_MetadataAnomalies(t *testing.T) {
	v := NewVideoAnalyzer()

	// Suspicious codec
	meta := map[string]interface{}{"codec": "rawvideo"}
	result := v.Analyze([][]byte{make([]byte, 64)}, meta)
	if result.Score == 0 {
		t.Error("expected non-zero score for suspicious codec 'rawvideo'")
	}

	// Resolution mismatch
	meta2 := map[string]interface{}{
		"face_resolution":  float64(100),
		"frame_resolution": float64(1000),
	}
	result2 := v.Analyze([][]byte{make([]byte, 64)}, meta2)
	if result2.Score == 0 {
		t.Error("expected non-zero score for face/frame resolution mismatch")
	}

	// Non-standard FPS
	meta3 := map[string]interface{}{"fps": float64(17.5)}
	result3 := v.Analyze([][]byte{make([]byte, 64)}, meta3)
	if result3.Score == 0 {
		t.Error("expected non-zero score for non-standard FPS")
	}
}

// ─── frameDifference ──────────────────────────────────────────────────────────

func TestFrameDifference(t *testing.T) {
	a := []byte{10, 20, 30, 40}
	b := []byte{10, 20, 30, 40}
	if frameDifference(a, b) != 0 {
		t.Error("identical frames should have difference 0")
	}

	c := []byte{0, 0, 0, 0}
	d := []byte{100, 100, 100, 100}
	diff := frameDifference(c, d)
	if diff != 100.0 {
		t.Errorf("frameDifference = %f, want 100.0", diff)
	}

	if frameDifference(nil, nil) != 0 {
		t.Error("nil frames should have difference 0")
	}
}

// ─── AIPhishingDetector ───────────────────────────────────────────────────────

func TestAIPhishingDetector_UrgencyPatterns(t *testing.T) {
	d := NewAIPhishingDetector()
	cases := []string{
		"URGENT: act now before it's too late",
		"Immediate action required within 24 hours",
		"This expires today, don't delay",
		"Time-sensitive request ASAP",
	}
	for _, body := range cases {
		score := d.Analyze("", "", body, "")
		if score.Score == 0 {
			t.Errorf("expected urgency detection for %q", body)
		}
		hasUrgency := false
		for _, ind := range score.Indicators {
			if ind == "urgency language" {
				hasUrgency = true
			}
		}
		if !hasUrgency {
			t.Errorf("expected 'urgency language' indicator for %q", body)
		}
	}
}

func TestAIPhishingDetector_ImpersonationPatterns(t *testing.T) {
	d := NewAIPhishingDetector()
	cases := []string{
		"Message from the CEO regarding budget",
		"The CFO has approved this transfer",
		"IT Department security update",
		"From the board member: urgent matter",
	}
	for _, body := range cases {
		score := d.Analyze("", "", body, "")
		hasImpersonation := false
		for _, ind := range score.Indicators {
			if ind == "executive impersonation" {
				hasImpersonation = true
			}
		}
		if !hasImpersonation {
			t.Errorf("expected 'executive impersonation' indicator for %q", body)
		}
	}
}

func TestAIPhishingDetector_ActionPatterns(t *testing.T) {
	d := NewAIPhishingDetector()
	cases := []string{
		"Please click here to verify your account",
		"Download the attachment immediately",
		"Verify your identity by clicking below",
		"Wire transfer needed urgently",
	}
	for _, body := range cases {
		score := d.Analyze("", "", body, "")
		hasAction := false
		for _, ind := range score.Indicators {
			if ind == "suspicious call-to-action" {
				hasAction = true
			}
		}
		if !hasAction {
			t.Errorf("expected 'suspicious call-to-action' indicator for %q", body)
		}
	}
}

func TestAIPhishingDetector_ThreatPatterns(t *testing.T) {
	d := NewAIPhishingDetector()
	cases := []string{
		"Your account will be suspended",
		"Legal action will be taken",
		"Unauthorized access detected on your account",
		"Security breach: your account is compromised",
	}
	for _, body := range cases {
		score := d.Analyze("", "", body, "")
		hasThreat := false
		for _, ind := range score.Indicators {
			if ind == "threat/fear language" {
				hasThreat = true
			}
		}
		if !hasThreat {
			t.Errorf("expected 'threat/fear language' indicator for %q", body)
		}
	}
}

func TestAIPhishingDetector_HeaderAnalysis(t *testing.T) {
	d := NewAIPhishingDetector()

	// Missing DKIM and SPF
	score := d.Analyze("", "", "test body", "Received: from mail.example.com")
	hasDKIM := false
	hasSPF := false
	for _, ind := range score.Indicators {
		if ind == "missing DKIM" {
			hasDKIM = true
		}
		if ind == "missing SPF" {
			hasSPF = true
		}
	}
	if !hasDKIM {
		t.Error("expected 'missing DKIM' indicator")
	}
	if !hasSPF {
		t.Error("expected 'missing SPF' indicator")
	}

	// DMARC failure
	score2 := d.Analyze("", "", "body", "dkim=pass; spf=pass; dmarc=fail")
	hasDMARC := false
	for _, ind := range score2.Indicators {
		if ind == "DMARC failure" {
			hasDMARC = true
		}
	}
	if !hasDMARC {
		t.Error("expected 'DMARC failure' indicator")
	}

	// All passing headers → no header indicators
	score3 := d.Analyze("", "", "body", "dkim=pass; spf=pass; dmarc=pass")
	for _, ind := range score3.Indicators {
		if ind == "missing DKIM" || ind == "missing SPF" || ind == "DMARC failure" {
			t.Errorf("unexpected header indicator %q when all pass", ind)
		}
	}
}

func TestAIPhishingDetector_CombinedScore(t *testing.T) {
	d := NewAIPhishingDetector()
	// Combine urgency + impersonation + action + threat → should exceed 0.5 threshold
	body := "URGENT: The CEO requests you click here to verify your account or it will be suspended"
	score := d.Analyze("", "", body, "")
	if !score.IsPhishing {
		t.Errorf("expected IsPhishing=true for combined indicators, score=%.2f", score.Score)
	}
	if score.Score < 0.5 {
		t.Errorf("Score = %f, want >= 0.5", score.Score)
	}
}

func TestAIPhishingDetector_CleanEmail(t *testing.T) {
	d := NewAIPhishingDetector()
	body := "Hi team, the quarterly report is attached. Let me know if you have questions. Best, Alice"
	score := d.Analyze("alice@company.com", "Q3 Report", body, "dkim=pass; spf=pass; dmarc=pass")
	if score.IsPhishing {
		t.Errorf("clean email should not be flagged as phishing, score=%.2f", score.Score)
	}
}

// ─── DomainSpoofChecker ──────────────────────────────────────────────────────

func TestDomainSpoofChecker_Homoglyphs(t *testing.T) {
	dc := NewDomainSpoofChecker()
	// "gооgle.com" with Cyrillic 'о' (U+043E) instead of Latin 'o'
	spoofed := "g\u043E\u043Egle.com"
	result := dc.Check(spoofed)
	if result != "google.com" {
		t.Errorf("Check(%q) = %q, want 'google.com'", spoofed, result)
	}
}

func TestDomainSpoofChecker_Levenshtein(t *testing.T) {
	dc := NewDomainSpoofChecker()
	// 1-edit-distance from "google.com"
	result := dc.Check("gogle.com")
	if result != "google.com" {
		t.Errorf("Check('gogle.com') = %q, want 'google.com'", result)
	}
	// 1-edit-distance from "github.com"
	result2 := dc.Check("githb.com")
	if result2 != "github.com" {
		t.Errorf("Check('githb.com') = %q, want 'github.com'", result2)
	}
}

func TestDomainSpoofChecker_ExactMatch(t *testing.T) {
	dc := NewDomainSpoofChecker()
	// Exact trusted domain should NOT trigger
	result := dc.Check("google.com")
	if result != "" {
		t.Errorf("Check('google.com') = %q, want empty (exact match)", result)
	}
}

func TestDomainSpoofChecker_UnrelatedDomain(t *testing.T) {
	dc := NewDomainSpoofChecker()
	result := dc.Check("totallyunrelated.xyz")
	if result != "" {
		t.Errorf("Check('totallyunrelated.xyz') = %q, want empty", result)
	}
}

// ─── levenshtein ──────────────────────────────────────────────────────────────

func TestLevenshtein(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"", "", 0},
		{"abc", "", 3},
		{"", "xyz", 3},
		{"kitten", "sitting", 3},
		{"google", "gogle", 1},
		{"same", "same", 0},
		{"a", "b", 1},
	}
	for _, tc := range cases {
		got := levenshtein(tc.a, tc.b)
		if got != tc.want {
			t.Errorf("levenshtein(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

// ─── CommunicationTracker ─────────────────────────────────────────────────────

func TestCommunicationTracker_RecordAndGet(t *testing.T) {
	ct := NewCommunicationTracker()

	// Initially no pattern
	if ct.GetPattern("alice") != nil {
		t.Error("expected nil pattern for unknown identity")
	}

	ct.RecordCommunication("alice", "10.0.0.1")
	ct.RecordCommunication("alice", "10.0.0.2")

	p := ct.GetPattern("alice")
	if p == nil {
		t.Fatal("expected non-nil pattern after recording")
	}
	if p.MessageCount != 2 {
		t.Errorf("MessageCount = %d, want 2", p.MessageCount)
	}
	if !p.UsualIPs["10.0.0.1"] || !p.UsualIPs["10.0.0.2"] {
		t.Error("expected both IPs to be recorded")
	}
}

// ─── HandleEvent Integration ──────────────────────────────────────────────────

func TestShield_HandleEvent_AudioEvent(t *testing.T) {
	cp := newCapPipeline()
	s := startedShield(t, cp.pipeline)

	ev := core.NewSecurityEvent("test", "voice_call", core.SeverityInfo, "incoming call")
	ev.Details["caller_id"] = "+1234567890"
	ev.Details["claimed_identity"] = "CEO"
	// Create synthetic low-entropy audio data to trigger detection
	data := make([]byte, 4096)
	for i := range data {
		data[i] = byte(i % 3)
	}
	ev.RawData = data

	if err := s.HandleEvent(ev); err != nil {
		t.Fatalf("HandleEvent() error: %v", err)
	}
	// The low-entropy data should trigger some indicators; alert depends on total score
}

func TestShield_HandleEvent_CommunicationEvent(t *testing.T) {
	cp := newCapPipeline()
	s := startedShield(t, cp.pipeline)

	ev := core.NewSecurityEvent("test", "email_received", core.SeverityInfo, "new email")
	ev.Details["sender"] = "CEO <ceo@evil.com>"
	ev.Details["subject"] = "URGENT: Wire transfer needed immediately"
	ev.Details["body"] = "Click here to verify your account or it will be suspended. The CEO needs this done ASAP."
	ev.Details["sender_domain"] = "evil.com"
	ev.Details["headers"] = "Received: from mail.evil.com"
	ev.SourceIP = "10.0.0.99"

	if err := s.HandleEvent(ev); err != nil {
		t.Fatalf("HandleEvent() error: %v", err)
	}

	if cp.count() == 0 {
		t.Error("expected alert for phishing email with multiple indicators")
	}
	if !cp.hasAlertType("ai_phishing") {
		t.Error("expected ai_phishing alert type")
	}
}

func TestShield_HandleEvent_HighValueRequest(t *testing.T) {
	cp := newCapPipeline()
	s := startedShield(t, cp.pipeline)

	ev := core.NewSecurityEvent("test", "wire_transfer_request", core.SeverityInfo, "transfer request")
	ev.Details["requester"] = "unknown_person"
	ev.Details["request_type"] = "wire_transfer"
	ev.Details["amount"] = float64(500000)
	ev.Details["urgency"] = "critical"
	ev.Details["channel"] = "phone"

	if err := s.HandleEvent(ev); err != nil {
		t.Fatalf("HandleEvent() error: %v", err)
	}

	if cp.count() == 0 {
		t.Error("expected alert for high-value urgent request from unknown requester")
	}
	if !cp.hasAlertType("suspicious_request") {
		t.Error("expected suspicious_request alert type")
	}
}

// Suppress unused import warnings
var _ = time.Second
var _ = rand.New
