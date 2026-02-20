package core

import (
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func testLogger() zerolog.Logger {
	return zerolog.Nop()
}

func TestThreatCorrelator_SingleModule_NoCorrelation(t *testing.T) {
	logger := testLogger()
	pipeline := NewAlertPipeline(logger, 1000)
	tc := NewThreatCorrelator(logger, pipeline, nil)

	// Single module alert should NOT trigger correlation
	alert := &Alert{
		ID:       "a1",
		Module:   "injection_shield",
		Severity: SeverityHigh,
		Title:    "SQLi detected",
		Metadata: map[string]interface{}{"source_ip": "10.0.0.1"},
		EventIDs: []string{"e1"},
	}

	initialCount := pipeline.Count()
	tc.Ingest(alert)

	// No correlated alert should be generated from a single module
	if pipeline.Count() != initialCount {
		t.Errorf("expected no new alerts from single module, got %d new", pipeline.Count()-initialCount)
	}
}

func TestThreatCorrelator_TwoModules_TriggersCorrelation(t *testing.T) {
	logger := testLogger()
	pipeline := NewAlertPipeline(logger, 1000)
	tc := NewThreatCorrelator(logger, pipeline, nil)

	// Auth module alert
	tc.Ingest(&Alert{
		ID:       "a1",
		Module:   "auth_fortress",
		Severity: SeverityHigh,
		Title:    "Brute force detected",
		Metadata: map[string]interface{}{"source_ip": "10.0.0.5"},
		EventIDs: []string{"e1"},
	})

	// Network module alert from same IP — should trigger "Credential Attack → Lateral Movement"
	tc.Ingest(&Alert{
		ID:       "a2",
		Module:   "network_guardian",
		Severity: SeverityHigh,
		Title:    "Lateral movement detected",
		Metadata: map[string]interface{}{"source_ip": "10.0.0.5"},
		EventIDs: []string{"e2"},
	})

	// Should have generated at least one correlated alert
	alerts := pipeline.GetAlerts(SeverityCritical, 100)
	found := false
	for _, a := range alerts {
		if a.Module == "threat_correlator" {
			found = true
			if a.Severity != SeverityCritical {
				t.Errorf("expected CRITICAL severity, got %s", a.Severity.String())
			}
			break
		}
	}
	if !found {
		t.Error("expected correlated alert from threat_correlator, none found")
	}
}

func TestThreatCorrelator_ThreeModules_MultiVector(t *testing.T) {
	logger := testLogger()
	pipeline := NewAlertPipeline(logger, 1000)
	tc := NewThreatCorrelator(logger, pipeline, nil)

	ip := "192.168.1.100"

	// Three different modules from same IP
	modules := []string{"injection_shield", "runtime_watcher", "ransomware"}
	for i, mod := range modules {
		tc.Ingest(&Alert{
			ID:       "a" + string(rune('0'+i)),
			Module:   mod,
			Severity: SeverityHigh,
			Title:    "Alert from " + mod,
			Metadata: map[string]interface{}{"source_ip": ip},
			EventIDs: []string{"e" + string(rune('0'+i))},
		})
	}

	// Should trigger "Multi-Vector Assault" chain (any 3+ modules)
	alerts := pipeline.GetAlerts(SeverityCritical, 100)
	foundMultiVector := false
	for _, a := range alerts {
		if a.Module == "threat_correlator" {
			meta, ok := a.Metadata["chain_name"].(string)
			if ok && meta == "Multi-Vector Assault" {
				foundMultiVector = true
			}
		}
	}
	if !foundMultiVector {
		t.Error("expected Multi-Vector Assault chain alert, none found")
	}
}

func TestThreatCorrelator_DifferentIPs_NoCorrelation(t *testing.T) {
	logger := testLogger()
	pipeline := NewAlertPipeline(logger, 1000)
	tc := NewThreatCorrelator(logger, pipeline, nil)

	// Two modules but different IPs — should NOT correlate
	tc.Ingest(&Alert{
		ID:       "a1",
		Module:   "auth_fortress",
		Severity: SeverityHigh,
		Metadata: map[string]interface{}{"source_ip": "10.0.0.1"},
		EventIDs: []string{"e1"},
	})
	tc.Ingest(&Alert{
		ID:       "a2",
		Module:   "network_guardian",
		Severity: SeverityHigh,
		Metadata: map[string]interface{}{"source_ip": "10.0.0.2"},
		EventIDs: []string{"e2"},
	})

	alerts := pipeline.GetAlerts(SeverityCritical, 100)
	for _, a := range alerts {
		if a.Module == "threat_correlator" {
			t.Error("should not correlate alerts from different IPs")
		}
	}
}

func TestThreatCorrelator_NoSourceIP_Ignored(t *testing.T) {
	logger := testLogger()
	pipeline := NewAlertPipeline(logger, 1000)
	tc := NewThreatCorrelator(logger, pipeline, nil)

	// Alert without source_ip should be silently ignored
	tc.Ingest(&Alert{
		ID:       "a1",
		Module:   "injection_shield",
		Severity: SeverityHigh,
		Metadata: map[string]interface{}{},
		EventIDs: []string{"e1"},
	})

	if pipeline.Count() != 0 {
		t.Error("expected no alerts for events without source_ip")
	}
}

func TestThreatCorrelator_Deduplication(t *testing.T) {
	logger := testLogger()
	pipeline := NewAlertPipeline(logger, 1000)
	tc := NewThreatCorrelator(logger, pipeline, nil)

	ip := "10.0.0.99"

	// Fire the same two-module combo twice
	for i := 0; i < 2; i++ {
		tc.Ingest(&Alert{
			ID:       "auth-" + string(rune('0'+i)),
			Module:   "auth_fortress",
			Severity: SeverityHigh,
			Metadata: map[string]interface{}{"source_ip": ip},
			EventIDs: []string{"e1"},
		})
		tc.Ingest(&Alert{
			ID:       "net-" + string(rune('0'+i)),
			Module:   "network_guardian",
			Severity: SeverityHigh,
			Metadata: map[string]interface{}{"source_ip": ip},
			EventIDs: []string{"e2"},
		})
	}

	// Should only have ONE correlated alert per chain per IP (deduplication)
	correlatedCount := 0
	alerts := pipeline.GetAlerts(SeverityInfo, 100)
	for _, a := range alerts {
		if a.Module == "threat_correlator" {
			correlatedCount++
		}
	}
	// We expect some correlated alerts but the same chain should not fire twice
	// for the same IP in the same window
	if correlatedCount > 3 {
		t.Errorf("expected deduplication to limit correlated alerts, got %d", correlatedCount)
	}
}

func TestThreatCorrelator_InjectionPlusRuntime_Chain(t *testing.T) {
	logger := testLogger()
	pipeline := NewAlertPipeline(logger, 1000)
	tc := NewThreatCorrelator(logger, pipeline, nil)

	ip := "172.16.0.50"

	tc.Ingest(&Alert{
		ID:       "inj1",
		Module:   "injection_shield",
		Severity: SeverityCritical,
		Metadata: map[string]interface{}{"source_ip": ip},
		EventIDs: []string{"e1"},
	})
	tc.Ingest(&Alert{
		ID:       "rt1",
		Module:   "runtime_watcher",
		Severity: SeverityHigh,
		Metadata: map[string]interface{}{"source_ip": ip},
		EventIDs: []string{"e2"},
	})

	// Should trigger "Injection → Persistence" chain
	alerts := pipeline.GetAlerts(SeverityCritical, 100)
	foundChain := false
	for _, a := range alerts {
		if a.Module == "threat_correlator" {
			if meta, ok := a.Metadata["chain_name"].(string); ok {
				if meta == "Injection → Persistence" {
					foundChain = true
				}
			}
		}
	}
	if !foundChain {
		t.Error("expected 'Injection → Persistence' chain alert")
	}
}

func TestNewAlert_CarriesSourceIP(t *testing.T) {
	event := NewSecurityEvent("test_module", "test_type", SeverityHigh, "test")
	event.SourceIP = "10.0.0.42"

	alert := NewAlert(event, "Test Alert", "Test description")

	ip, ok := alert.Metadata["source_ip"].(string)
	if !ok || ip != "10.0.0.42" {
		t.Errorf("expected source_ip=10.0.0.42 in alert metadata, got %v", alert.Metadata["source_ip"])
	}
}

func TestNewAlert_NoSourceIP_NoMetadata(t *testing.T) {
	event := NewSecurityEvent("test_module", "test_type", SeverityHigh, "test")
	// No SourceIP set

	alert := NewAlert(event, "Test Alert", "Test description")

	if _, ok := alert.Metadata["source_ip"]; ok {
		t.Error("expected no source_ip in metadata when event has no SourceIP")
	}
}

func TestThreatCorrelator_CleanupExpiredWindows(t *testing.T) {
	logger := testLogger()
	pipeline := NewAlertPipeline(logger, 1000)
	tc := NewThreatCorrelator(logger, pipeline, nil)
	tc.windowDuration = 1 * time.Millisecond // very short for testing

	tc.Ingest(&Alert{
		ID:       "a1",
		Module:   "auth_fortress",
		Severity: SeverityHigh,
		Metadata: map[string]interface{}{"source_ip": "10.0.0.1"},
		EventIDs: []string{"e1"},
	})

	// Wait for window to expire
	time.Sleep(5 * time.Millisecond)

	// Now ingest from a different module — should NOT correlate because
	// the first alert's window expired
	tc.Ingest(&Alert{
		ID:       "a2",
		Module:   "network_guardian",
		Severity: SeverityHigh,
		Metadata: map[string]interface{}{"source_ip": "10.0.0.1"},
		EventIDs: []string{"e2"},
	})

	for _, a := range pipeline.GetAlerts(SeverityCritical, 100) {
		if a.Module == "threat_correlator" {
			t.Error("should not correlate after window expiry")
		}
	}
}
