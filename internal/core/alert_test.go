package core

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

// ─── AlertStatus ────────────────────────────────────────────────────────────

func TestAlertStatus_String(t *testing.T) {
	cases := []struct {
		status AlertStatus
		want   string
	}{
		{AlertStatusOpen, "OPEN"},
		{AlertStatusAcknowledged, "ACKNOWLEDGED"},
		{AlertStatusResolved, "RESOLVED"},
		{AlertStatusFalsePositive, "FALSE_POSITIVE"},
		{AlertStatus(99), "UNKNOWN"},
	}
	for _, tc := range cases {
		if got := tc.status.String(); got != tc.want {
			t.Errorf("AlertStatus(%d).String() = %q, want %q", tc.status, got, tc.want)
		}
	}
}

func TestAlertStatus_MarshalJSON(t *testing.T) {
	a := struct {
		S AlertStatus `json:"status"`
	}{S: AlertStatusAcknowledged}
	data, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "ACKNOWLEDGED") {
		t.Errorf("expected ACKNOWLEDGED in JSON, got %s", data)
	}
}

func TestParseAlertStatus(t *testing.T) {
	cases := []struct {
		input string
		want  AlertStatus
		ok    bool
	}{
		{"OPEN", AlertStatusOpen, true},
		{"open", AlertStatusOpen, true},
		{"ACKNOWLEDGED", AlertStatusAcknowledged, true},
		{"ACK", AlertStatusAcknowledged, true},
		{"ack", AlertStatusAcknowledged, true},
		{"RESOLVED", AlertStatusResolved, true},
		{"resolved", AlertStatusResolved, true},
		{"FALSE_POSITIVE", AlertStatusFalsePositive, true},
		{"false_positive", AlertStatusFalsePositive, true},
		{"GARBAGE", AlertStatusOpen, false},
		{"", AlertStatusOpen, false},
	}
	for _, tc := range cases {
		got, ok := ParseAlertStatus(tc.input)
		if ok != tc.ok {
			t.Errorf("ParseAlertStatus(%q) ok=%v, want %v", tc.input, ok, tc.ok)
		}
		if ok && got != tc.want {
			t.Errorf("ParseAlertStatus(%q) = %v, want %v", tc.input, got, tc.want)
		}
	}
}

// ─── NewAlert ───────────────────────────────────────────────────────────────

func TestNewAlert(t *testing.T) {
	event := NewSecurityEvent("test_module", "test_type", SeverityHigh, "test summary")
	alert := NewAlert(event, "Test Title", "Test Description")

	if alert.ID == "" {
		t.Error("expected non-empty alert ID")
	}
	if alert.Module != "test_module" {
		t.Errorf("module = %q, want %q", alert.Module, "test_module")
	}
	if alert.Type != "test_type" {
		t.Errorf("type = %q, want %q", alert.Type, "test_type")
	}
	if alert.Severity != SeverityHigh {
		t.Errorf("severity = %v, want High", alert.Severity)
	}
	if alert.Status != AlertStatusOpen {
		t.Errorf("status = %v, want Open", alert.Status)
	}
	if alert.Title != "Test Title" {
		t.Errorf("title = %q, want 'Test Title'", alert.Title)
	}
	if alert.Description != "Test Description" {
		t.Errorf("description = %q, want 'Test Description'", alert.Description)
	}
	if len(alert.EventIDs) != 1 || alert.EventIDs[0] != event.ID {
		t.Error("EventIDs should contain the source event ID")
	}
	if alert.Metadata == nil {
		t.Error("Metadata map should be initialised")
	}
	if alert.Timestamp.IsZero() {
		t.Error("Timestamp should be set")
	}
}

func TestAlert_Marshal(t *testing.T) {
	event := NewSecurityEvent("m", "t", SeverityCritical, "s")
	alert := NewAlert(event, "Title", "Desc")
	alert.Mitigations = []string{"fix it"}

	data, err := alert.Marshal()
	if err != nil {
		t.Fatalf("Marshal() error: %v", err)
	}

	// AlertStatus is serialized as a string (e.g., "OPEN").
	// There is no UnmarshalJSON for AlertStatus, so we verify
	// the raw JSON contains the expected string fields.
	rawJSON := string(data)
	if !strings.Contains(rawJSON, alert.ID) {
		t.Errorf("marshaled JSON does not contain alert ID %q", alert.ID)
	}
	if !strings.Contains(rawJSON, "OPEN") {
		t.Error("marshaled JSON should contain status string 'OPEN'")
	}
	if !strings.Contains(rawJSON, "CRITICAL") {
		t.Error("marshaled JSON should contain severity 'CRITICAL'")
	}
	if !strings.Contains(rawJSON, "fix it") {
		t.Error("marshaled JSON should contain mitigation text")
	}
}

// ─── AlertPipeline ──────────────────────────────────────────────────────────

func newTestPipeline(maxStore int) *AlertPipeline {
	logger := zerolog.Nop()
	return NewAlertPipeline(logger, maxStore)
}

func newTestAlert(module, alertType string, severity Severity) *Alert {
	event := NewSecurityEvent(module, alertType, severity, "summary")
	return NewAlert(event, "Title", "Desc")
}

func TestNewAlertPipeline_DefaultMaxStore(t *testing.T) {
	p := newTestPipeline(0)
	if p.maxStore != 10000 {
		t.Errorf("expected default maxStore=10000, got %d", p.maxStore)
	}
	p2 := newTestPipeline(-5)
	if p2.maxStore != 10000 {
		t.Errorf("expected default maxStore=10000, got %d", p2.maxStore)
	}
}

func TestAlertPipeline_Process_Store(t *testing.T) {
	p := newTestPipeline(100)
	alert := newTestAlert("mod", "type", SeverityHigh)
	p.Process(alert)

	if p.Count() != 1 {
		t.Errorf("expected 1 alert, got %d", p.Count())
	}
}

func TestAlertPipeline_Process_HandlerCalled(t *testing.T) {
	p := newTestPipeline(100)
	var called int
	p.AddHandler(func(a *Alert) { called++ })
	p.AddHandler(func(a *Alert) { called++ })

	p.Process(newTestAlert("m", "t", SeverityLow))

	if called != 2 {
		t.Errorf("expected 2 handler calls, got %d", called)
	}
}

func TestAlertPipeline_GetAlerts_Filtering(t *testing.T) {
	p := newTestPipeline(100)
	p.Process(newTestAlert("m", "t", SeverityInfo))
	p.Process(newTestAlert("m", "t", SeverityLow))
	p.Process(newTestAlert("m", "t", SeverityMedium))
	p.Process(newTestAlert("m", "t", SeverityHigh))
	p.Process(newTestAlert("m", "t", SeverityCritical))

	got := p.GetAlerts(SeverityHigh, 100)
	if len(got) != 2 {
		t.Errorf("expected 2 High/Critical alerts, got %d", len(got))
	}
}

func TestAlertPipeline_GetAlerts_Limit(t *testing.T) {
	p := newTestPipeline(100)
	for i := 0; i < 10; i++ {
		p.Process(newTestAlert("m", "t", SeverityCritical))
	}
	got := p.GetAlerts(SeverityInfo, 3)
	if len(got) != 3 {
		t.Errorf("expected 3 alerts with limit=3, got %d", len(got))
	}
}

func TestAlertPipeline_GetAlerts_MostRecentFirst(t *testing.T) {
	p := newTestPipeline(100)
	var ids []string
	for i := 0; i < 5; i++ {
		a := newTestAlert("m", "t", SeverityLow)
		ids = append(ids, a.ID)
		p.Process(a)
		time.Sleep(time.Millisecond) // ensure ordering
	}
	got := p.GetAlerts(SeverityInfo, 5)
	// Most recent = last inserted = ids[4] should be got[0]
	if got[0].ID != ids[4] {
		t.Errorf("expected most recent first; got[0].ID=%q, want %q", got[0].ID, ids[4])
	}
}

func TestAlertPipeline_GetAlertByID(t *testing.T) {
	p := newTestPipeline(100)
	alert := newTestAlert("m", "t", SeverityMedium)
	p.Process(alert)

	found := p.GetAlertByID(alert.ID)
	if found == nil {
		t.Fatal("GetAlertByID returned nil")
	}
	if found.ID != alert.ID {
		t.Errorf("got wrong alert ID: %q", found.ID)
	}

	notFound := p.GetAlertByID("nonexistent")
	if notFound != nil {
		t.Error("expected nil for nonexistent ID")
	}
}

func TestAlertPipeline_UpdateAlertStatus(t *testing.T) {
	p := newTestPipeline(100)
	alert := newTestAlert("m", "t", SeverityHigh)
	p.Process(alert)

	updated, ok := p.UpdateAlertStatus(alert.ID, AlertStatusResolved)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if updated.Status != AlertStatusResolved {
		t.Errorf("status = %v, want Resolved", updated.Status)
	}

	// Verify the change persisted
	found := p.GetAlertByID(alert.ID)
	if found.Status != AlertStatusResolved {
		t.Error("status change did not persist")
	}

	// Non-existent ID
	_, ok2 := p.UpdateAlertStatus("bad-id", AlertStatusAcknowledged)
	if ok2 {
		t.Error("expected ok=false for non-existent ID")
	}
}

func TestAlertPipeline_DeleteAlert(t *testing.T) {
	p := newTestPipeline(100)
	a1 := newTestAlert("m", "t", SeverityLow)
	a2 := newTestAlert("m", "t", SeverityHigh)
	p.Process(a1)
	p.Process(a2)

	if !p.DeleteAlert(a1.ID) {
		t.Error("expected true when deleting existing alert")
	}
	if p.Count() != 1 {
		t.Errorf("expected 1 alert after deletion, got %d", p.Count())
	}
	if p.GetAlertByID(a1.ID) != nil {
		t.Error("deleted alert should not be findable")
	}
	// a2 should still exist
	if p.GetAlertByID(a2.ID) == nil {
		t.Error("remaining alert should still exist")
	}

	// Deleting non-existent
	if p.DeleteAlert("ghost") {
		t.Error("expected false for non-existent ID")
	}
}

func TestAlertPipeline_ClearAlerts(t *testing.T) {
	p := newTestPipeline(100)
	for i := 0; i < 5; i++ {
		p.Process(newTestAlert("m", "t", SeverityInfo))
	}
	count := p.ClearAlerts()
	if count != 5 {
		t.Errorf("ClearAlerts returned %d, want 5", count)
	}
	if p.Count() != 0 {
		t.Errorf("expected 0 alerts after clear, got %d", p.Count())
	}
}

func TestAlertPipeline_MaxStore_Eviction(t *testing.T) {
	maxStore := 10
	p := newTestPipeline(maxStore)
	for i := 0; i < 20; i++ {
		p.Process(newTestAlert("m", "t", SeverityInfo))
	}
	// Should drop oldest 10% when full, so count stays near maxStore
	if p.Count() > maxStore {
		t.Errorf("stored %d alerts, expected at most %d", p.Count(), maxStore)
	}
}

func TestAlertPipeline_ConcurrentAccess(t *testing.T) {
	p := newTestPipeline(10000)
	var wg sync.WaitGroup

	for i := 0; i < 50; i++ {
		wg.Add(3)
		go func() {
			defer wg.Done()
			p.Process(newTestAlert("m", "t", SeverityHigh))
		}()
		go func() {
			defer wg.Done()
			p.GetAlerts(SeverityInfo, 10)
		}()
		go func() {
			defer wg.Done()
			p.Count()
		}()
	}
	wg.Wait()
}
