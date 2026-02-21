package core

import (
	"testing"
)

func TestDefaultArchiveConfig(t *testing.T) {
	cfg := DefaultArchiveConfig()
	if cfg.Enabled {
		t.Error("archive should be disabled by default")
	}
	if cfg.Dir != "./data/archive" {
		t.Errorf("Dir = %q, want ./data/archive", cfg.Dir)
	}
	if cfg.RotateBytes != 100*1024*1024 {
		t.Errorf("RotateBytes = %d, want 100MB", cfg.RotateBytes)
	}
	if cfg.RotateInterval != "1h" {
		t.Errorf("RotateInterval = %q, want 1h", cfg.RotateInterval)
	}
	if !cfg.Compress {
		t.Error("Compress should be true by default")
	}
}

func TestArchiver_ShouldSample_NoRules(t *testing.T) {
	a := &Archiver{
		cfg:            ArchiveConfig{},
		sampleCounters: make(map[string]int64),
	}
	data := []byte(`{"type":"http_request","severity":"INFO"}`)
	if a.shouldSample(data) {
		t.Error("should not sample when no rules configured")
	}
}

func TestArchiver_ShouldSample_MatchingRule(t *testing.T) {
	a := &Archiver{
		cfg: ArchiveConfig{
			SampleRules: []SampleRule{
				{EventType: "dns_query", MaxSeverity: "INFO", SampleRate: 10},
			},
		},
		sampleCounters: make(map[string]int64),
	}

	data := []byte(`{"type":"dns_query","severity":"INFO"}`)

	// First 9 should be sampled (dropped), 10th kept
	dropped := 0
	for i := 0; i < 10; i++ {
		if a.shouldSample(data) {
			dropped++
		}
	}
	if dropped != 9 {
		t.Errorf("expected 9 dropped out of 10, got %d", dropped)
	}
}

func TestArchiver_ShouldSample_HighSeverityAlwaysKept(t *testing.T) {
	a := &Archiver{
		cfg: ArchiveConfig{
			SampleRules: []SampleRule{
				{EventType: "dns_query", MaxSeverity: "INFO", SampleRate: 100},
			},
		},
		sampleCounters: make(map[string]int64),
	}

	// HIGH severity should always be kept even if type matches
	data := []byte(`{"type":"dns_query","severity":"HIGH"}`)
	for i := 0; i < 20; i++ {
		if a.shouldSample(data) {
			t.Error("HIGH severity event should never be sampled")
			return
		}
	}
}

func TestArchiver_ShouldSample_NonMatchingType(t *testing.T) {
	a := &Archiver{
		cfg: ArchiveConfig{
			SampleRules: []SampleRule{
				{EventType: "dns_query", MaxSeverity: "INFO", SampleRate: 100},
			},
		},
		sampleCounters: make(map[string]int64),
	}

	data := []byte(`{"type":"login_failure","severity":"INFO"}`)
	for i := 0; i < 20; i++ {
		if a.shouldSample(data) {
			t.Error("non-matching event type should not be sampled")
			return
		}
	}
}

func TestArchiver_ShouldSample_RateOne_KeepsAll(t *testing.T) {
	a := &Archiver{
		cfg: ArchiveConfig{
			SampleRules: []SampleRule{
				{EventType: "dns_query", MaxSeverity: "INFO", SampleRate: 1},
			},
		},
		sampleCounters: make(map[string]int64),
	}

	data := []byte(`{"type":"dns_query","severity":"INFO"}`)
	for i := 0; i < 20; i++ {
		if a.shouldSample(data) {
			t.Error("sample_rate 1 should keep all events")
			return
		}
	}
}

func TestArchiver_ShouldSample_InvalidJSON(t *testing.T) {
	a := &Archiver{
		cfg: ArchiveConfig{
			SampleRules: []SampleRule{
				{EventType: "dns_query", MaxSeverity: "INFO", SampleRate: 100},
			},
		},
		sampleCounters: make(map[string]int64),
	}

	data := []byte(`not json`)
	if a.shouldSample(data) {
		t.Error("invalid JSON should not be sampled (keep it)")
	}
}

func TestArchiver_Status(t *testing.T) {
	a := &Archiver{
		cfg: ArchiveConfig{
			Enabled:  true,
			Dir:      "/tmp/test-archive",
			Compress: true,
		},
		eventsArchived: 42,
		alertsArchived: 5,
		filesRotated:   3,
		bytesWritten:   1024,
		eventsSampled:  10,
		sampleCounters: make(map[string]int64),
	}

	status := a.Status()
	if status["enabled"] != true {
		t.Error("expected enabled = true")
	}
	if status["events_archived"].(int64) != 42 {
		t.Errorf("events_archived = %v, want 42", status["events_archived"])
	}
	if status["alerts_archived"].(int64) != 5 {
		t.Errorf("alerts_archived = %v, want 5", status["alerts_archived"])
	}
	if status["events_sampled"].(int64) != 10 {
		t.Errorf("events_sampled = %v, want 10", status["events_sampled"])
	}
}
