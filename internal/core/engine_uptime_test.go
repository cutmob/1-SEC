package core

import (
	"testing"
	"time"
)

func TestEngine_Uptime_ZeroBeforeStart(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RustEngine.Enabled = false
	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Before Start(), startTime is zero
	if engine.Uptime() != 0 {
		t.Errorf("expected 0 uptime before start, got %v", engine.Uptime())
	}
}

func TestEngine_Uptime_PositiveAfterSet(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RustEngine.Enabled = false
	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate what Start() does
	engine.SetStartTimeForTest(time.Now().Add(-5 * time.Second))

	uptime := engine.Uptime()
	if uptime < 4*time.Second || uptime > 10*time.Second {
		t.Errorf("expected ~5s uptime, got %v", uptime)
	}
}
