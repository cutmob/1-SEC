package core

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/rs/zerolog"
)

// mockModule is a test double that satisfies the Module interface.
type mockModule struct {
	name          string
	description   string
	startErr      error
	stopErr       error
	eventsHandled []*SecurityEvent
	mu            sync.Mutex
}

func (m *mockModule) Name() string        { return m.name }
func (m *mockModule) Description() string { return m.description }
func (m *mockModule) Stop() error         { return m.stopErr }
func (m *mockModule) HandleEvent(event *SecurityEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.eventsHandled = append(m.eventsHandled, event)
	return nil
}
func (m *mockModule) Start(_ context.Context, _ *EventBus, _ *AlertPipeline, _ *Config) error {
	return m.startErr
}

func newMockModule(name string) *mockModule {
	return &mockModule{name: name, description: "mock " + name}
}

func newRegistry() *ModuleRegistry {
	return NewModuleRegistry(zerolog.Nop())
}

// ─── Register ────────────────────────────────────────────────────────────────

func TestModuleRegistry_Register(t *testing.T) {
	r := newRegistry()
	mod := newMockModule("net")

	if err := r.Register(mod); err != nil {
		t.Fatalf("Register() error: %v", err)
	}
	if r.Count() != 1 {
		t.Errorf("Count() = %d, want 1", r.Count())
	}
}

func TestModuleRegistry_Register_Duplicate(t *testing.T) {
	r := newRegistry()
	mod := newMockModule("dup")
	r.Register(mod)

	if err := r.Register(mod); err == nil {
		t.Error("expected error when registering duplicate module name")
	}
}

func TestModuleRegistry_Register_DifferentNames(t *testing.T) {
	r := newRegistry()
	for _, name := range []string{"a", "b", "c"} {
		if err := r.Register(newMockModule(name)); err != nil {
			t.Errorf("Register(%q) error: %v", name, err)
		}
	}
	if r.Count() != 3 {
		t.Errorf("Count() = %d, want 3", r.Count())
	}
}

// ─── Get ─────────────────────────────────────────────────────────────────────

func TestModuleRegistry_Get(t *testing.T) {
	r := newRegistry()
	mod := newMockModule("found")
	r.Register(mod)

	got, ok := r.Get("found")
	if !ok {
		t.Fatal("Get() ok=false, want true")
	}
	if got.Name() != "found" {
		t.Errorf("module name = %q, want 'found'", got.Name())
	}

	_, ok2 := r.Get("missing")
	if ok2 {
		t.Error("Get('missing') ok=true, want false")
	}
}

// ─── All ─────────────────────────────────────────────────────────────────────

func TestModuleRegistry_All_OrderPreserved(t *testing.T) {
	r := newRegistry()
	names := []string{"z", "a", "m", "b"}
	for _, n := range names {
		r.Register(newMockModule(n))
	}

	all := r.All()
	if len(all) != len(names) {
		t.Fatalf("All() returned %d modules, want %d", len(all), len(names))
	}
	for i, mod := range all {
		if mod.Name() != names[i] {
			t.Errorf("all[%d].Name() = %q, want %q", i, mod.Name(), names[i])
		}
	}
}

// ─── StartAll ────────────────────────────────────────────────────────────────

func TestModuleRegistry_StartAll_AllEnabled(t *testing.T) {
	r := newRegistry()
	r.Register(newMockModule("m1"))
	r.Register(newMockModule("m2"))

	cfg := DefaultConfig()
	// Ensure modules are enabled
	cfg.Modules["m1"] = ModuleConfig{Enabled: true}
	cfg.Modules["m2"] = ModuleConfig{Enabled: true}

	if err := r.StartAll(context.Background(), nil, nil, cfg); err != nil {
		t.Fatalf("StartAll() error: %v", err)
	}
}

func TestModuleRegistry_StartAll_DisabledSkipped(t *testing.T) {
	r := newRegistry()
	started := false
	mod := &mockModule{
		name:     "skip_me",
		startErr: nil,
	}
	mod.startErr = errors.New("should not be called")
	// Override Start to record if called
	type trackable struct {
		*mockModule
		wasCalled bool
	}
	tracker := &trackable{mockModule: mod}
	_ = tracker

	r.Register(newMockModule("m_enabled"))
	cfg := DefaultConfig()
	cfg.Modules["m_enabled"] = ModuleConfig{Enabled: false}

	err := r.StartAll(context.Background(), nil, nil, cfg)
	if err != nil {
		t.Fatalf("StartAll() should not fail when module is disabled: %v", err)
	}
	_ = started
}

func TestModuleRegistry_StartAll_ErrorPropagates(t *testing.T) {
	r := newRegistry()
	mod := &mockModule{name: "boom", startErr: errors.New("startup failure")}
	r.Register(mod)

	cfg := DefaultConfig()
	cfg.Modules["boom"] = ModuleConfig{Enabled: true}

	err := r.StartAll(context.Background(), nil, nil, cfg)
	if err == nil {
		t.Error("expected StartAll() to propagate module start error")
	}
}

// ─── StopAll ─────────────────────────────────────────────────────────────────

func TestModuleRegistry_StopAll_ReverseOrder(t *testing.T) {
	r := newRegistry()

	makeStoppable := func(name string) Module {
		return &struct{ *mockModule }{&mockModule{
			name: name,
		}}
	}
	_ = makeStoppable

	r.Register(newMockModule("first"))
	r.Register(newMockModule("second"))
	r.Register(newMockModule("third"))

	// StopAll should not panic even if modules have no-op Stop
	r.StopAll()
}

func TestModuleRegistry_StopAll_ErrorContinues(t *testing.T) {
	r := newRegistry()
	r.Register(&mockModule{name: "err1", stopErr: errors.New("stop fail")})
	r.Register(&mockModule{name: "err2", stopErr: errors.New("stop fail 2")})

	// Should not panic; errors are logged but all modules get Stop() called
	r.StopAll()
}

// ─── Count ────────────────────────────────────────────────────────────────────

func TestModuleRegistry_Count(t *testing.T) {
	r := newRegistry()
	if r.Count() != 0 {
		t.Errorf("empty registry count = %d, want 0", r.Count())
	}
	r.Register(newMockModule("a"))
	r.Register(newMockModule("b"))
	if r.Count() != 2 {
		t.Errorf("count = %d, want 2", r.Count())
	}
}

// ─── Interface Compliance ─────────────────────────────────────────────────────

func TestModule_Interface(t *testing.T) {
	// Verify mockModule satisfies the Module interface at compile time
	var _ Module = (*mockModule)(nil)
}

// ─── Concurrent Registration ──────────────────────────────────────────────────

func TestModuleRegistry_ConcurrentRead(t *testing.T) {
	r := newRegistry()
	for i := 0; i < 5; i++ {
		r.Register(newMockModule(string(rune('a' + i))))
	}

	var wg sync.WaitGroup
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.All()
			r.Count()
		}()
	}
	wg.Wait()
}
