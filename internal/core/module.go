package core

import (
	"context"
	"fmt"
	"sync"

	"github.com/rs/zerolog"
)

// Module is the interface that all 1SEC security modules must implement.
type Module interface {
	// Name returns the unique name of the module.
	Name() string
	// Description returns a human-readable description.
	Description() string
	// Start initializes and starts the module.
	Start(ctx context.Context, bus *EventBus, pipeline *AlertPipeline, cfg *Config) error
	// Stop gracefully shuts down the module.
	Stop() error
	// HandleEvent processes an incoming security event.
	HandleEvent(event *SecurityEvent) error
}

// ModuleRegistry manages module registration and lifecycle.
type ModuleRegistry struct {
	mu      sync.RWMutex
	modules map[string]Module
	order   []string
	logger  zerolog.Logger
}

// NewModuleRegistry creates a new ModuleRegistry.
func NewModuleRegistry(logger zerolog.Logger) *ModuleRegistry {
	return &ModuleRegistry{
		modules: make(map[string]Module),
		order:   make([]string, 0),
		logger:  logger.With().Str("component", "module_registry").Logger(),
	}
}

// Register adds a module to the registry.
func (r *ModuleRegistry) Register(mod Module) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	name := mod.Name()
	if _, exists := r.modules[name]; exists {
		return fmt.Errorf("module %q already registered", name)
	}

	r.modules[name] = mod
	r.order = append(r.order, name)
	r.logger.Info().Str("module", name).Msg("module registered")
	return nil
}

// Get returns a module by name.
func (r *ModuleRegistry) Get(name string) (Module, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	mod, ok := r.modules[name]
	return mod, ok
}

// All returns all registered modules in registration order.
func (r *ModuleRegistry) All() []Module {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]Module, 0, len(r.order))
	for _, name := range r.order {
		result = append(result, r.modules[name])
	}
	return result
}

// StartAll starts all registered modules that are enabled in config.
func (r *ModuleRegistry) StartAll(ctx context.Context, bus *EventBus, pipeline *AlertPipeline, cfg *Config) error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, name := range r.order {
		mod := r.modules[name]
		if !cfg.IsModuleEnabled(name) {
			r.logger.Info().Str("module", name).Msg("module disabled, skipping")
			continue
		}
		r.logger.Info().Str("module", name).Msg("starting module")
		if err := mod.Start(ctx, bus, pipeline, cfg); err != nil {
			return fmt.Errorf("failed to start module %q: %w", name, err)
		}
		r.logger.Info().Str("module", name).Msg("module started")
	}
	return nil
}

// StopAll stops all registered modules in reverse order.
func (r *ModuleRegistry) StopAll() {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for i := len(r.order) - 1; i >= 0; i-- {
		name := r.order[i]
		mod := r.modules[name]
		r.logger.Info().Str("module", name).Msg("stopping module")
		if err := mod.Stop(); err != nil {
			r.logger.Error().Err(err).Str("module", name).Msg("error stopping module")
		}
	}
}

// Count returns the number of registered modules.
func (r *ModuleRegistry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.modules)
}
