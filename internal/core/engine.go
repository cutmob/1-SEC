package core

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog"
)

// Engine is the main 1SEC engine that orchestrates all components.
type Engine struct {
	Config   *Config
	Bus      *EventBus
	Registry *ModuleRegistry
	Pipeline *AlertPipeline
	Logger   zerolog.Logger
	ctx      context.Context
	cancel   context.CancelFunc
}

// NewEngine creates a new 1SEC engine.
func NewEngine(cfg *Config) (*Engine, error) {
	// Configure logger
	var logger zerolog.Logger
	if cfg.Logging.Format == "json" {
		logger = zerolog.New(os.Stdout).With().Timestamp().Logger()
	} else {
		logger = zerolog.New(zerolog.ConsoleWriter{
			Out:        os.Stdout,
			TimeFormat: time.RFC3339,
		}).With().Timestamp().Logger()
	}

	switch cfg.LogLevel() {
	case "debug":
		logger = logger.Level(zerolog.DebugLevel)
	case "warn":
		logger = logger.Level(zerolog.WarnLevel)
	case "error":
		logger = logger.Level(zerolog.ErrorLevel)
	default:
		logger = logger.Level(zerolog.InfoLevel)
	}

	ctx, cancel := context.WithCancel(context.Background())

	engine := &Engine{
		Config:   cfg,
		Registry: NewModuleRegistry(logger),
		Pipeline: NewAlertPipeline(logger, cfg.Alerts.MaxStore),
		Logger:   logger.With().Str("component", "engine").Logger(),
		ctx:      ctx,
		cancel:   cancel,
	}

	// Add console alert handler if enabled
	if cfg.Alerts.EnableConsole {
		engine.Pipeline.AddHandler(func(alert *Alert) {
			engine.Logger.Warn().
				Str("alert_id", alert.ID).
				Str("module", alert.Module).
				Str("severity", alert.Severity.String()).
				Str("title", alert.Title).
				Str("description", alert.Description).
				Msg("SECURITY ALERT")
		})
	}

	// Add webhook alert handlers
	for _, url := range cfg.Alerts.WebhookURLs {
		webhookURL := url
		engine.Pipeline.AddHandler(func(alert *Alert) {
			go sendWebhook(webhookURL, alert, logger)
		})
	}

	return engine, nil
}

// Start initializes the event bus, starts all modules, and begins processing.
func (e *Engine) Start() error {
	e.Logger.Info().Msg("starting 1SEC engine")

	// Start event bus
	bus, err := NewEventBus(&e.Config.Bus, e.Logger)
	if err != nil {
		return fmt.Errorf("starting event bus: %w", err)
	}
	e.Bus = bus

	// Wire alert pipeline to publish alerts to the bus
	e.Pipeline.AddHandler(func(alert *Alert) {
		if err := e.Bus.PublishAlert(alert); err != nil {
			e.Logger.Error().Err(err).Str("alert_id", alert.ID).Msg("failed to publish alert to bus")
		}
	})

	// Start all enabled modules
	if err := e.Registry.StartAll(e.ctx, e.Bus, e.Pipeline, e.Config); err != nil {
		return fmt.Errorf("starting modules: %w", err)
	}

	// Subscribe to all events and route to modules
	if err := e.Bus.SubscribeToAllEvents(func(event *SecurityEvent) {
		for _, mod := range e.Registry.All() {
			if mod.Name() != event.Module {
				if err := mod.HandleEvent(event); err != nil {
					e.Logger.Error().Err(err).
						Str("module", mod.Name()).
						Str("event_id", event.ID).
						Msg("module failed to handle event")
				}
			}
		}
	}); err != nil {
		return fmt.Errorf("subscribing to events: %w", err)
	}

	e.Logger.Info().
		Int("modules", e.Registry.Count()).
		Msg("1SEC engine started")

	return nil
}

// Run starts the engine and blocks until shutdown signal is received.
func (e *Engine) Run() error {
	if err := e.Start(); err != nil {
		return err
	}

	// Wait for shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		e.Logger.Info().Str("signal", sig.String()).Msg("shutdown signal received")
	case <-e.ctx.Done():
		e.Logger.Info().Msg("context cancelled")
	}

	return e.Shutdown()
}

// Shutdown gracefully stops the engine.
func (e *Engine) Shutdown() error {
	e.Logger.Info().Msg("shutting down 1SEC engine")
	e.cancel()

	e.Registry.StopAll()

	if e.Bus != nil {
		if err := e.Bus.Close(); err != nil {
			e.Logger.Error().Err(err).Msg("error closing event bus")
		}
	}

	e.Logger.Info().Msg("1SEC engine stopped")
	return nil
}

// Context returns the engine's context.
func (e *Engine) Context() context.Context {
	return e.ctx
}

// sendWebhook sends an alert to a webhook URL.
func sendWebhook(url string, alert *Alert, logger zerolog.Logger) {
	data, err := alert.Marshal()
	if err != nil {
		logger.Error().Err(err).Msg("failed to marshal alert for webhook")
		return
	}

	resp, err := httpPost(url, "application/json", data)
	if err != nil {
		logger.Error().Err(err).Str("url", url).Msg("webhook delivery failed")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		logger.Warn().Int("status", resp.StatusCode).Str("url", url).Msg("webhook returned error status")
	}
}
