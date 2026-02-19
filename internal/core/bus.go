package core

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/rs/zerolog"
)

// EventBus wraps NATS JetStream for event publishing and subscribing.
type EventBus struct {
	nc     *nats.Conn
	js     nats.JetStreamContext
	ns     *server.Server
	logger zerolog.Logger
	mu     sync.RWMutex
	subs   []*nats.Subscription
}

// NewEventBus creates a new EventBus. If cfg.Embedded is true, it starts an embedded NATS server.
func NewEventBus(cfg *BusConfig, logger zerolog.Logger) (*EventBus, error) {
	bus := &EventBus{
		logger: logger.With().Str("component", "event_bus").Logger(),
		subs:   make([]*nats.Subscription, 0),
	}

	if cfg.Embedded {
		if err := os.MkdirAll(cfg.DataDir, 0755); err != nil {
			return nil, fmt.Errorf("creating NATS data dir: %w", err)
		}

		opts := &server.Options{
			Host:      "127.0.0.1",
			Port:      cfg.Port,
			JetStream: true,
			StoreDir:  cfg.DataDir,
			NoLog:     true,
			NoSigs:    true,
		}

		ns, err := server.NewServer(opts)
		if err != nil {
			return nil, fmt.Errorf("creating embedded NATS server: %w", err)
		}

		ns.Start()

		if !ns.ReadyForConnections(10 * time.Second) {
			return nil, fmt.Errorf("embedded NATS server failed to start within timeout")
		}

		bus.ns = ns
		bus.logger.Info().Int("port", cfg.Port).Msg("embedded NATS server started")
	}

	url := cfg.URL
	if cfg.Embedded {
		url = fmt.Sprintf("nats://127.0.0.1:%d", cfg.Port)
	}

	nc, err := nats.Connect(url,
		nats.RetryOnFailedConnect(true),
		nats.MaxReconnects(60),
		nats.ReconnectWait(time.Second),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			if err != nil {
				bus.logger.Warn().Err(err).Msg("NATS disconnected")
			}
		}),
		nats.ReconnectHandler(func(_ *nats.Conn) {
			bus.logger.Info().Msg("NATS reconnected")
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("connecting to NATS: %w", err)
	}
	bus.nc = nc

	js, err := nc.JetStream()
	if err != nil {
		return nil, fmt.Errorf("creating JetStream context: %w", err)
	}
	bus.js = js

	// Create or update the main security events stream.
	// AddStream returns the existing stream if config matches; if the stream exists
	// with a different config (e.g., after a version upgrade), we update it.
	eventsStreamCfg := &nats.StreamConfig{
		Name:      "SECURITY_EVENTS",
		Subjects:  []string{"sec.events.>"},
		Retention: nats.LimitsPolicy,
		MaxAge:    24 * time.Hour * 7, // 7 days retention
		MaxBytes:  1024 * 1024 * 1024, // 1GB max
		Storage:   nats.FileStorage,
		Discard:   nats.DiscardOld,
	}
	_, err = js.AddStream(eventsStreamCfg)
	if err != nil {
		// Stream may exist with different config from a previous version — try update
		if _, updateErr := js.UpdateStream(eventsStreamCfg); updateErr != nil {
			return nil, fmt.Errorf("creating/updating events stream: %w (original: %v)", updateErr, err)
		}
	}

	// Create or update the alerts stream.
	alertsStreamCfg := &nats.StreamConfig{
		Name:      "SECURITY_ALERTS",
		Subjects:  []string{"sec.alerts.>"},
		Retention: nats.LimitsPolicy,
		MaxAge:    24 * time.Hour * 30, // 30 days retention
		MaxBytes:  512 * 1024 * 1024,   // 512MB max
		Storage:   nats.FileStorage,
		Discard:   nats.DiscardOld,
	}
	_, err = js.AddStream(alertsStreamCfg)
	if err != nil {
		if _, updateErr := js.UpdateStream(alertsStreamCfg); updateErr != nil {
			return nil, fmt.Errorf("creating/updating alerts stream: %w (original: %v)", updateErr, err)
		}
	}

	bus.logger.Info().Str("url", url).Msg("connected to NATS JetStream")
	return bus, nil
}

// PublishEvent publishes a SecurityEvent to the event bus.
func (b *EventBus) PublishEvent(event *SecurityEvent) error {
	data, err := event.Marshal()
	if err != nil {
		return fmt.Errorf("marshaling event: %w", err)
	}

	subject := fmt.Sprintf("sec.events.%s.%s", event.Module, event.Type)
	_, err = b.js.Publish(subject, data)
	if err != nil {
		return fmt.Errorf("publishing event to %s: %w", subject, err)
	}

	b.logger.Debug().
		Str("event_id", event.ID).
		Str("subject", subject).
		Str("severity", event.Severity.String()).
		Msg("event published")

	return nil
}

// PublishAlert publishes an Alert to the alert stream.
func (b *EventBus) PublishAlert(alert *Alert) error {
	data, err := alert.Marshal()
	if err != nil {
		return fmt.Errorf("marshaling alert: %w", err)
	}

	subject := fmt.Sprintf("sec.alerts.%s.%s", alert.Module, alert.Severity.String())
	_, err = b.js.Publish(subject, data)
	if err != nil {
		return fmt.Errorf("publishing alert to %s: %w", subject, err)
	}

	return nil
}

// Subscribe creates a durable subscription to a subject pattern.
func (b *EventBus) Subscribe(subject string, handler func(msg *nats.Msg)) error {
	sub, err := b.js.Subscribe(subject, handler, nats.DeliverNew(), nats.AckExplicit())
	if err != nil {
		return fmt.Errorf("subscribing to %s: %w", subject, err)
	}

	b.mu.Lock()
	b.subs = append(b.subs, sub)
	b.mu.Unlock()

	b.logger.Debug().Str("subject", subject).Msg("subscribed")
	return nil
}

// SubscribeToAllEvents subscribes to all security events.
func (b *EventBus) SubscribeToAllEvents(handler func(event *SecurityEvent)) error {
	return b.Subscribe("sec.events.>", func(msg *nats.Msg) {
		event, err := UnmarshalSecurityEvent(msg.Data)
		if err != nil {
			b.logger.Error().Err(err).Msg("failed to unmarshal event")
			_ = msg.Nak()
			return
		}
		handler(event)
		_ = msg.Ack()
	})
}

// Close shuts down the event bus.
func (b *EventBus) Close() error {
	b.mu.Lock()
	for _, sub := range b.subs {
		_ = sub.Unsubscribe()
	}
	b.subs = nil
	b.mu.Unlock()

	if b.nc != nil {
		b.nc.Close()
	}

	if b.ns != nil {
		b.ns.Shutdown()
		b.ns.WaitForShutdown()
		b.logger.Info().Msg("embedded NATS server stopped")
	}

	return nil
}

// IsConnected returns true if the NATS connection is active.
func (b *EventBus) IsConnected() bool {
	return b.nc != nil && b.nc.IsConnected()
}
