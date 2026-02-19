package iot

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/1sec-project/1sec/internal/core"
	"github.com/rs/zerolog"
)

const ModuleName = "iot_shield"

// Shield is the IoT & OT Shield module.
type Shield struct {
	logger     zerolog.Logger
	bus        *core.EventBus
	pipeline   *core.AlertPipeline
	ctx        context.Context
	cancel     context.CancelFunc
	inventory  *DeviceInventory
	anomalyDet *ProtocolAnomalyDetector
}

func New() *Shield { return &Shield{} }

func (s *Shield) Name() string        { return ModuleName }
func (s *Shield) Description() string {
	return "IoT/OT device fingerprinting, protocol anomaly detection, firmware integrity, and default credential scanning"
}

func (s *Shield) Start(ctx context.Context, bus *core.EventBus, pipeline *core.AlertPipeline, cfg *core.Config) error {
	s.ctx, s.cancel = context.WithCancel(ctx)
	s.bus = bus
	s.pipeline = pipeline
	s.logger = zerolog.New(zerolog.NewConsoleWriter()).With().Timestamp().Str("module", ModuleName).Logger()

	s.inventory = NewDeviceInventory()
	s.anomalyDet = NewProtocolAnomalyDetector()

	go s.inventory.CleanupLoop(s.ctx)

	s.logger.Info().Msg("IoT/OT shield started")
	return nil
}

func (s *Shield) Stop() error {
	if s.cancel != nil {
		s.cancel()
	}
	return nil
}

func (s *Shield) HandleEvent(event *core.SecurityEvent) error {
	switch event.Type {
	case "device_connect", "device_activity", "iot_traffic":
		s.handleDeviceEvent(event)
	case "protocol_message":
		s.handleProtocolEvent(event)
	case "firmware_update", "firmware_check":
		s.handleFirmwareEvent(event)
	}
	return nil
}

func (s *Shield) handleDeviceEvent(event *core.SecurityEvent) {
	deviceID := getStringDetail(event, "device_id")
	deviceType := getStringDetail(event, "device_type")
	mac := getStringDetail(event, "mac_address")
	firmware := getStringDetail(event, "firmware_version")

	if deviceID == "" && mac == "" {
		return
	}
	if deviceID == "" {
		deviceID = mac
	}

	isNew := s.inventory.Register(deviceID, deviceType, mac, firmware, event.SourceIP)
	if isNew {
		s.raiseAlert(event, core.SeverityMedium,
			"New IoT Device Detected",
			fmt.Sprintf("New device on network: ID=%s type=%s IP=%s MAC=%s", deviceID, deviceType, event.SourceIP, mac),
			"new_device")
	}

	if user := getStringDetail(event, "username"); user != "" {
		if isDefaultCredential(user, getStringDetail(event, "password")) {
			s.raiseAlert(event, core.SeverityCritical,
				"Default Credentials Detected",
				fmt.Sprintf("Device %s (%s) is using default credentials (user: %s)", deviceID, deviceType, user),
				"default_credentials")
		}
	}
}

func (s *Shield) handleProtocolEvent(event *core.SecurityEvent) {
	protocol := strings.ToLower(getStringDetail(event, "protocol"))
	payload := getStringDetail(event, "payload")

	if protocol == "" {
		return
	}

	anomaly := s.anomalyDet.Check(protocol, payload, event.SourceIP)
	if anomaly != "" {
		s.raiseAlert(event, core.SeverityHigh,
			"IoT Protocol Anomaly",
			fmt.Sprintf("Protocol anomaly on %s from %s: %s", protocol, event.SourceIP, anomaly),
			"protocol_anomaly")
	}
}

func (s *Shield) handleFirmwareEvent(event *core.SecurityEvent) {
	deviceID := getStringDetail(event, "device_id")
	version := getStringDetail(event, "firmware_version")
	hash := getStringDetail(event, "firmware_hash")
	expectedHash := getStringDetail(event, "expected_hash")

	if hash != "" && expectedHash != "" && hash != expectedHash {
		s.raiseAlert(event, core.SeverityCritical,
			"Firmware Integrity Violation",
			fmt.Sprintf("Device %s firmware hash mismatch. Expected: %s, Got: %s (version: %s)",
				deviceID, truncate(expectedHash, 16), truncate(hash, 16), version),
			"firmware_integrity")
	}
}

func (s *Shield) raiseAlert(event *core.SecurityEvent, severity core.Severity, title, description, alertType string) {
	newEvent := core.NewSecurityEvent(ModuleName, alertType, severity, description)
	newEvent.SourceIP = event.SourceIP
	newEvent.Details["original_event_id"] = event.ID

	if s.bus != nil {
		_ = s.bus.PublishEvent(newEvent)
	}

	alert := core.NewAlert(newEvent, title, description)
	if s.pipeline != nil {
		s.pipeline.Process(alert)
	}
}

// DeviceInventory tracks known IoT/OT devices.
type DeviceInventory struct {
	mu      sync.RWMutex
	devices map[string]*DeviceRecord
}

type DeviceRecord struct {
	ID        string
	Type      string
	MAC       string
	Firmware  string
	IP        string
	FirstSeen time.Time
	LastSeen  time.Time
}

func NewDeviceInventory() *DeviceInventory {
	return &DeviceInventory{devices: make(map[string]*DeviceRecord)}
}

func (inv *DeviceInventory) Register(id, deviceType, mac, firmware, ip string) bool {
	inv.mu.Lock()
	defer inv.mu.Unlock()

	now := time.Now()
	if rec, exists := inv.devices[id]; exists {
		rec.LastSeen = now
		rec.IP = ip
		if firmware != "" {
			rec.Firmware = firmware
		}
		return false
	}

	inv.devices[id] = &DeviceRecord{
		ID: id, Type: deviceType, MAC: mac,
		Firmware: firmware, IP: ip,
		FirstSeen: now, LastSeen: now,
	}
	return true
}

func (inv *DeviceInventory) CleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			inv.mu.Lock()
			cutoff := time.Now().Add(-24 * time.Hour)
			for id, rec := range inv.devices {
				if rec.LastSeen.Before(cutoff) {
					delete(inv.devices, id)
				}
			}
			inv.mu.Unlock()
		}
	}
}

// ProtocolAnomalyDetector checks IoT protocol messages for anomalies.
type ProtocolAnomalyDetector struct {
	mu       sync.RWMutex
	counters map[string]*protoCounter
}

type protoCounter struct {
	count    int
	window   time.Time
	lastSeen time.Time
}

func NewProtocolAnomalyDetector() *ProtocolAnomalyDetector {
	return &ProtocolAnomalyDetector{counters: make(map[string]*protoCounter)}
}

func (d *ProtocolAnomalyDetector) Check(protocol, payload, sourceIP string) string {
	d.mu.Lock()
	defer d.mu.Unlock()

	key := sourceIP + ":" + protocol
	now := time.Now()

	counter, exists := d.counters[key]
	if !exists {
		d.counters[key] = &protoCounter{count: 1, window: now, lastSeen: now}
	} else {
		if now.Sub(counter.window) > time.Minute {
			counter.count = 0
			counter.window = now
		}
		counter.count++
		counter.lastSeen = now

		if counter.count > 500 {
			return fmt.Sprintf("abnormal message rate: %d msgs/min", counter.count)
		}
	}

	if protocol == "modbus" || protocol == "dnp3" || protocol == "opcua" {
		if strings.Contains(payload, "write_coil") || strings.Contains(payload, "force_listen") {
			return "suspicious write command on industrial protocol"
		}
	}

	return ""
}

func isDefaultCredential(username, password string) bool {
	defaults := map[string][]string{
		"admin":   {"admin", "password", "1234", "12345", ""},
		"root":    {"root", "toor", "password", "admin", ""},
		"user":    {"user", "password", "1234", ""},
		"default": {"default", "password", ""},
		"pi":      {"raspberry", ""},
		"ubnt":    {"ubnt", ""},
		"support": {"support", ""},
		"guest":   {"guest", ""},
	}
	userLower := strings.ToLower(username)
	if passwords, ok := defaults[userLower]; ok {
		for _, p := range passwords {
			if password == p {
				return true
			}
		}
	}
	return false
}

func getStringDetail(event *core.SecurityEvent, key string) string {
	if event.Details == nil {
		return ""
	}
	if val, ok := event.Details[key].(string); ok {
		return val
	}
	return ""
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
