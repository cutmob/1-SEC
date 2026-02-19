package quantumcrypto

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/1sec-project/1sec/internal/core"
	"github.com/rs/zerolog"
)

const ModuleName = "quantum_crypto"

// Monitor is the Quantum-Ready Crypto module providing cryptographic inventory scanning,
// PQC migration tooling, crypto-agility assessment, TLS configuration auditing,
// and harvest-now-decrypt-later (HNDL) traffic pattern detection.
type Monitor struct {
	logger      zerolog.Logger
	bus         *core.EventBus
	pipeline    *core.AlertPipeline
	cfg         *core.Config
	ctx         context.Context
	cancel      context.CancelFunc
	inventory   *CryptoInventory
	tlsAuditor  *TLSAuditor
	hndlDet     *HNDLDetector
}

func New() *Monitor { return &Monitor{} }

func (m *Monitor) Name() string { return ModuleName }
func (m *Monitor) Description() string {
	return "Cryptographic inventory scanning, post-quantum migration assessment, crypto-agility framework, TLS configuration auditing, and harvest-now-decrypt-later detection"
}

func (m *Monitor) Start(ctx context.Context, bus *core.EventBus, pipeline *core.AlertPipeline, cfg *core.Config) error {
	m.ctx, m.cancel = context.WithCancel(ctx)
	m.bus = bus
	m.pipeline = pipeline
	m.cfg = cfg
	m.logger = zerolog.New(zerolog.NewConsoleWriter()).With().Timestamp().Str("module", ModuleName).Logger()

	m.inventory = NewCryptoInventory()
	m.tlsAuditor = NewTLSAuditor()
	m.hndlDet = NewHNDLDetector()

	go m.hndlDet.CleanupLoop(m.ctx)

	m.logger.Info().Msg("quantum-ready crypto monitor started")
	return nil
}

func (m *Monitor) Stop() error {
	if m.cancel != nil {
		m.cancel()
	}
	return nil
}

func (m *Monitor) HandleEvent(event *core.SecurityEvent) error {
	switch event.Type {
	case "tls_handshake", "tls_connection", "ssl_connection":
		m.handleTLSEvent(event)
	case "crypto_usage", "encryption_operation", "key_generation":
		m.handleCryptoUsage(event)
	case "certificate_event", "cert_expiry", "cert_issued":
		m.handleCertEvent(event)
	case "crypto_scan", "crypto_inventory":
		m.handleInventoryScan(event)
	case "traffic_capture", "bulk_data_transfer", "encrypted_exfiltration":
		m.handleHNDLEvent(event)
	}
	return nil
}

func (m *Monitor) handleTLSEvent(event *core.SecurityEvent) {
	version := getStringDetail(event, "tls_version")
	cipherSuite := getStringDetail(event, "cipher_suite")
	keyExchange := getStringDetail(event, "key_exchange")
	serverName := getStringDetail(event, "server_name")

	findings := m.tlsAuditor.Audit(version, cipherSuite, keyExchange)

	for _, f := range findings {
		m.raiseAlert(event, f.Severity,
			f.Title,
			fmt.Sprintf("TLS connection to %s: %s (version: %s, cipher: %s, key exchange: %s)",
				serverName, f.Description, version, cipherSuite, keyExchange),
			f.AlertType)
	}

	// Track crypto usage in inventory
	if cipherSuite != "" {
		m.inventory.RecordUsage("tls_cipher", cipherSuite, serverName)
	}
	if keyExchange != "" {
		m.inventory.RecordUsage("key_exchange", keyExchange, serverName)
	}
}

func (m *Monitor) handleCryptoUsage(event *core.SecurityEvent) {
	algorithm := getStringDetail(event, "algorithm")
	keySize := getIntDetail(event, "key_size")
	purpose := getStringDetail(event, "purpose")
	component := getStringDetail(event, "component")

	if algorithm == "" {
		return
	}

	m.inventory.RecordUsage(purpose, algorithm, component)

	// Check for quantum-vulnerable algorithms
	vuln := classifyQuantumVulnerability(algorithm, keySize)
	if vuln.Vulnerable {
		m.raiseAlert(event, vuln.Severity,
			"Quantum-Vulnerable Cryptography Detected",
			fmt.Sprintf("Component %s uses %s (%d-bit) for %s. %s",
				component, algorithm, keySize, purpose, vuln.Recommendation),
			"quantum_vulnerable_crypto")
	}

	// Check for weak key sizes
	if isWeakKeySize(algorithm, keySize) {
		m.raiseAlert(event, core.SeverityHigh,
			"Weak Cryptographic Key Size",
			fmt.Sprintf("Component %s uses %s with %d-bit key for %s. This is below recommended minimum.",
				component, algorithm, keySize, purpose),
			"weak_key_size")
	}
}

func (m *Monitor) handleCertEvent(event *core.SecurityEvent) {
	certDomain := getStringDetail(event, "domain")
	expiryDays := getIntDetail(event, "days_until_expiry")
	keyAlgo := getStringDetail(event, "key_algorithm")
	keySize := getIntDetail(event, "key_size")
	issuer := getStringDetail(event, "issuer")

	if expiryDays > 0 && expiryDays <= 30 {
		severity := core.SeverityMedium
		if expiryDays <= 7 {
			severity = core.SeverityHigh
		}
		if expiryDays <= 1 {
			severity = core.SeverityCritical
		}
		m.raiseAlert(event, severity,
			"Certificate Expiring Soon",
			fmt.Sprintf("Certificate for %s expires in %d days (issuer: %s)", certDomain, expiryDays, issuer),
			"cert_expiry")
	}

	if keyAlgo != "" {
		vuln := classifyQuantumVulnerability(keyAlgo, keySize)
		if vuln.Vulnerable {
			m.raiseAlert(event, core.SeverityMedium,
				"Certificate Uses Quantum-Vulnerable Algorithm",
				fmt.Sprintf("Certificate for %s uses %s (%d-bit). %s", certDomain, keyAlgo, keySize, vuln.Recommendation),
				"cert_quantum_vulnerable")
		}
	}
}

func (m *Monitor) handleInventoryScan(event *core.SecurityEvent) {
	totalAlgorithms := getIntDetail(event, "total_algorithms")
	vulnerableCount := getIntDetail(event, "vulnerable_count")
	pqcReadyCount := getIntDetail(event, "pqc_ready_count")

	if vulnerableCount > 0 {
		severity := core.SeverityMedium
		if vulnerableCount > 10 {
			severity = core.SeverityHigh
		}
		pctVulnerable := 0.0
		if totalAlgorithms > 0 {
			pctVulnerable = float64(vulnerableCount) / float64(totalAlgorithms) * 100
		}
		m.raiseAlert(event, severity,
			"Quantum-Vulnerable Crypto Inventory Report",
			fmt.Sprintf("Crypto inventory scan: %d/%d algorithms (%.1f%%) are quantum-vulnerable. %d are PQC-ready. Begin migration planning.",
				vulnerableCount, totalAlgorithms, pctVulnerable, pqcReadyCount),
			"crypto_inventory_report")
	}
}

func (m *Monitor) raiseAlert(event *core.SecurityEvent, severity core.Severity, title, description, alertType string) {
	newEvent := core.NewSecurityEvent(ModuleName, alertType, severity, description)
	newEvent.SourceIP = event.SourceIP
	newEvent.Details["original_event_id"] = event.ID

	if m.bus != nil {
		_ = m.bus.PublishEvent(newEvent)
	}

	alert := core.NewAlert(newEvent, title, description)
	alert.Mitigations = []string{
		"Inventory all cryptographic algorithm usage across your infrastructure",
		"Prioritize migration of key exchange and digital signatures to PQC algorithms",
		"Adopt NIST-approved post-quantum standards (ML-KEM, ML-DSA, SLH-DSA)",
		"Implement crypto-agility to enable algorithm swaps without code changes",
		"Monitor for harvest-now-decrypt-later data collection targeting your traffic",
	}
	if m.pipeline != nil {
		m.pipeline.Process(alert)
	}
}

// CryptoInventory tracks all cryptographic algorithm usage.
type CryptoInventory struct {
	mu      sync.RWMutex
	entries map[string]*cryptoEntry
}

type cryptoEntry struct {
	Purpose    string
	Algorithm  string
	Components map[string]bool
	FirstSeen  time.Time
	LastSeen   time.Time
	UsageCount int
}

func NewCryptoInventory() *CryptoInventory {
	return &CryptoInventory{entries: make(map[string]*cryptoEntry)}
}

func (ci *CryptoInventory) RecordUsage(purpose, algorithm, component string) {
	ci.mu.Lock()
	defer ci.mu.Unlock()

	key := purpose + ":" + algorithm
	entry, exists := ci.entries[key]
	if !exists {
		entry = &cryptoEntry{
			Purpose:    purpose,
			Algorithm:  algorithm,
			Components: make(map[string]bool),
			FirstSeen:  time.Now(),
		}
		ci.entries[key] = entry
	}
	if component != "" {
		entry.Components[component] = true
	}
	entry.LastSeen = time.Now()
	entry.UsageCount++
}

// TLSAuditor checks TLS configurations for security issues.
type TLSAuditor struct {
	weakCiphers    *regexp.Regexp
	weakVersions   map[string]bool
	weakKeyExchange map[string]bool
}

type TLSFinding struct {
	Title       string
	Description string
	Severity    core.Severity
	AlertType   string
}

func NewTLSAuditor() *TLSAuditor {
	return &TLSAuditor{
		weakCiphers: regexp.MustCompile(`(?i)(RC4|DES|3DES|NULL|EXPORT|anon|MD5|CBC)`),
		weakVersions: map[string]bool{
			"SSLv2": true, "SSLv3": true, "TLSv1.0": true, "TLSv1.1": true,
			"ssl2": true, "ssl3": true, "tls1.0": true, "tls1.1": true,
		},
		weakKeyExchange: map[string]bool{
			"RSA": true, "DHE-1024": true, "DH-1024": true,
		},
	}
}

func (ta *TLSAuditor) Audit(version, cipherSuite, keyExchange string) []TLSFinding {
	var findings []TLSFinding

	if ta.weakVersions[version] {
		findings = append(findings, TLSFinding{
			Title:       "Deprecated TLS Version",
			Description: fmt.Sprintf("TLS version %s is deprecated and insecure", version),
			Severity:    core.SeverityHigh,
			AlertType:   "weak_tls_version",
		})
	}

	if cipherSuite != "" && ta.weakCiphers.MatchString(cipherSuite) {
		findings = append(findings, TLSFinding{
			Title:       "Weak Cipher Suite",
			Description: fmt.Sprintf("Cipher suite %s contains weak algorithms", cipherSuite),
			Severity:    core.SeverityHigh,
			AlertType:   "weak_cipher",
		})
	}

	if ta.weakKeyExchange[keyExchange] {
		findings = append(findings, TLSFinding{
			Title:       "Weak Key Exchange",
			Description: fmt.Sprintf("Key exchange %s is vulnerable to quantum attacks", keyExchange),
			Severity:    core.SeverityMedium,
			AlertType:   "weak_key_exchange",
		})
	}

	return findings
}

type quantumVuln struct {
	Vulnerable     bool
	Severity       core.Severity
	Recommendation string
}

func classifyQuantumVulnerability(algorithm string, keySize int) quantumVuln {
	algoLower := strings.ToLower(algorithm)

	// Algorithms broken by quantum computers (Shor's algorithm)
	quantumBroken := map[string]bool{
		"rsa": true, "ecdsa": true, "ecdh": true, "ecdhe": true,
		"dsa": true, "dh": true, "dhe": true, "elgamal": true,
		"ed25519": true, "ed448": true, "x25519": true, "x448": true,
		"secp256r1": true, "secp384r1": true, "secp521r1": true,
		"p-256": true, "p-384": true, "p-521": true,
	}

	// PQC-safe algorithms (NIST approved)
	pqcSafe := map[string]bool{
		"ml-kem": true, "ml-dsa": true, "slh-dsa": true,
		"kyber": true, "dilithium": true, "sphincs+": true,
		"falcon": true, "bike": true, "hqc": true,
		"ml-kem-768": true, "ml-kem-1024": true,
		"ml-dsa-65": true, "ml-dsa-87": true,
	}

	if pqcSafe[algoLower] {
		return quantumVuln{Vulnerable: false}
	}

	for broken := range quantumBroken {
		if strings.Contains(algoLower, broken) {
			return quantumVuln{
				Vulnerable:     true,
				Severity:       core.SeverityMedium,
				Recommendation: fmt.Sprintf("Migrate from %s to a NIST-approved PQC algorithm (ML-KEM for key exchange, ML-DSA for signatures).", algorithm),
			}
		}
	}

	// Symmetric algorithms: quantum reduces security by half (Grover's algorithm)
	symmetric := map[string]bool{
		"aes": true, "chacha20": true, "aes-gcm": true, "aes-cbc": true,
	}
	for sym := range symmetric {
		if strings.Contains(algoLower, sym) {
			if keySize > 0 && keySize < 256 {
				return quantumVuln{
					Vulnerable:     true,
					Severity:       core.SeverityLow,
					Recommendation: fmt.Sprintf("Increase %s key size to 256-bit for quantum resistance (Grover's algorithm halves effective security).", algorithm),
				}
			}
			return quantumVuln{Vulnerable: false}
		}
	}

	return quantumVuln{Vulnerable: false}
}

func isWeakKeySize(algorithm string, keySize int) bool {
	if keySize <= 0 {
		return false
	}
	algoLower := strings.ToLower(algorithm)
	if strings.Contains(algoLower, "rsa") && keySize < 2048 {
		return true
	}
	if (strings.Contains(algoLower, "ec") || strings.Contains(algoLower, "ed")) && keySize < 256 {
		return true
	}
	if strings.Contains(algoLower, "aes") && keySize < 128 {
		return true
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

func getIntDetail(event *core.SecurityEvent, key string) int {
	if event.Details == nil {
		return 0
	}
	switch v := event.Details[key].(type) {
	case int:
		return v
	case float64:
		return int(v)
	}
	return 0
}

// handleHNDLEvent detects harvest-now-decrypt-later patterns: bulk encrypted
// traffic capture targeting quantum-vulnerable encryption.
func (m *Monitor) handleHNDLEvent(event *core.SecurityEvent) {
	sourceIP := event.SourceIP
	destIP := event.DestIP
	bytesTransferred := getIntDetail(event, "bytes_transferred")
	protocol := getStringDetail(event, "protocol")
	cipherSuite := getStringDetail(event, "cipher_suite")
	keyExchange := getStringDetail(event, "key_exchange")
	captureType := getStringDetail(event, "capture_type")

	result := m.hndlDet.Analyze(sourceIP, destIP, bytesTransferred, protocol, cipherSuite, keyExchange, captureType)

	if result.HNDLSuspected {
		m.raiseAlert(event, core.SeverityCritical,
			"Harvest-Now-Decrypt-Later Attack Suspected",
			fmt.Sprintf("Bulk encrypted traffic capture detected from %s to %s. "+
				"Volume: %s in %s. Cipher: %s (key exchange: %s). "+
				"Traffic is using quantum-vulnerable encryption and is being captured at scale. "+
				"Nation-state actors collect encrypted data now to decrypt with future quantum computers. "+
				"Indicators: %s.",
				sourceIP, destIP, result.VolumeStr, result.TimeWindow,
				cipherSuite, keyExchange, strings.Join(result.Indicators, ", ")),
			"hndl_attack")
	}

	if result.BulkCapture {
		m.raiseAlert(event, core.SeverityHigh,
			"Bulk Encrypted Traffic Capture Detected",
			fmt.Sprintf("Unusual bulk traffic capture from %s: %s transferred in %s. "+
				"Capture type: %s. This may indicate passive interception for future decryption.",
				sourceIP, result.VolumeStr, result.TimeWindow, captureType),
			"bulk_traffic_capture")
	}
}

// ---------------------------------------------------------------------------
// HNDLDetector — harvest-now-decrypt-later pattern detection
// ---------------------------------------------------------------------------

type HNDLDetector struct {
	mu       sync.Mutex
	captures map[string]*hndlProfile // key: sourceIP
}

type hndlProfile struct {
	destinations map[string]int64 // destIP -> bytes
	totalBytes   int64
	ciphers      map[string]int
	keyExchanges map[string]int
	captureTypes map[string]int
	eventCount   int
	windowStart  time.Time
	lastSeen     time.Time
}

type HNDLResult struct {
	HNDLSuspected bool
	BulkCapture   bool
	VolumeStr     string
	TimeWindow    string
	Indicators    []string
}

func NewHNDLDetector() *HNDLDetector {
	return &HNDLDetector{captures: make(map[string]*hndlProfile)}
}

func (h *HNDLDetector) Analyze(sourceIP, destIP string, bytes int, protocol, cipher, keyExchange, captureType string) HNDLResult {
	h.mu.Lock()
	defer h.mu.Unlock()

	result := HNDLResult{}
	now := time.Now()

	profile, exists := h.captures[sourceIP]
	if !exists || now.Sub(profile.windowStart) > 1*time.Hour {
		profile = &hndlProfile{
			destinations: make(map[string]int64),
			ciphers:      make(map[string]int),
			keyExchanges: make(map[string]int),
			captureTypes: make(map[string]int),
			windowStart:  now,
		}
		h.captures[sourceIP] = profile
	}

	profile.lastSeen = now
	profile.totalBytes += int64(bytes)
	profile.eventCount++
	if destIP != "" {
		profile.destinations[destIP] += int64(bytes)
	}
	if cipher != "" {
		profile.ciphers[cipher]++
	}
	if keyExchange != "" {
		profile.keyExchanges[keyExchange]++
	}
	if captureType != "" {
		profile.captureTypes[captureType]++
	}

	result.VolumeStr = formatBytes(profile.totalBytes)
	result.TimeWindow = now.Sub(profile.windowStart).Round(time.Second).String()

	var indicators []string

	// High volume capture
	if profile.totalBytes > 1<<30 { // > 1 GB
		indicators = append(indicators, fmt.Sprintf("high volume (%s)", formatBytes(profile.totalBytes)))
	}

	// Many destinations (broad interception)
	if len(profile.destinations) > 20 {
		indicators = append(indicators, fmt.Sprintf("broad targeting (%d destinations)", len(profile.destinations)))
	}

	// Quantum-vulnerable ciphers being captured
	quantumVulnCiphers := 0
	for c := range profile.ciphers {
		cLower := strings.ToLower(c)
		if strings.Contains(cLower, "rsa") || strings.Contains(cLower, "ecdh") ||
			strings.Contains(cLower, "ecdsa") || strings.Contains(cLower, "dhe") {
			quantumVulnCiphers++
		}
	}
	if quantumVulnCiphers > 0 {
		indicators = append(indicators, "quantum-vulnerable ciphers targeted")
	}

	// Passive capture indicators
	if profile.captureTypes["mirror"] > 0 || profile.captureTypes["tap"] > 0 ||
		profile.captureTypes["pcap"] > 0 || profile.captureTypes["span"] > 0 {
		indicators = append(indicators, "passive network capture detected")
	}

	// HNDL: high volume + quantum-vulnerable + broad targeting
	if len(indicators) >= 2 && profile.totalBytes > 100<<20 { // > 100 MB
		result.HNDLSuspected = true
		result.Indicators = indicators
	}

	// Bulk capture: any large-scale capture
	if profile.totalBytes > 500<<20 && profile.eventCount > 100 { // > 500 MB, 100+ events
		result.BulkCapture = true
	}

	return result
}

func (h *HNDLDetector) CleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			h.mu.Lock()
			cutoff := time.Now().Add(-2 * time.Hour)
			for ip, p := range h.captures {
				if p.lastSeen.Before(cutoff) {
					delete(h.captures, ip)
				}
			}
			h.mu.Unlock()
		}
	}
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
