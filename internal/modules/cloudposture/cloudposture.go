package cloudposture

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

const ModuleName = "cloud_posture"

// Manager is the Cloud Posture Manager module providing configuration drift detection,
// misconfiguration scanning, secrets sprawl detection, and multi-cloud policy enforcement.
type Manager struct {
	logger        zerolog.Logger
	bus           *core.EventBus
	pipeline      *core.AlertPipeline
	cfg           *core.Config
	ctx           context.Context
	cancel        context.CancelFunc
	driftTracker  *DriftTracker
	secretScanner *SecretScanner
	policyEngine  *CloudPolicyEngine
}

func New() *Manager { return &Manager{} }

func (m *Manager) Name() string { return ModuleName }
func (m *Manager) Description() string {
	return "Cloud configuration drift detection, misconfiguration scanning, secrets sprawl detection, and multi-cloud policy enforcement"
}

func (m *Manager) Start(ctx context.Context, bus *core.EventBus, pipeline *core.AlertPipeline, cfg *core.Config) error {
	m.ctx, m.cancel = context.WithCancel(ctx)
	m.bus = bus
	m.pipeline = pipeline
	m.cfg = cfg
	m.logger = zerolog.New(zerolog.NewConsoleWriter()).With().Timestamp().Str("module", ModuleName).Logger()

	m.driftTracker = NewDriftTracker()
	m.secretScanner = NewSecretScanner()
	m.policyEngine = NewCloudPolicyEngine()

	m.logger.Info().Msg("cloud posture manager started")
	return nil
}

func (m *Manager) Stop() error {
	if m.cancel != nil {
		m.cancel()
	}
	return nil
}

func (m *Manager) HandleEvent(event *core.SecurityEvent) error {
	switch event.Type {
	case "config_change", "resource_update", "iac_deploy":
		m.handleConfigChange(event)
	case "config_scan", "posture_check":
		m.handleConfigScan(event)
	case "secret_detected", "credential_found":
		m.handleSecretDetection(event)
	case "log_entry", "audit_log":
		m.handleLogForSecrets(event)
	case "policy_check", "compliance_scan":
		m.handlePolicyCheck(event)
	}
	return nil
}

func (m *Manager) handleConfigChange(event *core.SecurityEvent) {
	resource := getStringDetail(event, "resource")
	resourceType := getStringDetail(event, "resource_type")
	changeType := getStringDetail(event, "change_type")
	user := getStringDetail(event, "user")
	oldValue := getStringDetail(event, "old_value")
	newValue := getStringDetail(event, "new_value")

	if resource == "" {
		return
	}

	drift := m.driftTracker.RecordChange(resource, resourceType, changeType, user, oldValue, newValue)

	if drift.UnexpectedChange {
		m.raiseAlert(event, core.SeverityHigh,
			"Configuration Drift Detected",
			fmt.Sprintf("Resource %s (%s) changed unexpectedly by %s. Change: %s. This deviates from the expected baseline.",
				resource, resourceType, user, changeType),
			"config_drift")
	}

	if drift.SecurityDegradation {
		m.raiseAlert(event, core.SeverityCritical,
			"Security Configuration Degraded",
			fmt.Sprintf("Resource %s security posture degraded: %s. Changed by %s.",
				resource, drift.DegradationReason, user),
			"security_degradation")
	}

	if drift.RapidChanges {
		m.raiseAlert(event, core.SeverityMedium,
			"Rapid Configuration Changes",
			fmt.Sprintf("Resource %s has been modified %d times in the last hour by %s. Possible misconfiguration or attack.",
				resource, drift.ChangeCount, user),
			"rapid_config_changes")
	}
}

func (m *Manager) handleConfigScan(event *core.SecurityEvent) {
	findings := getStringDetail(event, "findings")
	criticalCount := getIntDetail(event, "critical_count")
	highCount := getIntDetail(event, "high_count")
	resourceType := getStringDetail(event, "resource_type")

	// Check for common misconfigurations
	misconfigs := m.policyEngine.CheckMisconfigurations(event)
	for _, mc := range misconfigs {
		m.raiseAlert(event, mc.Severity,
			mc.Title,
			mc.Description,
			mc.AlertType)
	}

	if criticalCount > 0 {
		m.raiseAlert(event, core.SeverityCritical,
			"Critical Cloud Misconfigurations Found",
			fmt.Sprintf("Posture scan found %d critical and %d high misconfigurations in %s resources. Findings: %s",
				criticalCount, highCount, resourceType, truncate(findings, 200)),
			"critical_misconfigs")
	}
}

func (m *Manager) handleSecretDetection(event *core.SecurityEvent) {
	secretType := getStringDetail(event, "secret_type")
	location := getStringDetail(event, "location")
	file := getStringDetail(event, "file")

	m.raiseAlert(event, core.SeverityCritical,
		"Secret Detected in Infrastructure",
		fmt.Sprintf("Secret of type %q found in %s (file: %s). Rotate immediately and remove from source.",
			secretType, location, file),
		"secret_detected")
}

func (m *Manager) handleLogForSecrets(event *core.SecurityEvent) {
	logContent := getStringDetail(event, "content")
	if logContent == "" {
		logContent = event.Summary
	}

	secrets := m.secretScanner.Scan(logContent)
	for _, secret := range secrets {
		m.raiseAlert(event, core.SeverityCritical,
			"Secret Leaked in Logs",
			fmt.Sprintf("Secret of type %q detected in log output. Pattern: %s. Secrets must never appear in logs.",
				secret.Type, secret.PatternName),
			"secret_in_logs")
	}
}

func (m *Manager) handlePolicyCheck(event *core.SecurityEvent) {
	framework := getStringDetail(event, "framework")
	passCount := getIntDetail(event, "pass_count")
	failCount := getIntDetail(event, "fail_count")
	totalChecks := getIntDetail(event, "total_checks")

	if failCount > 0 && totalChecks > 0 {
		complianceRate := float64(passCount) / float64(totalChecks) * 100
		severity := core.SeverityMedium
		if complianceRate < 70 {
			severity = core.SeverityHigh
		}
		if complianceRate < 50 {
			severity = core.SeverityCritical
		}
		m.raiseAlert(event, severity,
			fmt.Sprintf("Compliance Check: %s", framework),
			fmt.Sprintf("Framework %s: %d/%d checks passed (%.1f%% compliance). %d failures require remediation.",
				framework, passCount, totalChecks, complianceRate, failCount),
			"compliance_failure")
	}
}

func (m *Manager) raiseAlert(event *core.SecurityEvent, severity core.Severity, title, description, alertType string) {
	newEvent := core.NewSecurityEvent(ModuleName, alertType, severity, description)
	newEvent.SourceIP = event.SourceIP
	newEvent.Details["original_event_id"] = event.ID

	if m.bus != nil {
		_ = m.bus.PublishEvent(newEvent)
	}

	alert := core.NewAlert(newEvent, title, description)
	alert.Mitigations = []string{
		"Implement infrastructure-as-code with drift detection",
		"Use policy-as-code frameworks (OPA, Sentinel) for enforcement",
		"Rotate any exposed secrets immediately",
		"Enable cloud provider security scanning services",
		"Maintain a baseline configuration and alert on deviations",
	}
	if m.pipeline != nil {
		m.pipeline.Process(alert)
	}
}

// DriftTracker monitors configuration changes for drift.
type DriftTracker struct {
	mu        sync.RWMutex
	baselines map[string]*resourceBaseline
	changes   map[string]*changeHistory
}

type resourceBaseline struct {
	ResourceType string
	ExpectedHash string
	LastKnown    string
	SetAt        time.Time
}

type changeHistory struct {
	Count    int
	Window   time.Time
	LastUser string
}

type DriftResult struct {
	UnexpectedChange    bool
	SecurityDegradation bool
	RapidChanges        bool
	DegradationReason   string
	ChangeCount         int
}

func NewDriftTracker() *DriftTracker {
	return &DriftTracker{
		baselines: make(map[string]*resourceBaseline),
		changes:   make(map[string]*changeHistory),
	}
}

func (dt *DriftTracker) RecordChange(resource, resourceType, changeType, user, oldValue, newValue string) DriftResult {
	dt.mu.Lock()
	defer dt.mu.Unlock()

	result := DriftResult{}
	now := time.Now()

	// Track change frequency
	hist, exists := dt.changes[resource]
	if !exists || now.Sub(hist.Window) > time.Hour {
		hist = &changeHistory{Window: now}
		dt.changes[resource] = hist
	}
	hist.Count++
	hist.LastUser = user
	result.ChangeCount = hist.Count

	if hist.Count > 10 {
		result.RapidChanges = true
	}

	// Check for security degradation patterns
	degradation := checkSecurityDegradation(resourceType, changeType, oldValue, newValue)
	if degradation != "" {
		result.SecurityDegradation = true
		result.DegradationReason = degradation
	}

	// Check against baseline
	baseline, hasBaseline := dt.baselines[resource]
	if hasBaseline && baseline.ExpectedHash != "" && newValue != baseline.ExpectedHash {
		result.UnexpectedChange = true
	}

	return result
}

func checkSecurityDegradation(resourceType, changeType, oldValue, newValue string) string {
	newLower := strings.ToLower(newValue)
	changeLower := strings.ToLower(changeType)

	// Public access enabled
	if strings.Contains(newLower, "public") && !strings.Contains(strings.ToLower(oldValue), "public") {
		return "resource changed from private to public access"
	}

	// Encryption disabled
	if strings.Contains(changeLower, "encryption") && (newLower == "false" || newLower == "disabled" || newLower == "none") {
		return "encryption was disabled"
	}

	// Logging disabled
	if strings.Contains(changeLower, "logging") && (newLower == "false" || newLower == "disabled") {
		return "logging was disabled"
	}

	// Firewall rule opened
	if strings.Contains(changeLower, "firewall") && strings.Contains(newLower, "0.0.0.0/0") {
		return "firewall opened to all traffic (0.0.0.0/0)"
	}

	// MFA disabled
	if strings.Contains(changeLower, "mfa") && (newLower == "false" || newLower == "disabled") {
		return "multi-factor authentication was disabled"
	}

	return ""
}

// SecretScanner detects secrets in text content.
type SecretScanner struct {
	patterns []secretPattern
}

type secretPattern struct {
	Name  string
	Type  string
	Regex *regexp.Regexp
}

type SecretFinding struct {
	PatternName string
	Type        string
}

func NewSecretScanner() *SecretScanner {
	return &SecretScanner{
		patterns: []secretPattern{
			{Name: "aws_access_key", Type: "AWS Access Key", Regex: regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
			{Name: "aws_secret_key", Type: "AWS Secret Key", Regex: regexp.MustCompile(`(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}`)},
			{Name: "github_token", Type: "GitHub Token", Regex: regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`)},
			{Name: "github_oauth", Type: "GitHub OAuth", Regex: regexp.MustCompile(`gho_[a-zA-Z0-9]{36}`)},
			{Name: "gitlab_token", Type: "GitLab Token", Regex: regexp.MustCompile(`glpat-[a-zA-Z0-9\-]{20,}`)},
			{Name: "slack_token", Type: "Slack Token", Regex: regexp.MustCompile(`xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34}`)},
			{Name: "openai_key", Type: "OpenAI API Key", Regex: regexp.MustCompile(`sk-[a-zA-Z0-9]{20,}`)},
			{Name: "stripe_key", Type: "Stripe Key", Regex: regexp.MustCompile(`(?:sk|pk)_(test|live)_[a-zA-Z0-9]{24,}`)},
			{Name: "private_key", Type: "Private Key", Regex: regexp.MustCompile(`-----BEGIN\s+(RSA\s+|EC\s+|DSA\s+)?PRIVATE\s+KEY-----`)},
			{Name: "generic_secret", Type: "Generic Secret", Regex: regexp.MustCompile(`(?i)(password|secret|token|api_key|apikey)\s*[=:]\s*['"][^'"]{8,}['"]`)},
			{Name: "connection_string", Type: "Connection String", Regex: regexp.MustCompile(`(?i)(mongodb|postgres|mysql|redis|amqp)://[^\s]+:[^\s]+@`)},
			{Name: "jwt_token", Type: "JWT Token", Regex: regexp.MustCompile(`eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}`)},
		},
	}
}

func (ss *SecretScanner) Scan(content string) []SecretFinding {
	var findings []SecretFinding
	for _, p := range ss.patterns {
		if p.Regex.MatchString(content) {
			findings = append(findings, SecretFinding{PatternName: p.Name, Type: p.Type})
		}
	}
	return findings
}

// CloudPolicyEngine checks for common cloud misconfigurations.
type CloudPolicyEngine struct {
	rules []policyRule
}

type policyRule struct {
	ResourceType string
	Check        func(event *core.SecurityEvent) *Misconfiguration
}

type Misconfiguration struct {
	Title       string
	Description string
	Severity    core.Severity
	AlertType   string
}

func NewCloudPolicyEngine() *CloudPolicyEngine {
	pe := &CloudPolicyEngine{}
	pe.rules = []policyRule{
		{ResourceType: "storage_bucket", Check: checkPublicBucket},
		{ResourceType: "security_group", Check: checkOpenSecurityGroup},
		{ResourceType: "database", Check: checkPublicDatabase},
		{ResourceType: "iam_policy", Check: checkOverlyPermissiveIAM},
	}
	return pe
}

func (pe *CloudPolicyEngine) CheckMisconfigurations(event *core.SecurityEvent) []*Misconfiguration {
	var results []*Misconfiguration
	resourceType := getStringDetail(event, "resource_type")

	for _, rule := range pe.rules {
		if rule.ResourceType == resourceType || resourceType == "" {
			if mc := rule.Check(event); mc != nil {
				results = append(results, mc)
			}
		}
	}
	return results
}

func checkPublicBucket(event *core.SecurityEvent) *Misconfiguration {
	acl := strings.ToLower(getStringDetail(event, "acl"))
	publicAccess := strings.ToLower(getStringDetail(event, "public_access"))
	if acl == "public-read" || acl == "public-read-write" || publicAccess == "true" || publicAccess == "enabled" {
		return &Misconfiguration{
			Title:       "Public Storage Bucket",
			Description: fmt.Sprintf("Storage bucket %s has public access enabled. This exposes data to the internet.", getStringDetail(event, "resource")),
			Severity:    core.SeverityCritical,
			AlertType:   "public_bucket",
		}
	}
	return nil
}

func checkOpenSecurityGroup(event *core.SecurityEvent) *Misconfiguration {
	ingressRule := getStringDetail(event, "ingress_cidr")
	port := getStringDetail(event, "port")
	if ingressRule == "0.0.0.0/0" && (port == "22" || port == "3389" || port == "3306" || port == "5432" || port == "27017") {
		return &Misconfiguration{
			Title:       "Security Group Open to Internet",
			Description: fmt.Sprintf("Security group allows inbound traffic from 0.0.0.0/0 on sensitive port %s.", port),
			Severity:    core.SeverityCritical,
			AlertType:   "open_security_group",
		}
	}
	return nil
}

func checkPublicDatabase(event *core.SecurityEvent) *Misconfiguration {
	publiclyAccessible := strings.ToLower(getStringDetail(event, "publicly_accessible"))
	if publiclyAccessible == "true" || publiclyAccessible == "yes" {
		return &Misconfiguration{
			Title:       "Publicly Accessible Database",
			Description: fmt.Sprintf("Database %s is publicly accessible. Databases should not be exposed to the internet.", getStringDetail(event, "resource")),
			Severity:    core.SeverityCritical,
			AlertType:   "public_database",
		}
	}
	return nil
}

func checkOverlyPermissiveIAM(event *core.SecurityEvent) *Misconfiguration {
	policy := getStringDetail(event, "policy")
	if strings.Contains(policy, "\"Action\": \"*\"") || strings.Contains(policy, "\"Resource\": \"*\"") {
		return &Misconfiguration{
			Title:       "Overly Permissive IAM Policy",
			Description: fmt.Sprintf("IAM policy on %s uses wildcard permissions. Apply least-privilege principle.", getStringDetail(event, "resource")),
			Severity:    core.SeverityHigh,
			AlertType:   "permissive_iam",
		}
	}
	return nil
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

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
