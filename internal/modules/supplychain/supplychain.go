package supplychain

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/1sec-project/1sec/internal/core"
	"github.com/rs/zerolog"
)

const ModuleName = "supply_chain"

// Sentinel is the Supply Chain Sentinel module providing SBOM generation,
// package integrity verification, CI/CD hardening checks, and typosquatting detection.
type Sentinel struct {
	logger       zerolog.Logger
	bus          *core.EventBus
	pipeline     *core.AlertPipeline
	cfg          *core.Config
	ctx          context.Context
	cancel       context.CancelFunc
	pkgTracker   *PackageTracker
	cicdMonitor  *CICDMonitor
	typosquatDet *TyposquatDetector
}

func New() *Sentinel { return &Sentinel{} }

func (s *Sentinel) Name() string { return ModuleName }
func (s *Sentinel) Description() string {
	return "SBOM generation, package integrity verification, CI/CD pipeline hardening, and typosquatting detection"
}
func (s *Sentinel) EventTypes() []string {
	return []string{
		"package_install", "dependency_add", "package_update",
		"build_artifact", "artifact_deploy",
		"cicd_event", "pipeline_run", "pipeline_config_change",
		"sbom_scan",
	}
}

func (s *Sentinel) Start(ctx context.Context, bus *core.EventBus, pipeline *core.AlertPipeline, cfg *core.Config) error {
	s.ctx, s.cancel = context.WithCancel(ctx)
	s.bus = bus
	s.pipeline = pipeline
	s.cfg = cfg
	s.logger = zerolog.New(zerolog.NewConsoleWriter()).With().Timestamp().Str("module", ModuleName).Logger()

	s.pkgTracker = NewPackageTracker()
	s.cicdMonitor = NewCICDMonitor()
	s.typosquatDet = NewTyposquatDetector()

	s.logger.Info().Msg("supply chain sentinel started")
	return nil
}

func (s *Sentinel) Stop() error {
	if s.cancel != nil {
		s.cancel()
	}
	return nil
}

func (s *Sentinel) HandleEvent(event *core.SecurityEvent) error {
	switch event.Type {
	case "package_install", "dependency_add", "package_update":
		s.handlePackageEvent(event)
	case "build_artifact", "artifact_deploy":
		s.handleArtifactEvent(event)
	case "cicd_event", "pipeline_run", "pipeline_config_change":
		s.handleCICDEvent(event)
	case "sbom_scan":
		s.handleSBOMEvent(event)
	}
	return nil
}

func (s *Sentinel) handlePackageEvent(event *core.SecurityEvent) {
	pkgName := getStringDetail(event, "package_name")
	pkgVersion := getStringDetail(event, "version")
	registry := getStringDetail(event, "registry")
	hash := getStringDetail(event, "hash")
	expectedHash := getStringDetail(event, "expected_hash")

	if pkgName == "" {
		return
	}

	// Typosquatting detection
	if suspect := s.typosquatDet.Check(pkgName, registry); suspect != "" {
		s.raiseAlert(event, core.SeverityHigh,
			"Typosquatting Suspected",
			fmt.Sprintf("Package %q in %s looks like a typosquat of popular package %q. Verify before installing.",
				pkgName, registry, suspect),
			"typosquat")
	}

	// Package integrity check
	if hash != "" && expectedHash != "" && hash != expectedHash {
		s.raiseAlert(event, core.SeverityCritical,
			"Package Integrity Violation",
			fmt.Sprintf("Package %s@%s hash mismatch. Expected: %s, Got: %s. Possible supply chain compromise.",
				pkgName, pkgVersion, truncate(expectedHash, 16), truncate(hash, 16)),
			"integrity_violation")
	}

	// Dependency confusion: private package name appearing in public registry
	if getStringDetail(event, "scope") == "private" && registry == "public" {
		s.raiseAlert(event, core.SeverityCritical,
			"Dependency Confusion Attack",
			fmt.Sprintf("Private package %q resolved from public registry %s. This is a dependency confusion attack vector.",
				pkgName, registry),
			"dependency_confusion")
	}

	// Track the package
	s.pkgTracker.Record(pkgName, pkgVersion, registry, hash)

	// Check for known malicious packages
	if s.pkgTracker.IsKnownMalicious(pkgName) {
		s.raiseAlert(event, core.SeverityCritical,
			"Known Malicious Package",
			fmt.Sprintf("Package %s@%s is flagged as malicious. Remove immediately.", pkgName, pkgVersion),
			"malicious_package")
	}
}

func (s *Sentinel) handleArtifactEvent(event *core.SecurityEvent) {
	artifactName := getStringDetail(event, "artifact_name")
	signature := getStringDetail(event, "signature")
	provenance := getStringDetail(event, "provenance")

	if artifactName == "" {
		return
	}

	// Check for unsigned artifacts
	if signature == "" {
		s.raiseAlert(event, core.SeverityHigh,
			"Unsigned Build Artifact",
			fmt.Sprintf("Artifact %s has no signature. Build artifacts should be signed for integrity verification.", artifactName),
			"unsigned_artifact")
	}

	// Check for missing provenance
	if provenance == "" {
		s.raiseAlert(event, core.SeverityMedium,
			"Missing Artifact Provenance",
			fmt.Sprintf("Artifact %s has no provenance attestation. Cannot verify build origin.", artifactName),
			"missing_provenance")
	}
}

func (s *Sentinel) handleCICDEvent(event *core.SecurityEvent) {
	action := getStringDetail(event, "action")
	pipelineName := getStringDetail(event, "pipeline_name")
	user := getStringDetail(event, "user")

	if action == "" {
		return
	}

	result := s.cicdMonitor.Analyze(action, pipelineName, user, event.SourceIP)

	if result.UnauthorizedChange {
		s.raiseAlert(event, core.SeverityCritical,
			"Unauthorized CI/CD Pipeline Change",
			fmt.Sprintf("User %s modified pipeline %q from IP %s. This change was not authorized.",
				user, pipelineName, event.SourceIP),
			"unauthorized_cicd_change")
	}

	if result.SuspiciousStep {
		s.raiseAlert(event, core.SeverityHigh,
			"Suspicious CI/CD Step Detected",
			fmt.Sprintf("Pipeline %q contains suspicious step: %s", pipelineName, action),
			"suspicious_cicd_step")
	}

	if result.SecretExposure {
		s.raiseAlert(event, core.SeverityCritical,
			"Secret Exposure in CI/CD",
			fmt.Sprintf("Pipeline %q may be exposing secrets in logs or artifacts.", pipelineName),
			"cicd_secret_exposure")
	}
}

func (s *Sentinel) handleSBOMEvent(event *core.SecurityEvent) {
	vulnCount := getIntDetail(event, "vulnerability_count")
	criticalCount := getIntDetail(event, "critical_count")
	highCount := getIntDetail(event, "high_count")

	if criticalCount > 0 {
		s.raiseAlert(event, core.SeverityCritical,
			"Critical Vulnerabilities in Dependencies",
			fmt.Sprintf("SBOM scan found %d critical and %d high vulnerabilities across %d total findings.",
				criticalCount, highCount, vulnCount),
			"sbom_critical_vulns")
	} else if highCount > 0 {
		s.raiseAlert(event, core.SeverityHigh,
			"High Vulnerabilities in Dependencies",
			fmt.Sprintf("SBOM scan found %d high vulnerabilities across %d total findings.", highCount, vulnCount),
			"sbom_high_vulns")
	}
}

func (s *Sentinel) raiseAlert(event *core.SecurityEvent, severity core.Severity, title, description, alertType string) {
	newEvent := core.NewSecurityEvent(ModuleName, alertType, severity, description)
	newEvent.SourceIP = event.SourceIP
	newEvent.Details["original_event_id"] = event.ID

	if s.bus != nil {
		_ = s.bus.PublishEvent(newEvent)
	}

	alert := core.NewAlert(newEvent, title, description)
	alert.Mitigations = getSupplyChainMitigations(alertType)
	if s.pipeline != nil {
		s.pipeline.Process(alert)
	}
}

// PackageTracker tracks installed packages and known malicious ones.
type PackageTracker struct {
	mu        sync.RWMutex
	packages  map[string]*PackageRecord
	malicious map[string]bool
}

type PackageRecord struct {
	Name      string
	Version   string
	Registry  string
	Hash      string
	FirstSeen time.Time
}

func NewPackageTracker() *PackageTracker {
	pt := &PackageTracker{
		packages:  make(map[string]*PackageRecord),
		malicious: make(map[string]bool),
	}
	// Seed with known malicious package patterns
	knownMalicious := []string{
		"event-stream-malicious", "flatmap-stream",
		"ua-parser-js-malicious", "coa-malicious",
		"colors-malicious", "faker-malicious",
		"peacenotwar", "node-ipc-malicious",
	}
	for _, pkg := range knownMalicious {
		pt.malicious[pkg] = true
	}
	return pt
}

func (pt *PackageTracker) Record(name, version, registry, hash string) {
	pt.mu.Lock()
	defer pt.mu.Unlock()
	key := registry + ":" + name
	pt.packages[key] = &PackageRecord{
		Name: name, Version: version, Registry: registry,
		Hash: hash, FirstSeen: time.Now(),
	}
}

func (pt *PackageTracker) IsKnownMalicious(name string) bool {
	pt.mu.RLock()
	defer pt.mu.RUnlock()
	return pt.malicious[strings.ToLower(name)]
}

// CICDMonitor analyzes CI/CD pipeline events for security issues.
type CICDMonitor struct {
	mu              sync.RWMutex
	authorizedUsers map[string]bool
	suspiciousSteps *regexp.Regexp
	secretPatterns  *regexp.Regexp
}

type CICDResult struct {
	UnauthorizedChange bool
	SuspiciousStep     bool
	SecretExposure     bool
}

func NewCICDMonitor() *CICDMonitor {
	return &CICDMonitor{
		authorizedUsers: make(map[string]bool),
		suspiciousSteps: regexp.MustCompile(`(?i)(curl\s+.*\|\s*sh|wget\s+.*\|\s*bash|eval\s*\(|base64\s+-d|nc\s+-[elp]|reverse.?shell|crypto.?min)`),
		secretPatterns:  regexp.MustCompile(`(?i)(echo\s+\$\{?[A-Z_]*SECRET|echo\s+\$\{?[A-Z_]*TOKEN|echo\s+\$\{?[A-Z_]*PASSWORD|echo\s+\$\{?[A-Z_]*KEY|printenv|env\s*$|set\s*$)`),
	}
}

func (cm *CICDMonitor) Analyze(action, pipeline, user, ip string) CICDResult {
	result := CICDResult{}

	if cm.suspiciousSteps.MatchString(action) {
		result.SuspiciousStep = true
	}

	if cm.secretPatterns.MatchString(action) {
		result.SecretExposure = true
	}

	cm.mu.RLock()
	if len(cm.authorizedUsers) > 0 && !cm.authorizedUsers[user] {
		result.UnauthorizedChange = true
	}
	cm.mu.RUnlock()

	return result
}

// TyposquatDetector detects potential typosquatting attacks on package names.
type TyposquatDetector struct {
	popularPackages map[string][]string // registry -> list of popular package names
}

func NewTyposquatDetector() *TyposquatDetector {
	return &TyposquatDetector{
		popularPackages: map[string][]string{
			"npm": {
				"lodash", "express", "react", "axios", "moment",
				"webpack", "typescript", "next", "vue", "angular",
				"jquery", "chalk", "commander", "debug", "request",
				"dotenv", "cors", "uuid", "jsonwebtoken", "bcrypt",
				"mongoose", "sequelize", "prisma", "socket.io",
			},
			"pypi": {
				"requests", "numpy", "pandas", "flask", "django",
				"boto3", "tensorflow", "torch", "scikit-learn", "pillow",
				"matplotlib", "sqlalchemy", "celery", "fastapi", "pydantic",
				"cryptography", "paramiko", "beautifulsoup4", "selenium",
			},
			"public": {
				"lodash", "express", "react", "requests", "numpy",
				"pandas", "flask", "django", "axios", "webpack",
			},
		},
	}
}

func (td *TyposquatDetector) Check(pkgName, registry string) string {
	popular, ok := td.popularPackages[strings.ToLower(registry)]
	if !ok {
		popular = td.popularPackages["public"]
	}

	nameLower := strings.ToLower(pkgName)
	for _, pkg := range popular {
		if nameLower == pkg {
			continue // exact match, not a typosquat
		}
		if levenshtein(nameLower, pkg) <= 2 && levenshtein(nameLower, pkg) > 0 {
			return pkg
		}
		// Check for common typosquat patterns
		if strings.ReplaceAll(nameLower, "-", "") == strings.ReplaceAll(pkg, "-", "") && nameLower != pkg {
			return pkg
		}
		if strings.ReplaceAll(nameLower, "_", "-") == pkg || strings.ReplaceAll(nameLower, "-", "_") == pkg {
			return pkg
		}
	}
	return ""
}

func levenshtein(a, b string) int {
	la, lb := len(a), len(b)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}

	matrix := make([][]int, la+1)
	for i := range matrix {
		matrix[i] = make([]int, lb+1)
		matrix[i][0] = i
	}
	for j := 0; j <= lb; j++ {
		matrix[0][j] = j
	}

	for i := 1; i <= la; i++ {
		for j := 1; j <= lb; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			matrix[i][j] = min(
				matrix[i-1][j]+1,
				min(matrix[i][j-1]+1, matrix[i-1][j-1]+cost),
			)
		}
	}
	return matrix[la][lb]
}

// HashBytes returns the SHA-256 hex digest of data.
func HashBytes(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
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

// getSupplyChainMitigations returns context-specific mitigations based on alert type.
func getSupplyChainMitigations(alertType string) []string {
	switch alertType {
	case "typosquat":
		return []string{
			"Verify the package name against the official registry listing",
			"Check package download counts, author, and publication date",
			"Use lockfiles and hash pinning to prevent substitution",
			"Implement package name validation in CI/CD pipelines",
		}
	case "package_integrity_violation":
		return []string{
			"Do not install the package — hash mismatch indicates tampering",
			"Verify the package hash against the official registry",
			"Check if the registry has been compromised",
			"Use signed packages and verify signatures before installation",
		}
	case "dependency_confusion":
		return []string{
			"Configure package managers to prioritize private registries",
			"Use scoped packages or namespaces to prevent confusion",
			"Register placeholder packages on public registries for private package names",
			"Implement registry allowlisting in your package manager configuration",
		}
	case "known_malicious_package":
		return []string{
			"Remove the package immediately from all environments",
			"Audit systems where the package was installed for compromise indicators",
			"Rotate any credentials that may have been exposed",
			"Report the package to the registry maintainers",
		}
	case "unsigned_artifact":
		return []string{
			"Implement artifact signing in your build pipeline (e.g., Sigstore, cosign)",
			"Require signature verification before deployment",
			"Use SLSA framework for build provenance attestation",
		}
	case "missing_provenance":
		return []string{
			"Implement build provenance attestation (SLSA Level 2+)",
			"Use reproducible builds to enable independent verification",
			"Require provenance for all artifacts before deployment",
		}
	case "unauthorized_cicd_change":
		return []string{
			"Require code review and approval for all CI/CD pipeline changes",
			"Implement branch protection rules on pipeline configuration files",
			"Use infrastructure-as-code with version control for pipeline definitions",
			"Monitor and alert on pipeline configuration changes",
		}
	case "suspicious_cicd_step":
		return []string{
			"Review the suspicious pipeline step for malicious intent",
			"Implement allowlists for permitted CI/CD actions and commands",
			"Use hardened, minimal base images for CI/CD runners",
		}
	case "cicd_secret_exposure":
		return []string{
			"Rotate all secrets that may have been exposed",
			"Use secret management tools (Vault, AWS Secrets Manager) instead of env vars",
			"Implement secret scanning in CI/CD logs and artifacts",
			"Mask secrets in CI/CD output and disable debug logging in production",
		}
	case "sbom_critical_vulns", "sbom_high_vulns":
		return []string{
			"Prioritize patching critical and high vulnerabilities",
			"Implement automated dependency updates with security scanning",
			"Use SBOM scanning in CI/CD to block deployments with critical vulns",
			"Monitor vulnerability databases for new disclosures affecting your dependencies",
		}
	default:
		return []string{
			"Verify package integrity using checksums and signatures",
			"Use a private registry mirror with allow-listing",
			"Implement SBOM scanning in your CI/CD pipeline",
		}
	}
}
