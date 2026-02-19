package apifortress

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

const ModuleName = "api_fortress"

// Fortress is the API Fortress module providing BOLA detection, BFLA detection,
// mass assignment protection, schema validation, shadow API discovery, per-endpoint
// rate limiting, excessive data exposure detection, GraphQL abuse prevention,
// JWT validation, SSRF-via-API detection, and response anomaly analysis.
type Fortress struct {
	logger          zerolog.Logger
	bus             *core.EventBus
	pipeline        *core.AlertPipeline
	cfg             *core.Config
	ctx             context.Context
	cancel          context.CancelFunc
	bolaDetector    *BOLADetector
	bflaDetector    *BFLADetector
	apiRegistry     *APIRegistry
	rateLimiter     *EndpointRateLimiter
	massAssignDet   *MassAssignmentDetector
	dataExposureDet *DataExposureDetector
	graphqlGuard    *GraphQLGuard
	jwtValidator    *JWTValidator
	ssrfDetector    *SSRFViaAPIDetector
	responseAnalyzer *ResponseAnomalyAnalyzer
}

func New() *Fortress { return &Fortress{} }

func (f *Fortress) Name() string        { return ModuleName }
func (f *Fortress) Description() string {
	return "BOLA/BFLA detection, mass assignment protection, API schema validation, shadow API discovery, per-endpoint rate limiting, excessive data exposure, GraphQL abuse prevention, JWT validation, SSRF-via-API detection, and response anomaly analysis"
}

func (f *Fortress) Start(ctx context.Context, bus *core.EventBus, pipeline *core.AlertPipeline, cfg *core.Config) error {
	f.ctx, f.cancel = context.WithCancel(ctx)
	f.bus = bus
	f.pipeline = pipeline
	f.cfg = cfg
	f.logger = zerolog.New(zerolog.NewConsoleWriter()).With().Timestamp().Str("module", ModuleName).Logger()

	settings := cfg.GetModuleSettings(ModuleName)

	f.bolaDetector = NewBOLADetector(settings)
	f.bflaDetector = NewBFLADetector()
	f.apiRegistry = NewAPIRegistry()
	f.rateLimiter = NewEndpointRateLimiter(settings)
	f.massAssignDet = NewMassAssignmentDetector()
	f.dataExposureDet = NewDataExposureDetector()
	f.graphqlGuard = NewGraphQLGuard(settings)
	f.jwtValidator = NewJWTValidator()
	f.ssrfDetector = NewSSRFViaAPIDetector()
	f.responseAnalyzer = NewResponseAnomalyAnalyzer()

	go f.bolaDetector.CleanupLoop(f.ctx)
	go f.rateLimiter.CleanupLoop(f.ctx)
	go f.bflaDetector.CleanupLoop(f.ctx)
	go f.responseAnalyzer.CleanupLoop(f.ctx)

	f.logger.Info().Msg("API fortress started")
	return nil
}

func (f *Fortress) Stop() error {
	if f.cancel != nil {
		f.cancel()
	}
	return nil
}

func (f *Fortress) HandleEvent(event *core.SecurityEvent) error {
	switch event.Type {
	case "http_request", "api_request":
		f.handleAPIRequest(event)
	case "http_response", "api_response":
		f.handleAPIResponse(event)
	case "graphql_request":
		f.handleGraphQLRequest(event)
	case "jwt_validation", "token_event":
		f.handleJWTEvent(event)
	}
	return nil
}

func (f *Fortress) handleAPIRequest(event *core.SecurityEvent) {
	path := getStringDetail(event, "path")
	method := strings.ToUpper(getStringDetail(event, "method"))
	userID := getStringDetail(event, "user_id")
	resourceID := getStringDetail(event, "resource_id")
	userRole := getStringDetail(event, "user_role")
	body := getStringDetail(event, "body")
	contentType := getStringDetail(event, "content_type")
	statusCode := getIntDetail(event, "status_code")

	// BOLA detection — user accessing resources they don't own
	if resourceID != "" && userID != "" {
		result := f.bolaDetector.Detect(userID, resourceID, path, method, event.SourceIP)
		if result.IsAttack {
			f.raiseAlert(event, core.SeverityCritical,
				"BOLA Attack Detected [API1:2023]",
				fmt.Sprintf("User %s is enumerating resources via %s %s. Accessed %d unique resource IDs in %s from IP %s. OWASP API Top 10: API1 Broken Object Level Authorization.",
					userID, method, path, result.ResourceCount, result.Window.String(), event.SourceIP),
				"bola")
		}
		if result.IDORAttempt {
			f.raiseAlert(event, core.SeverityHigh,
				"IDOR Attempt Detected [API1:2023]",
				fmt.Sprintf("User %s accessed resource %s sequentially after %s. Path: %s. Possible Insecure Direct Object Reference.",
					userID, resourceID, result.PreviousResource, path),
				"idor")
		}
	}

	// BFLA detection — user calling endpoints above their privilege level
	if userRole != "" && path != "" {
		if violation := f.bflaDetector.Check(userID, userRole, method, path, event.SourceIP); violation != nil {
			f.raiseAlert(event, violation.Severity,
				"BFLA Detected [API5:2023]",
				fmt.Sprintf("User %s (role: %s) attempted %s %s which requires role %s. OWASP API Top 10: API5 Broken Function Level Authorization. %s",
					userID, userRole, method, path, violation.RequiredRole, violation.Reason),
				"bfla")
		}
	}

	// Shadow API detection
	if path != "" && method != "" {
		if f.apiRegistry.IsUndocumented(method, path) {
			f.raiseAlert(event, core.SeverityMedium,
				"Shadow API Endpoint Detected [API9:2023]",
				fmt.Sprintf("Undocumented API endpoint accessed: %s %s from IP %s (user: %s). OWASP API Top 10: API9 Improper Inventory Management.",
					method, path, event.SourceIP, userID),
				"shadow_api")
		}
		f.apiRegistry.RecordAccess(method, path)
	}

	// Per-endpoint rate limiting
	if path != "" {
		if exceeded := f.rateLimiter.Check(event.SourceIP, method, path); exceeded != nil {
			f.raiseAlert(event, exceeded.Severity,
				"API Rate Limit Exceeded [API4:2023]",
				fmt.Sprintf("IP %s exceeded rate limit for %s %s: %d requests in %s (limit: %d). %s",
					event.SourceIP, method, path, exceeded.Count, exceeded.Window.String(), exceeded.Limit, exceeded.Detail),
				"api_rate_limit")
		}
	}

	// Mass assignment detection
	if body != "" && (method == "POST" || method == "PUT" || method == "PATCH") {
		if findings := f.massAssignDet.Check(method, path, body, contentType); len(findings) > 0 {
			for _, finding := range findings {
				f.raiseAlert(event, finding.Severity,
					"Mass Assignment Attempt [API6:2023]",
					fmt.Sprintf("%s %s from user %s (IP: %s): %s. OWASP API Top 10: API6 Unrestricted Access to Sensitive Business Flows.",
						method, path, userID, event.SourceIP, finding.Description),
					"mass_assignment")
			}
		}
	}

	// SSRF via API detection
	if body != "" || path != "" {
		urlParam := getStringDetail(event, "url_param")
		if ssrf := f.ssrfDetector.Check(path, body, urlParam); ssrf != nil {
			f.raiseAlert(event, ssrf.Severity,
				"SSRF via API Detected [API7:2023]",
				fmt.Sprintf("SSRF attempt via %s %s from %s: %s. OWASP API Top 10: API7 Server Side Request Forgery.",
					method, path, event.SourceIP, ssrf.Description),
				"ssrf_via_api")
		}
	}

	// Schema violation: unexpected parameters
	if params := getStringDetail(event, "unexpected_params"); params != "" {
		f.raiseAlert(event, core.SeverityMedium,
			"API Schema Violation [API3:2023]",
			fmt.Sprintf("Unexpected parameters in %s %s from %s: %s. OWASP API Top 10: API3 Broken Object Property Level Authorization.",
				method, path, event.SourceIP, params),
			"schema_violation")
	}

	// Track response for anomaly analysis
	if statusCode > 0 {
		f.responseAnalyzer.RecordRequest(method, path, statusCode, event.SourceIP)
	}
}

func (f *Fortress) handleAPIResponse(event *core.SecurityEvent) {
	path := getStringDetail(event, "path")
	method := strings.ToUpper(getStringDetail(event, "method"))
	statusCode := getIntDetail(event, "status_code")
	responseBody := getStringDetail(event, "response_body")
	responseSize := getIntDetail(event, "response_size")
	userID := getStringDetail(event, "user_id")

	// Excessive data exposure detection
	if responseBody != "" || responseSize > 0 {
		if finding := f.dataExposureDet.Check(path, method, responseBody, responseSize); finding != nil {
			f.raiseAlert(event, finding.Severity,
				"Excessive Data Exposure [API3:2023]",
				fmt.Sprintf("Response from %s %s to user %s: %s. OWASP API Top 10: API3 Broken Object Property Level Authorization.",
					method, path, userID, finding.Description),
				"data_exposure")
		}
	}

	// Response anomaly detection
	if statusCode > 0 {
		anomaly := f.responseAnalyzer.Analyze(method, path, statusCode, responseSize, event.SourceIP)
		if anomaly.ErrorSpike {
			f.raiseAlert(event, core.SeverityHigh,
				"API Error Rate Spike",
				fmt.Sprintf("Endpoint %s %s error rate spiked to %.1f%% (normal: %.1f%%). %d errors in the last %s from IP %s.",
					method, path, anomaly.ErrorRate*100, anomaly.BaselineErrorRate*100,
					anomaly.ErrorCount, anomaly.Window.String(), event.SourceIP),
				"error_rate_spike")
		}
		if anomaly.ResponseSizeAnomaly {
			f.raiseAlert(event, core.SeverityMedium,
				"API Response Size Anomaly",
				fmt.Sprintf("Response from %s %s is %d bytes, %.1fx above average (%d bytes). Possible data leak.",
					method, path, responseSize, anomaly.SizeRatio, anomaly.AvgResponseSize),
				"response_size_anomaly")
		}
	}
}

func (f *Fortress) handleGraphQLRequest(event *core.SecurityEvent) {
	query := getStringDetail(event, "query")
	operationName := getStringDetail(event, "operation_name")
	userID := getStringDetail(event, "user_id")

	if query == "" {
		return
	}

	findings := f.graphqlGuard.Analyze(query, operationName, userID, event.SourceIP)
	for _, finding := range findings {
		f.raiseAlert(event, finding.Severity,
			finding.Title,
			fmt.Sprintf("GraphQL request from %s (user: %s): %s",
				event.SourceIP, userID, finding.Description),
			finding.AlertType)
	}
}

func (f *Fortress) handleJWTEvent(event *core.SecurityEvent) {
	token := getStringDetail(event, "token")
	header := getStringDetail(event, "header")
	algorithm := getStringDetail(event, "algorithm")
	claims := getStringDetail(event, "claims")

	findings := f.jwtValidator.Validate(token, header, algorithm, claims)
	for _, finding := range findings {
		f.raiseAlert(event, finding.Severity,
			finding.Title,
			fmt.Sprintf("JWT issue from %s: %s", event.SourceIP, finding.Description),
			finding.AlertType)
	}
}

func (f *Fortress) raiseAlert(event *core.SecurityEvent, severity core.Severity, title, description, alertType string) {
	newEvent := core.NewSecurityEvent(ModuleName, alertType, severity, description)
	newEvent.SourceIP = event.SourceIP
	newEvent.Details["original_event_id"] = event.ID

	if f.bus != nil {
		_ = f.bus.PublishEvent(newEvent)
	}

	alert := core.NewAlert(newEvent, title, description)
	alert.Mitigations = getAPIMitigations(alertType)
	if f.pipeline != nil {
		f.pipeline.Process(alert)
	}
}

func getAPIMitigations(alertType string) []string {
	switch alertType {
	case "bola", "idor":
		return []string{
			"Implement object-level authorization checks on every data access",
			"Use random, non-sequential resource identifiers (UUIDs)",
			"Validate that the authenticated user owns the requested resource",
			"Log and monitor resource access patterns for enumeration",
		}
	case "bfla":
		return []string{
			"Implement function-level authorization checks on every endpoint",
			"Use role-based access control (RBAC) with least privilege",
			"Deny by default — explicitly allow only authorized role/endpoint combinations",
		}
	case "mass_assignment":
		return []string{
			"Use allowlists for accepted request body properties",
			"Never bind request bodies directly to internal data models",
			"Implement separate DTOs for input and output",
		}
	case "data_exposure":
		return []string{
			"Return only the fields the client explicitly needs",
			"Implement response filtering and field-level access control",
			"Never expose internal object representations directly",
		}
	case "ssrf_via_api":
		return []string{
			"Validate and sanitize all URL parameters server-side",
			"Use allowlists for permitted external domains",
			"Block requests to internal/private IP ranges from user-supplied URLs",
		}
	case "graphql_depth", "graphql_batch", "graphql_introspection", "graphql_alias_abuse":
		return []string{
			"Limit query depth, complexity, and alias count",
			"Disable introspection in production",
			"Implement query cost analysis and budget limits",
			"Use persisted queries to prevent arbitrary query execution",
		}
	default:
		return []string{
			"Review API security posture against OWASP API Top 10",
			"Implement authentication, authorization, and rate limiting on all endpoints",
			"Monitor API traffic for anomalous patterns",
		}
	}
}

// ===========================================================================
// BOLADetector — Broken Object Level Authorization with IDOR detection
// ===========================================================================

type BOLADetector struct {
	mu             sync.RWMutex
	accessPatterns map[string]*bolaProfile // userID -> profile
	ipPatterns     map[string]*bolaProfile // IP -> profile
	threshold      int
}

type bolaProfile struct {
	resources     map[string]bool
	orderedIDs    []string
	firstSeen     time.Time
	lastSeen      time.Time
}

type BOLAResult struct {
	IsAttack         bool
	IDORAttempt      bool
	ResourceCount    int
	PreviousResource string
	Window           time.Duration
}

func NewBOLADetector(settings map[string]interface{}) *BOLADetector {
	threshold := 20
	if val, ok := settings["bola_threshold"]; ok {
		if v, ok := val.(float64); ok && v > 0 {
			threshold = int(v)
		}
	}
	return &BOLADetector{
		accessPatterns: make(map[string]*bolaProfile),
		ipPatterns:     make(map[string]*bolaProfile),
		threshold:      threshold,
	}
}

func (b *BOLADetector) Detect(userID, resourceID, path, method, ip string) BOLAResult {
	b.mu.Lock()
	defer b.mu.Unlock()

	result := BOLAResult{}
	now := time.Now()

	// Per-user tracking
	profile := b.getOrCreateProfile(b.accessPatterns, userID, now)
	profile.lastSeen = now

	if !profile.resources[resourceID] {
		profile.resources[resourceID] = true
		profile.orderedIDs = append(profile.orderedIDs, resourceID)
		if len(profile.orderedIDs) > 200 {
			profile.orderedIDs = profile.orderedIDs[len(profile.orderedIDs)-200:]
		}
	}

	result.ResourceCount = len(profile.resources)
	result.Window = now.Sub(profile.firstSeen)

	// Enumeration detection: accessing many different resources
	if len(profile.resources) > b.threshold {
		result.IsAttack = true
	}

	// IDOR detection: sequential ID access pattern
	if len(profile.orderedIDs) >= 3 {
		recent := profile.orderedIDs[len(profile.orderedIDs)-3:]
		if isSequentialIDs(recent) {
			result.IDORAttempt = true
			result.PreviousResource = recent[len(recent)-2]
		}
	}

	// Per-IP tracking (catches attacks across multiple user accounts)
	ipProfile := b.getOrCreateProfile(b.ipPatterns, ip, now)
	ipProfile.lastSeen = now
	ipProfile.resources[resourceID] = true
	if len(ipProfile.resources) > b.threshold*2 {
		result.IsAttack = true
	}

	return result
}

func (b *BOLADetector) getOrCreateProfile(m map[string]*bolaProfile, key string, now time.Time) *bolaProfile {
	p, exists := m[key]
	if !exists || now.Sub(p.lastSeen) > 10*time.Minute {
		p = &bolaProfile{
			resources: make(map[string]bool),
			firstSeen: now,
		}
		m[key] = p
	}
	return p
}

func (b *BOLADetector) CleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			b.mu.Lock()
			cutoff := time.Now().Add(-15 * time.Minute)
			cleanupProfiles(b.accessPatterns, cutoff)
			cleanupProfiles(b.ipPatterns, cutoff)
			b.mu.Unlock()
		}
	}
}

func cleanupProfiles(m map[string]*bolaProfile, cutoff time.Time) {
	for k, p := range m {
		if p.lastSeen.Before(cutoff) {
			delete(m, k)
		}
	}
}

// isSequentialIDs checks if a slice of ID strings are numerically sequential.
func isSequentialIDs(ids []string) bool {
	if len(ids) < 2 {
		return false
	}
	nums := make([]int, 0, len(ids))
	for _, id := range ids {
		n := parseNumericID(id)
		if n < 0 {
			return false
		}
		nums = append(nums, n)
	}
	for i := 1; i < len(nums); i++ {
		diff := nums[i] - nums[i-1]
		if diff < 1 || diff > 3 { // allow small gaps (1, 2, or 3)
			return false
		}
	}
	return true
}

func parseNumericID(s string) int {
	n := 0
	hasDigit := false
	for _, c := range s {
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
			hasDigit = true
		} else {
			if hasDigit {
				break
			}
			return -1
		}
	}
	if !hasDigit {
		return -1
	}
	return n
}

// ===========================================================================
// BFLADetector — Broken Function Level Authorization
// ===========================================================================

type BFLADetector struct {
	mu             sync.RWMutex
	adminPaths     *regexp.Regexp
	writePaths     *regexp.Regexp
	roleHierarchy  map[string]int // role -> privilege level
	userAttempts   map[string]*bflaTracker
}

type bflaTracker struct {
	violations int
	lastSeen   time.Time
}

type BFLAViolation struct {
	Severity     core.Severity
	RequiredRole string
	Reason       string
}

func NewBFLADetector() *BFLADetector {
	return &BFLADetector{
		adminPaths: regexp.MustCompile(`(?i)(/admin|/management|/internal|/debug|/actuator|/console|/config|/settings|/users/\{?id\}?/role|/system|/ops/|/superadmin)`),
		writePaths: regexp.MustCompile(`(?i)(/users$|/accounts$|/roles|/permissions|/policies|/billing|/subscriptions|/organizations)`),
		roleHierarchy: map[string]int{
			"anonymous": 0, "guest": 0,
			"user": 1, "member": 1,
			"editor": 2, "moderator": 2,
			"admin": 3, "administrator": 3,
			"superadmin": 4, "owner": 4, "root": 4,
		},
		userAttempts: make(map[string]*bflaTracker),
	}
}

func (b *BFLADetector) Check(userID, userRole, method, path, ip string) *BFLAViolation {
	b.mu.Lock()
	defer b.mu.Unlock()

	roleLower := strings.ToLower(userRole)
	userLevel, knownRole := b.roleHierarchy[roleLower]
	if !knownRole {
		userLevel = 1 // default to basic user
	}

	// Admin path access by non-admin
	if b.adminPaths.MatchString(path) && userLevel < 3 {
		b.recordAttempt(userID)
		return &BFLAViolation{
			Severity:     core.SeverityCritical,
			RequiredRole: "admin",
			Reason:       fmt.Sprintf("Admin endpoint accessed by %s-level user", userRole),
		}
	}

	// Write operations on sensitive paths by low-privilege users
	if (method == "POST" || method == "PUT" || method == "DELETE" || method == "PATCH") &&
		b.writePaths.MatchString(path) && userLevel < 2 {
		b.recordAttempt(userID)
		return &BFLAViolation{
			Severity:     core.SeverityHigh,
			RequiredRole: "editor",
			Reason:       fmt.Sprintf("Write operation on sensitive resource by %s-level user", userRole),
		}
	}

	// DELETE on any resource by non-admin
	if method == "DELETE" && userLevel < 3 {
		// Only flag if it's a resource deletion (not a sub-resource action)
		normalized := normalizePath(path)
		if strings.Count(normalized, "/") <= 3 {
			b.recordAttempt(userID)
			return &BFLAViolation{
				Severity:     core.SeverityHigh,
				RequiredRole: "admin",
				Reason:       "DELETE operation on top-level resource by non-admin user",
			}
		}
	}

	// Repeated BFLA attempts from same user
	if tracker, ok := b.userAttempts[userID]; ok && tracker.violations >= 5 {
		return &BFLAViolation{
			Severity:     core.SeverityCritical,
			RequiredRole: "admin",
			Reason:       fmt.Sprintf("Repeated privilege escalation attempts: %d violations", tracker.violations),
		}
	}

	return nil
}

func (b *BFLADetector) recordAttempt(userID string) {
	tracker, exists := b.userAttempts[userID]
	if !exists {
		tracker = &bflaTracker{}
		b.userAttempts[userID] = tracker
	}
	tracker.violations++
	tracker.lastSeen = time.Now()
}

func (b *BFLADetector) CleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			b.mu.Lock()
			cutoff := time.Now().Add(-30 * time.Minute)
			for k, t := range b.userAttempts {
				if t.lastSeen.Before(cutoff) {
					delete(b.userAttempts, k)
				}
			}
			b.mu.Unlock()
		}
	}
}

// ===========================================================================
// MassAssignmentDetector — detects attempts to set privileged fields
// ===========================================================================

type MassAssignmentDetector struct {
	sensitiveFields *regexp.Regexp
	adminFields     *regexp.Regexp
}

type MassAssignmentFinding struct {
	Severity    core.Severity
	Description string
}

func NewMassAssignmentDetector() *MassAssignmentDetector {
	return &MassAssignmentDetector{
		sensitiveFields: regexp.MustCompile(`(?i)"(role|is_?admin|is_?superuser|is_?staff|privilege|permission|access_?level|user_?type|account_?type|verified|email_?verified|approved|active|disabled|banned|suspended|internal|trust_?level|credit|balance|price|amount|discount|subscription_?tier|plan)"\s*:`),
		adminFields:     regexp.MustCompile(`(?i)"(id|_id|created_?at|updated_?at|deleted_?at|password_?hash|salt|secret|token|api_?key|internal_?id|tenant_?id|org_?id|owner_?id)"\s*:`),
	}
}

func (m *MassAssignmentDetector) Check(method, path, body, contentType string) []MassAssignmentFinding {
	var findings []MassAssignmentFinding

	if !strings.Contains(strings.ToLower(contentType), "json") && contentType != "" {
		return findings
	}

	if m.adminFields.MatchString(body) {
		matches := m.adminFields.FindAllString(body, -1)
		fields := make([]string, 0, len(matches))
		for _, match := range matches {
			fields = append(fields, strings.TrimSpace(match))
		}
		findings = append(findings, MassAssignmentFinding{
			Severity:    core.SeverityCritical,
			Description: fmt.Sprintf("Request body contains internal/system fields: %s", strings.Join(fields, ", ")),
		})
	}

	if m.sensitiveFields.MatchString(body) {
		matches := m.sensitiveFields.FindAllString(body, -1)
		fields := make([]string, 0, len(matches))
		for _, match := range matches {
			fields = append(fields, strings.TrimSpace(match))
		}
		findings = append(findings, MassAssignmentFinding{
			Severity:    core.SeverityHigh,
			Description: fmt.Sprintf("Request body contains privilege-escalation fields: %s", strings.Join(fields, ", ")),
		})
	}

	return findings
}

// ===========================================================================
// DataExposureDetector — detects excessive data in API responses
// ===========================================================================

type DataExposureDetector struct {
	sensitivePatterns *regexp.Regexp
	piiPatterns       *regexp.Regexp
}

type DataExposureFinding struct {
	Severity    core.Severity
	Description string
}

func NewDataExposureDetector() *DataExposureDetector {
	return &DataExposureDetector{
		sensitivePatterns: regexp.MustCompile(`(?i)"(password|password_hash|salt|secret|private_key|api_key|api_secret|access_token|refresh_token|ssn|social_security|credit_card|card_number|cvv|bank_account|routing_number)"\s*:\s*"[^"]+"`),
		piiPatterns:       regexp.MustCompile(`(?i)"(date_of_birth|dob|national_id|passport_number|driver_license|tax_id|medical_record|health_insurance|biometric)"\s*:\s*"[^"]+"`),
	}
}

func (d *DataExposureDetector) Check(path, method, responseBody string, responseSize int) *DataExposureFinding {
	// Check for sensitive data in response
	if responseBody != "" {
		if d.sensitivePatterns.MatchString(responseBody) {
			matches := d.sensitivePatterns.FindAllString(responseBody, 5)
			return &DataExposureFinding{
				Severity:    core.SeverityCritical,
				Description: fmt.Sprintf("Response contains sensitive credentials/secrets: %d matches found. Fields: %s",
					len(matches), summarizeMatches(matches)),
			}
		}

		if d.piiPatterns.MatchString(responseBody) {
			matches := d.piiPatterns.FindAllString(responseBody, 5)
			return &DataExposureFinding{
				Severity:    core.SeverityHigh,
				Description: fmt.Sprintf("Response contains PII data: %d matches found. Fields: %s",
					len(matches), summarizeMatches(matches)),
			}
		}
	}

	// Abnormally large response for a single-object endpoint
	if responseSize > 1024*1024 && !strings.Contains(path, "/export") && !strings.Contains(path, "/download") && !strings.Contains(path, "/bulk") {
		return &DataExposureFinding{
			Severity:    core.SeverityMedium,
			Description: fmt.Sprintf("Response size %d bytes (%.1f MB) is unusually large for endpoint %s %s",
				responseSize, float64(responseSize)/(1024*1024), method, path),
		}
	}

	return nil
}

func summarizeMatches(matches []string) string {
	if len(matches) == 0 {
		return ""
	}
	fields := make([]string, 0, len(matches))
	for _, m := range matches {
		// Extract just the field name
		idx := strings.Index(m, "\"")
		if idx >= 0 {
			end := strings.Index(m[idx+1:], "\"")
			if end > 0 {
				fields = append(fields, m[idx+1:idx+1+end])
			}
		}
	}
	return strings.Join(fields, ", ")
}

// ===========================================================================
// GraphQLGuard — prevents GraphQL-specific abuse patterns
// ===========================================================================

type GraphQLGuard struct {
	maxDepth       int
	maxAliases     int
	maxBatchSize   int
	maxComplexity  int
	depthPattern   *regexp.Regexp
	aliasPattern   *regexp.Regexp
	introspection  *regexp.Regexp
	dangerousMutations *regexp.Regexp
}

type GraphQLFinding struct {
	Title       string
	Description string
	Severity    core.Severity
	AlertType   string
}

func NewGraphQLGuard(settings map[string]interface{}) *GraphQLGuard {
	maxDepth := 10
	maxAliases := 20
	maxBatch := 10
	if val, ok := settings["graphql_max_depth"]; ok {
		if v, ok := val.(float64); ok {
			maxDepth = int(v)
		}
	}
	if val, ok := settings["graphql_max_aliases"]; ok {
		if v, ok := val.(float64); ok {
			maxAliases = int(v)
		}
	}

	return &GraphQLGuard{
		maxDepth:     maxDepth,
		maxAliases:   maxAliases,
		maxBatchSize: maxBatch,
		maxComplexity: 1000,
		depthPattern: regexp.MustCompile(`\{`),
		aliasPattern: regexp.MustCompile(`\w+\s*:\s*\w+\s*[\({]`),
		introspection: regexp.MustCompile(`(?i)(__schema|__type|__typename\s*\{|introspectionQuery)`),
		dangerousMutations: regexp.MustCompile(`(?i)(deleteAll|dropDatabase|truncate|destroyAll|purge|resetAll|wipeData)`),
	}
}

func (g *GraphQLGuard) Analyze(query, operationName, userID, ip string) []GraphQLFinding {
	var findings []GraphQLFinding

	// Depth analysis (count nesting levels via brace counting)
	depth := g.measureDepth(query)
	if depth > g.maxDepth {
		findings = append(findings, GraphQLFinding{
			Title:       "GraphQL Query Depth Exceeded",
			Description: fmt.Sprintf("Query depth %d exceeds maximum %d. Deep queries can cause exponential resource consumption (DoS).", depth, g.maxDepth),
			Severity:    core.SeverityHigh,
			AlertType:   "graphql_depth",
		})
	}

	// Alias abuse (used to bypass rate limiting or amplify queries)
	aliasCount := len(g.aliasPattern.FindAllString(query, -1))
	if aliasCount > g.maxAliases {
		findings = append(findings, GraphQLFinding{
			Title:       "GraphQL Alias Abuse",
			Description: fmt.Sprintf("Query contains %d aliases (max: %d). Alias abuse can bypass rate limiting and amplify query cost.", aliasCount, g.maxAliases),
			Severity:    core.SeverityHigh,
			AlertType:   "graphql_alias_abuse",
		})
	}

	// Introspection in production
	if g.introspection.MatchString(query) {
		findings = append(findings, GraphQLFinding{
			Title:       "GraphQL Introspection Query",
			Description: "Introspection query detected. Introspection exposes the entire API schema and should be disabled in production.",
			Severity:    core.SeverityMedium,
			AlertType:   "graphql_introspection",
		})
	}

	// Batch query detection (array of queries)
	if strings.HasPrefix(strings.TrimSpace(query), "[") {
		// Count operations in batch
		opCount := strings.Count(query, "query ") + strings.Count(query, "mutation ")
		if opCount > g.maxBatchSize {
			findings = append(findings, GraphQLFinding{
				Title:       "GraphQL Batch Query Abuse",
				Description: fmt.Sprintf("Batch request contains %d operations (max: %d). Batch abuse can overwhelm the server.", opCount, g.maxBatchSize),
				Severity:    core.SeverityHigh,
				AlertType:   "graphql_batch",
			})
		}
	}

	// Dangerous mutations
	if g.dangerousMutations.MatchString(query) {
		findings = append(findings, GraphQLFinding{
			Title:       "Dangerous GraphQL Mutation",
			Description: "Query contains a potentially destructive mutation (deleteAll, truncate, etc.).",
			Severity:    core.SeverityCritical,
			AlertType:   "graphql_dangerous_mutation",
		})
	}

	// Field suggestion exploitation (error-based schema discovery)
	if strings.Contains(query, "__") && !g.introspection.MatchString(query) {
		findings = append(findings, GraphQLFinding{
			Title:       "GraphQL Schema Probing",
			Description: "Query uses double-underscore fields for schema probing without full introspection.",
			Severity:    core.SeverityLow,
			AlertType:   "graphql_schema_probe",
		})
	}

	return findings
}

func (g *GraphQLGuard) measureDepth(query string) int {
	maxDepth := 0
	current := 0
	for _, c := range query {
		if c == '{' {
			current++
			if current > maxDepth {
				maxDepth = current
			}
		} else if c == '}' {
			current--
		}
	}
	return maxDepth
}

// ===========================================================================
// JWTValidator — detects JWT security issues
// ===========================================================================

type JWTValidator struct {
	weakAlgorithms map[string]bool
	noneVariants   *regexp.Regexp
}

type JWTFinding struct {
	Title       string
	Description string
	Severity    core.Severity
	AlertType   string
}

func NewJWTValidator() *JWTValidator {
	return &JWTValidator{
		weakAlgorithms: map[string]bool{
			"none": true, "None": true, "NONE": true, "nOnE": true,
			"HS256": false, // not weak per se, but flag if used with public key
		},
		noneVariants: regexp.MustCompile(`(?i)^n[o0]n[e3]$`),
	}
}

func (j *JWTValidator) Validate(token, header, algorithm, claims string) []JWTFinding {
	var findings []JWTFinding

	algoLower := strings.ToLower(algorithm)

	// "none" algorithm attack
	if j.noneVariants.MatchString(algorithm) {
		findings = append(findings, JWTFinding{
			Title:       "JWT Algorithm None Attack",
			Description: fmt.Sprintf("JWT uses algorithm %q — this bypasses signature verification entirely. Critical authentication bypass.", algorithm),
			Severity:    core.SeverityCritical,
			AlertType:   "jwt_none_algorithm",
		})
	}

	// Algorithm confusion: RS256 -> HS256 (use public key as HMAC secret)
	if algoLower == "hs256" && strings.Contains(strings.ToLower(header), "rs256") {
		findings = append(findings, JWTFinding{
			Title:       "JWT Algorithm Confusion Attack",
			Description: "JWT header originally specified RS256 but was changed to HS256. This is an algorithm confusion attack that can forge tokens using the public key.",
			Severity:    core.SeverityCritical,
			AlertType:   "jwt_algorithm_confusion",
		})
	}

	// Weak algorithms
	if algoLower == "hs256" {
		findings = append(findings, JWTFinding{
			Title:       "JWT Using HS256",
			Description: "JWT uses HS256 (symmetric). Consider RS256 or ES256 (asymmetric) for better security — symmetric keys are harder to rotate and easier to leak.",
			Severity:    core.SeverityLow,
			AlertType:   "jwt_weak_algorithm",
		})
	}

	// Missing expiration
	if claims != "" && !strings.Contains(claims, "\"exp\"") {
		findings = append(findings, JWTFinding{
			Title:       "JWT Missing Expiration",
			Description: "JWT has no expiration claim (exp). Tokens without expiration are valid forever if compromised.",
			Severity:    core.SeverityHigh,
			AlertType:   "jwt_no_expiry",
		})
	}

	// Empty signature (token ends with ".")
	if token != "" && strings.HasSuffix(token, ".") {
		findings = append(findings, JWTFinding{
			Title:       "JWT Empty Signature",
			Description: "JWT has an empty signature segment. This token has no integrity protection.",
			Severity:    core.SeverityCritical,
			AlertType:   "jwt_empty_signature",
		})
	}

	// JKU/X5U header injection
	headerLower := strings.ToLower(header)
	if strings.Contains(headerLower, "\"jku\"") || strings.Contains(headerLower, "\"x5u\"") {
		findings = append(findings, JWTFinding{
			Title:       "JWT Key URL Injection (JKU/X5U)",
			Description: "JWT header contains jku or x5u claim pointing to an external key URL. Attacker can host their own key and forge tokens.",
			Severity:    core.SeverityCritical,
			AlertType:   "jwt_key_injection",
		})
	}

	return findings
}

// ===========================================================================
// SSRFViaAPIDetector — detects SSRF attempts through API parameters
// ===========================================================================

type SSRFViaAPIDetector struct {
	internalPatterns *regexp.Regexp
	cloudMetadata    *regexp.Regexp
	urlParams        *regexp.Regexp
}

type SSRFFinding struct {
	Severity    core.Severity
	Description string
}

func NewSSRFViaAPIDetector() *SSRFViaAPIDetector {
	return &SSRFViaAPIDetector{
		internalPatterns: regexp.MustCompile(`(?i)(127\.0\.0\.1|0\.0\.0\.0|localhost|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+|\[::1\]|\[0:0:0:0:0:0:0:1\]|0x7f|2130706433|017700000001|\.internal\.|\.local\.|\.corp\.|\.home\.)`),
		cloudMetadata: regexp.MustCompile(`(?i)(169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|fd00:ec2::254)`),
		urlParams:     regexp.MustCompile(`(?i)(url|uri|link|href|src|source|redirect|callback|webhook|endpoint|target|dest|fetch|load|proxy|forward)=`),
	}
}

func (s *SSRFViaAPIDetector) Check(path, body, urlParam string) *SSRFFinding {
	// Check URL parameters for internal/metadata targets
	targets := []string{urlParam, body}
	for _, target := range targets {
		if target == "" {
			continue
		}

		if s.cloudMetadata.MatchString(target) {
			return &SSRFFinding{
				Severity:    core.SeverityCritical,
				Description: "Request targets cloud metadata endpoint (169.254.169.254 or equivalent). This can expose instance credentials and secrets.",
			}
		}

		if s.internalPatterns.MatchString(target) {
			return &SSRFFinding{
				Severity:    core.SeverityHigh,
				Description: "Request targets internal/private IP address. SSRF can be used to scan internal networks and access internal services.",
			}
		}
	}

	// Check for URL parameters in the path that might be SSRF vectors
	if s.urlParams.MatchString(path) && s.internalPatterns.MatchString(path) {
		return &SSRFFinding{
			Severity:    core.SeverityHigh,
			Description: "URL parameter in path contains internal IP address.",
		}
	}

	return nil
}

// ===========================================================================
// ResponseAnomalyAnalyzer — tracks API response patterns for anomalies
// ===========================================================================

type ResponseAnomalyAnalyzer struct {
	mu        sync.RWMutex
	endpoints map[string]*endpointStats
}

type endpointStats struct {
	totalRequests  int
	errorCount     int
	totalSize      int64
	sizeCount      int
	windowStart    time.Time
	lastSeen       time.Time
	// Baseline (from previous window)
	baselineErrorRate float64
	baselineAvgSize   int
	baselineSamples   int
}

type ResponseAnomaly struct {
	ErrorSpike          bool
	ResponseSizeAnomaly bool
	ErrorRate           float64
	BaselineErrorRate   float64
	ErrorCount          int
	Window              time.Duration
	SizeRatio           float64
	AvgResponseSize     int
}

func NewResponseAnomalyAnalyzer() *ResponseAnomalyAnalyzer {
	return &ResponseAnomalyAnalyzer{
		endpoints: make(map[string]*endpointStats),
	}
}

func (r *ResponseAnomalyAnalyzer) RecordRequest(method, path string, statusCode int, ip string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	key := method + ":" + normalizePath(path)
	now := time.Now()

	stats, exists := r.endpoints[key]
	if !exists {
		stats = &endpointStats{windowStart: now}
		r.endpoints[key] = stats
	}

	// Rotate window every 5 minutes
	if now.Sub(stats.windowStart) > 5*time.Minute {
		if stats.totalRequests > 0 {
			currentErrorRate := float64(stats.errorCount) / float64(stats.totalRequests)
			stats.baselineErrorRate = (stats.baselineErrorRate*float64(stats.baselineSamples) + currentErrorRate) / float64(stats.baselineSamples+1)
			if stats.sizeCount > 0 {
				stats.baselineAvgSize = int((int64(stats.baselineAvgSize)*int64(stats.baselineSamples) + stats.totalSize/int64(stats.sizeCount)) / int64(stats.baselineSamples+1))
			}
			stats.baselineSamples++
		}
		stats.totalRequests = 0
		stats.errorCount = 0
		stats.totalSize = 0
		stats.sizeCount = 0
		stats.windowStart = now
	}

	stats.totalRequests++
	stats.lastSeen = now
	if statusCode >= 400 {
		stats.errorCount++
	}
}

func (r *ResponseAnomalyAnalyzer) Analyze(method, path string, statusCode, responseSize int, ip string) ResponseAnomaly {
	r.mu.Lock()
	defer r.mu.Unlock()

	anomaly := ResponseAnomaly{}
	key := method + ":" + normalizePath(path)

	stats, exists := r.endpoints[key]
	if !exists {
		return anomaly
	}

	// Track response size
	if responseSize > 0 {
		stats.totalSize += int64(responseSize)
		stats.sizeCount++
	}

	now := time.Now()
	anomaly.Window = now.Sub(stats.windowStart)

	// Error rate spike detection
	if stats.totalRequests > 20 && stats.baselineSamples > 3 {
		currentErrorRate := float64(stats.errorCount) / float64(stats.totalRequests)
		anomaly.ErrorRate = currentErrorRate
		anomaly.BaselineErrorRate = stats.baselineErrorRate
		anomaly.ErrorCount = stats.errorCount

		// Spike: current error rate is 3x baseline and above 20%
		if stats.baselineErrorRate > 0 && currentErrorRate > stats.baselineErrorRate*3 && currentErrorRate > 0.2 {
			anomaly.ErrorSpike = true
		}
		// Also flag if error rate is above 50% regardless of baseline
		if currentErrorRate > 0.5 && stats.totalRequests > 50 {
			anomaly.ErrorSpike = true
		}
	}

	// Response size anomaly
	if responseSize > 0 && stats.baselineAvgSize > 0 && stats.baselineSamples > 3 {
		ratio := float64(responseSize) / float64(stats.baselineAvgSize)
		anomaly.SizeRatio = ratio
		anomaly.AvgResponseSize = stats.baselineAvgSize
		if ratio > 5.0 && responseSize > 10240 { // 5x above average and > 10KB
			anomaly.ResponseSizeAnomaly = true
		}
	}

	return anomaly
}

func (r *ResponseAnomalyAnalyzer) CleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.mu.Lock()
			cutoff := time.Now().Add(-30 * time.Minute)
			for key, stats := range r.endpoints {
				if stats.lastSeen.Before(cutoff) {
					delete(r.endpoints, key)
				}
			}
			r.mu.Unlock()
		}
	}
}

// ===========================================================================
// APIRegistry — shadow API detection with learning phase
// ===========================================================================

type APIRegistry struct {
	mu            sync.RWMutex
	documented    map[string]bool // "METHOD:/path" -> true
	observed      map[string]int  // "METHOD:/path" -> access count
	learningStart time.Time
	learningDone  bool
}

func NewAPIRegistry() *APIRegistry {
	return &APIRegistry{
		documented:    make(map[string]bool),
		observed:      make(map[string]int),
		learningStart: time.Now(),
	}
}

func (r *APIRegistry) RegisterEndpoint(method, path string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := method + ":" + normalizePath(path)
	r.documented[key] = true
}

func (r *APIRegistry) IsUndocumented(method, path string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	key := method + ":" + normalizePath(path)

	if r.documented[key] {
		return false
	}

	// Learning phase: first hour, absorb all endpoints as baseline
	if !r.learningDone {
		if time.Since(r.learningStart) < time.Hour {
			r.documented[key] = true
			return false
		}
		r.learningDone = true
	}

	return true
}

func (r *APIRegistry) RecordAccess(method, path string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := method + ":" + normalizePath(path)
	r.observed[key]++
}

// ===========================================================================
// EndpointRateLimiter — per-endpoint rate limiting with burst detection
// ===========================================================================

type EndpointRateLimiter struct {
	mu           sync.RWMutex
	counters     map[string]*epCounter
	maxPerMinute int
}

type epCounter struct {
	count    int
	window   time.Time
	lastSeen time.Time
}

type RateLimitExceeded struct {
	Severity core.Severity
	Count    int
	Limit    int
	Window   time.Duration
	Detail   string
}

func NewEndpointRateLimiter(settings map[string]interface{}) *EndpointRateLimiter {
	maxRPM := 200
	if val, ok := settings["api_max_rpm"]; ok {
		if v, ok := val.(float64); ok {
			maxRPM = int(v)
		}
	}
	return &EndpointRateLimiter{
		counters:     make(map[string]*epCounter),
		maxPerMinute: maxRPM,
	}
}

func (rl *EndpointRateLimiter) Check(ip, method, path string) *RateLimitExceeded {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	key := ip + ":" + method + ":" + normalizePath(path)
	now := time.Now()

	counter, exists := rl.counters[key]
	if !exists {
		rl.counters[key] = &epCounter{count: 1, window: now, lastSeen: now}
		return nil
	}

	if now.Sub(counter.window) > time.Minute {
		counter.count = 0
		counter.window = now
	}

	counter.count++
	counter.lastSeen = now

	if counter.count > rl.maxPerMinute {
		severity := core.SeverityMedium
		detail := "Standard rate limit exceeded"
		if counter.count > rl.maxPerMinute*5 {
			severity = core.SeverityHigh
			detail = "Severe rate limit violation — possible automated attack"
		}
		if counter.count > rl.maxPerMinute*20 {
			severity = core.SeverityCritical
			detail = "Extreme rate limit violation — active DoS or brute force attack"
		}
		return &RateLimitExceeded{
			Severity: severity,
			Count:    counter.count,
			Limit:    rl.maxPerMinute,
			Window:   now.Sub(counter.window),
			Detail:   detail,
		}
	}

	return nil
}

func (rl *EndpointRateLimiter) CleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rl.mu.Lock()
			cutoff := time.Now().Add(-10 * time.Minute)
			for key, counter := range rl.counters {
				if counter.lastSeen.Before(cutoff) {
					delete(rl.counters, key)
				}
			}
			rl.mu.Unlock()
		}
	}
}

// ===========================================================================
// Helpers
// ===========================================================================

func normalizePath(path string) string {
	parts := strings.Split(path, "/")
	for i, part := range parts {
		if isNumericID(part) || isUUID(part) {
			parts[i] = "{id}"
		}
	}
	return strings.Join(parts, "/")
}

func isNumericID(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
		} else {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				return false
			}
		}
	}
	return true
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
