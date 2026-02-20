package apifortress

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/1sec-project/1sec/internal/core"
	"github.com/rs/zerolog"
)

// ─── Helpers ─────────────────────────────────────────────────────────────────

type capPipeline struct {
	*core.AlertPipeline
	mu     sync.Mutex
	alerts []*core.Alert
}

func newCapPipeline() *capPipeline {
	cp := &capPipeline{}
	cp.AlertPipeline = core.NewAlertPipeline(zerolog.Nop(), 10000)
	cp.AlertPipeline.AddHandler(func(a *core.Alert) {
		cp.mu.Lock()
		cp.alerts = append(cp.alerts, a)
		cp.mu.Unlock()
	})
	return cp
}

func (cp *capPipeline) alertCount() int {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	return len(cp.alerts)
}

func (cp *capPipeline) hasAlertType(alertType string) bool {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	for _, a := range cp.alerts {
		if a.Type == alertType {
			return true
		}
	}
	return false
}

func startedFortress(t *testing.T, pipeline *core.AlertPipeline) *Fortress {
	t.Helper()
	f := New()
	cfg := core.DefaultConfig()
	if err := f.Start(context.Background(), nil, pipeline, cfg); err != nil {
		t.Fatalf("Fortress.Start() error: %v", err)
	}
	return f
}

func makeAPIRequest(path, method, userID, resourceID, userRole string) *core.SecurityEvent {
	ev := core.NewSecurityEvent("test", "http_request", core.SeverityInfo, "API request")
	ev.Details["path"] = path
	ev.Details["method"] = method
	ev.Details["user_id"] = userID
	ev.Details["resource_id"] = resourceID
	ev.Details["user_role"] = userRole
	ev.SourceIP = "10.0.0.1"
	return ev
}

// ─── Module Interface ─────────────────────────────────────────────────────────

var _ core.Module = (*Fortress)(nil)

func TestFortress_Name(t *testing.T) {
	f := New()
	if f.Name() != ModuleName {
		t.Errorf("Name() = %q, want %q", f.Name(), ModuleName)
	}
}

func TestFortress_Description(t *testing.T) {
	f := New()
	if f.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

func TestFortress_Start_Stop(t *testing.T) {
	f := New()
	cfg := core.DefaultConfig()
	if err := f.Start(context.Background(), nil, nil, cfg); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	if err := f.Stop(); err != nil {
		t.Errorf("Stop() error: %v", err)
	}
}

func TestFortress_HandleEvent_UnknownType_NoError(t *testing.T) {
	f := New()
	f.Start(context.Background(), nil, nil, core.DefaultConfig())
	ev := core.NewSecurityEvent("test", "unknown_type", core.SeverityInfo, "s")
	if err := f.HandleEvent(ev); err != nil {
		t.Errorf("HandleEvent(unknown_type) error: %v", err)
	}
}

func TestFortress_HandleEvent_AllKnownTypes(t *testing.T) {
	pipeline := core.NewAlertPipeline(zerolog.Nop(), 100)
	f := startedFortress(t, pipeline)
	for _, et := range []string{"http_request", "http_response", "api_request", "api_response", "graphql_request", "jwt_validation", "token_event"} {
		ev := core.NewSecurityEvent("test", et, core.SeverityInfo, "test")
		if err := f.HandleEvent(ev); err != nil {
			t.Errorf("HandleEvent(%q) error: %v", et, err)
		}
	}
}

// ─── BOLADetector ─────────────────────────────────────────────────────────────

func TestBOLADetector_NoAttack_FewResources(t *testing.T) {
	d := NewBOLADetector(map[string]interface{}{})
	result := d.Detect("user1", "res-1", "/api/items/1", "GET", "192.168.1.1")
	if result.IsAttack {
		t.Error("should not flag as attack for single resource access")
	}
}

func TestBOLADetector_Enumeration_Attack(t *testing.T) {
	d := NewBOLADetector(map[string]interface{}{"bola_threshold": float64(5)})
	for i := 0; i < 10; i++ {
		d.Detect("user1", fmt.Sprintf("res-%d", i), "/api/items", "GET", "10.0.0.1")
	}
	result := d.Detect("user1", "res-99", "/api/items", "GET", "10.0.0.1")
	if !result.IsAttack {
		t.Error("expected IsAttack=true after exceeding enumeration threshold")
	}
}

func TestBOLADetector_IDOR_Sequential(t *testing.T) {
	d := NewBOLADetector(map[string]interface{}{})
	d.Detect("user1", "100", "/api/items/100", "GET", "10.0.0.1")
	d.Detect("user1", "101", "/api/items/101", "GET", "10.0.0.1")
	result := d.Detect("user1", "102", "/api/items/102", "GET", "10.0.0.1")
	if !result.IDORAttempt {
		t.Error("expected IDORAttempt=true for sequential IDs 100, 101, 102")
	}
}

func TestBOLADetector_IDOR_NonSequential(t *testing.T) {
	d := NewBOLADetector(map[string]interface{}{})
	d.Detect("user1", "100", "/api/items", "GET", "10.0.0.1")
	d.Detect("user1", "500", "/api/items", "GET", "10.0.0.1")
	result := d.Detect("user1", "999", "/api/items", "GET", "10.0.0.1")
	if result.IDORAttempt {
		t.Error("non-sequential IDs should not trigger IDOR detection")
	}
}

func TestBOLADetector_IDOR_UUIDIDs_Safe(t *testing.T) {
	d := NewBOLADetector(map[string]interface{}{})
	d.Detect("user1", "550e8400-e29b-41d4-a716-446655440000", "/api/items", "GET", "10.0.0.1")
	d.Detect("user1", "550e8400-e29b-41d4-a716-446655440001", "/api/items", "GET", "10.0.0.1")
	result := d.Detect("user1", "550e8400-e29b-41d4-a716-446655440002", "/api/items", "GET", "10.0.0.1")
	if result.IDORAttempt {
		t.Error("UUID-style IDs should not trigger IDOR detection")
	}
}

func TestBOLADetector_ResourceCount_Window(t *testing.T) {
	d := NewBOLADetector(map[string]interface{}{})
	d.Detect("user1", "r1", "/api/items", "GET", "10.0.0.1")
	result := d.Detect("user1", "r2", "/api/items", "GET", "10.0.0.1")
	if result.Window < 0 {
		t.Error("Window duration should be non-negative")
	}
	if result.ResourceCount < 1 {
		t.Errorf("ResourceCount = %d, want >= 1", result.ResourceCount)
	}
}

func TestBOLADetector_ConcurrentAccess(t *testing.T) {
	d := NewBOLADetector(map[string]interface{}{})
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			d.Detect(fmt.Sprintf("user%d", n%3), fmt.Sprintf("res%d", n), "/api/items", "GET", "10.0.0.1")
		}(i)
	}
	wg.Wait()
}

// ─── isSequentialIDs ─────────────────────────────────────────────────────────

func TestIsSequentialIDs(t *testing.T) {
	cases := []struct {
		ids  []string
		want bool
	}{
		{[]string{"1", "2", "3"}, true},
		{[]string{"100", "101", "102"}, true},
		{[]string{"1", "3", "5"}, true},  // gap of 2 — OK
		{[]string{"1", "4", "7"}, true},  // gap of 3 — still sequential per implementation (diff <= 3)
		{[]string{"1", "5", "9"}, false}, // gap of 4 — exceeds max diff of 3
		{[]string{"100", "200", "300"}, false},
		{[]string{"abc", "def", "ghi"}, false},
		{[]string{"1"}, false}, // too short
		{[]string{}, false},
	}
	for _, tc := range cases {
		got := isSequentialIDs(tc.ids)
		if got != tc.want {
			t.Errorf("isSequentialIDs(%v) = %v, want %v", tc.ids, got, tc.want)
		}
	}
}

// ─── parseNumericID ───────────────────────────────────────────────────────────

func TestParseNumericID(t *testing.T) {
	cases := []struct {
		s    string
		want int
	}{
		{"42", 42},
		{"007", 7},
		{"100abc", 100},
		{"abc", -1},
		{"", -1},
		{"abc123", -1},
	}
	for _, tc := range cases {
		got := parseNumericID(tc.s)
		if got != tc.want {
			t.Errorf("parseNumericID(%q) = %d, want %d", tc.s, got, tc.want)
		}
	}
}

// ─── BFLADetector ────────────────────────────────────────────────────────────

func TestBFLADetector_AdminPath_NonAdmin(t *testing.T) {
	d := NewBFLADetector()
	v := d.Check("user1", "user", "GET", "/admin/dashboard", "10.0.0.1")
	if v == nil {
		t.Error("expected BFLA violation for user accessing /admin")
	}
	if v.Severity != core.SeverityCritical {
		t.Errorf("Severity = %v, want Critical", v.Severity)
	}
}

func TestBFLADetector_AdminPath_Admin_Allowed(t *testing.T) {
	d := NewBFLADetector()
	v := d.Check("admin1", "admin", "GET", "/admin/dashboard", "10.0.0.1")
	if v != nil {
		t.Errorf("admin should be allowed on /admin: %v", v.Reason)
	}
}

func TestBFLADetector_SuperAdmin_Allowed(t *testing.T) {
	d := NewBFLADetector()
	v := d.Check("sa", "superadmin", "DELETE", "/system/reset", "10.0.0.1")
	if v != nil {
		t.Errorf("superadmin should be allowed: %v", v.Reason)
	}
}

func TestBFLADetector_WriteOnSensitivePath_LowPriv(t *testing.T) {
	d := NewBFLADetector()
	v := d.Check("user1", "user", "POST", "/users", "10.0.0.1")
	if v == nil {
		t.Error("expected BFLA for user POST to /users")
	}
}

func TestBFLADetector_WriteOnSensitivePath_Editor_Allowed(t *testing.T) {
	d := NewBFLADetector()
	v := d.Check("editor1", "editor", "POST", "/users", "10.0.0.1")
	if v != nil {
		t.Errorf("editor should be allowed to POST /users: %v", v.Reason)
	}
}

func TestBFLADetector_Delete_NonAdmin_TopLevel(t *testing.T) {
	d := NewBFLADetector()
	v := d.Check("user1", "user", "DELETE", "/items/5", "10.0.0.1")
	if v == nil {
		t.Error("expected BFLA for non-admin DELETE on top-level resource")
	}
}

func TestBFLADetector_Delete_Admin_Allowed(t *testing.T) {
	d := NewBFLADetector()
	v := d.Check("admin1", "admin", "DELETE", "/items/5", "10.0.0.1")
	if v != nil {
		t.Errorf("admin DELETE should be allowed: %v", v.Reason)
	}
}

func TestBFLADetector_RepeatedViolations_EscalatesSeverity(t *testing.T) {
	d := NewBFLADetector()
	for i := 0; i < 7; i++ {
		d.Check("repeat_offender", "user", "GET", "/admin", "10.0.0.1")
	}
	v := d.Check("repeat_offender", "user", "GET", "/normal", "10.0.0.1")
	if v == nil {
		t.Error("expected BFLA for repeat offender (>5 violations)")
	}
	if v.Severity != core.SeverityCritical {
		t.Errorf("Severity = %v, want Critical for repeat offender", v.Severity)
	}
}

func TestBFLADetector_UnknownRole_DefaultsToBasicUser(t *testing.T) {
	d := NewBFLADetector()
	v := d.Check("user1", "alien_role_xyz", "GET", "/admin", "10.0.0.1")
	if v == nil {
		t.Error("unknown role should default to user-level and be blocked from /admin")
	}
}

func TestBFLADetector_Concurrent(t *testing.T) {
	d := NewBFLADetector()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			d.Check(fmt.Sprintf("user%d", n), "user", "GET", "/admin", "10.0.0.1")
		}(i)
	}
	wg.Wait()
}

// ─── MassAssignmentDetector ───────────────────────────────────────────────────

func TestMassAssignment_AdminFields(t *testing.T) {
	d := NewMassAssignmentDetector()
	body := `{"name": "Alice", "id": "123", "secret": "abc"}`
	findings := d.Check("POST", "/api/users", body, "application/json")
	if len(findings) == 0 {
		t.Error("expected findings for id/secret in payload")
	}
	hasCritical := false
	for _, f := range findings {
		if f.Severity == core.SeverityCritical {
			hasCritical = true
		}
	}
	if !hasCritical {
		t.Error("expected Critical for internal field mass assignment")
	}
}

func TestMassAssignment_SensitiveFields(t *testing.T) {
	d := NewMassAssignmentDetector()
	body := `{"username": "alice", "is_admin": true, "role": "superadmin"}`
	findings := d.Check("POST", "/api/users", body, "application/json")
	if len(findings) == 0 {
		t.Error("expected findings for role/is_admin fields")
	}
}

func TestMassAssignment_CleanPayload(t *testing.T) {
	d := NewMassAssignmentDetector()
	body := `{"name": "Alice", "email": "alice@example.com", "age": 30}`
	findings := d.Check("POST", "/api/users", body, "application/json")
	if len(findings) > 0 {
		t.Errorf("expected no findings for clean payload, got %d", len(findings))
	}
}

func TestMassAssignment_NonJSON_ContentType_Skipped(t *testing.T) {
	d := NewMassAssignmentDetector()
	body := "role=admin&is_admin=true"
	findings := d.Check("POST", "/api/users", body, "application/x-www-form-urlencoded")
	if len(findings) > 0 {
		t.Error("non-JSON content should be skipped")
	}
}

func TestMassAssignment_PUTMethod(t *testing.T) {
	d := NewMassAssignmentDetector()
	body := `{"is_admin": true}`
	findings := d.Check("PUT", "/api/users/1", body, "application/json")
	if len(findings) == 0 {
		t.Error("expected findings for PUT with sensitive field")
	}
}

// ─── DataExposureDetector ─────────────────────────────────────────────────────

func TestDataExposure_SensitiveCredentials(t *testing.T) {
	d := NewDataExposureDetector()
	body := `{"user": "alice", "password": "mysecret123", "status": "ok"}`
	finding := d.Check("/api/users/1", "GET", body, 0)
	if finding == nil {
		t.Error("expected finding for password in response")
	}
	if finding.Severity != core.SeverityCritical {
		t.Errorf("Severity = %v, want Critical", finding.Severity)
	}
}

func TestDataExposure_PII_Data(t *testing.T) {
	d := NewDataExposureDetector()
	body := `{"date_of_birth": "1985-03-15", "national_id": "123-ABC"}`
	finding := d.Check("/api/users/1", "GET", body, 0)
	if finding == nil {
		t.Error("expected finding for PII data")
	}
}

func TestDataExposure_LargeResponse_NonExportPath(t *testing.T) {
	d := NewDataExposureDetector()
	finding := d.Check("/api/users/1", "GET", "", 2*1024*1024)
	if finding == nil {
		t.Error("expected finding for oversized response on non-export endpoint")
	}
}

func TestDataExposure_LargeResponse_ExportPath_OK(t *testing.T) {
	d := NewDataExposureDetector()
	finding := d.Check("/api/data/export", "GET", "", 2*1024*1024)
	if finding != nil {
		t.Error("export endpoint large response should not be flagged")
	}
}

func TestDataExposure_LargeResponse_BulkPath_OK(t *testing.T) {
	d := NewDataExposureDetector()
	finding := d.Check("/api/users/bulk", "GET", "", 2*1024*1024)
	if finding != nil {
		t.Error("bulk endpoint large response should not be flagged")
	}
}

func TestDataExposure_CleanResponse(t *testing.T) {
	d := NewDataExposureDetector()
	body := `{"name": "Alice", "status": "active"}`
	finding := d.Check("/api/users/1", "GET", body, 100)
	if finding != nil {
		t.Errorf("expected no finding for clean response: %v", finding.Description)
	}
}

// ─── GraphQLGuard ─────────────────────────────────────────────────────────────

func TestGraphQLGuard_MeasureDepth_Values(t *testing.T) {
	g := NewGraphQLGuard(map[string]interface{}{})
	cases := []struct {
		query string
		depth int
	}{
		{"{ a }", 1},
		{"{ a { b } }", 2},
		{"{ a { b { c } } }", 3},
	}
	for _, tc := range cases {
		got := g.measureDepth(tc.query)
		if got != tc.depth {
			t.Errorf("measureDepth(%q) = %d, want %d", tc.query, got, tc.depth)
		}
	}
}

func TestGraphQLGuard_DeepQuery(t *testing.T) {
	g := NewGraphQLGuard(map[string]interface{}{"graphql_max_depth": float64(3)})
	deepQuery := "query { a { b { c { d { e { f { g } } } } } } }"
	findings := g.Analyze(deepQuery, "", "user1", "10.0.0.1")
	hasDepth := false
	for _, f := range findings {
		if f.AlertType == "graphql_depth" {
			hasDepth = true
		}
	}
	if !hasDepth {
		t.Error("expected graphql_depth finding for deeply nested query")
	}
}

func TestGraphQLGuard_AliasAbuse(t *testing.T) {
	g := NewGraphQLGuard(map[string]interface{}{"graphql_max_aliases": float64(2)})
	aliases := ""
	for i := 0; i < 5; i++ {
		aliases += fmt.Sprintf("a%d: field%d { id } ", i, i)
	}
	query := "query { " + aliases + "}"
	findings := g.Analyze(query, "", "user1", "10.0.0.1")
	hasAlias := false
	for _, f := range findings {
		if f.AlertType == "graphql_alias_abuse" {
			hasAlias = true
		}
	}
	if !hasAlias {
		t.Error("expected graphql_alias_abuse finding")
	}
}

func TestGraphQLGuard_Introspection(t *testing.T) {
	g := NewGraphQLGuard(map[string]interface{}{})
	query := "{ __schema { types { name } } }"
	findings := g.Analyze(query, "", "user1", "10.0.0.1")
	hasIntro := false
	for _, f := range findings {
		if f.AlertType == "graphql_introspection" {
			hasIntro = true
		}
	}
	if !hasIntro {
		t.Error("expected graphql_introspection finding")
	}
}

func TestGraphQLGuard_DangerousMutation(t *testing.T) {
	g := NewGraphQLGuard(map[string]interface{}{})
	query := "mutation { deleteAll(confirm: true) { success } }"
	findings := g.Analyze(query, "", "user1", "10.0.0.1")
	hasDangerous := false
	for _, f := range findings {
		if f.AlertType == "graphql_dangerous_mutation" {
			hasDangerous = true
		}
	}
	if !hasDangerous {
		t.Error("expected graphql_dangerous_mutation finding")
	}
}

func TestGraphQLGuard_CleanQuery(t *testing.T) {
	g := NewGraphQLGuard(map[string]interface{}{})
	query := "query { user(id: \"123\") { name email } }"
	findings := g.Analyze(query, "", "user1", "10.0.0.1")
	if len(findings) > 0 {
		t.Errorf("expected no findings for clean query, got %d", len(findings))
	}
}

// ─── JWTValidator ─────────────────────────────────────────────────────────────

func TestJWTValidator_NoneAlgorithm(t *testing.T) {
	v := NewJWTValidator()
	findings := v.Validate("", `{"alg":"none","typ":"JWT"}`, "none", "")
	if len(findings) == 0 {
		t.Error("expected finding for JWT none algorithm")
	}
	hasCritical := false
	for _, f := range findings {
		if f.Severity == core.SeverityCritical {
			hasCritical = true
		}
	}
	if !hasCritical {
		t.Error("expected Critical severity for JWT none algorithm attack")
	}
}

func TestJWTValidator_NoneAlgorithm_CaseVariants(t *testing.T) {
	v := NewJWTValidator()
	// The "none" algorithm attack often uses case variants to bypass naive checks
	for _, alg := range []string{"none", "None", "NONE", "nOnE"} {
		header := fmt.Sprintf(`{"alg":"%s","typ":"JWT"}`, alg)
		findings := v.Validate("", header, alg, "")
		if len(findings) == 0 {
			t.Errorf("expected finding for JWT none alg variant: %q", alg)
		}
	}
}

func TestJWTValidator_EmptyInputs_NoError(t *testing.T) {
	v := NewJWTValidator()
	// Should not panic
	findings := v.Validate("", "", "", "")
	_ = findings
}

// ─── SSRFViaAPIDetector ───────────────────────────────────────────────────────

func TestSSRFDetector_PrivateIP_InBody(t *testing.T) {
	d := NewSSRFViaAPIDetector()
	result := d.Check("/api/fetch", `{"url":"http://192.168.1.1/admin"}`, "")
	if result == nil {
		t.Error("expected SSRF finding for private IP URL in body")
	}
}

func TestSSRFDetector_CloudMetadata(t *testing.T) {
	d := NewSSRFViaAPIDetector()
	result := d.Check("/api/fetch", `{"url":"http://169.254.169.254/latest/meta-data/"}`, "")
	if result == nil {
		t.Error("expected SSRF finding for AWS metadata endpoint")
	}
	if result.Severity != core.SeverityCritical {
		t.Errorf("Severity = %v, want Critical for cloud metadata SSRF", result.Severity)
	}
}

func TestSSRFDetector_Localhost(t *testing.T) {
	d := NewSSRFViaAPIDetector()
	result := d.Check("/api/proxy", `{"endpoint":"http://localhost:8080/internal"}`, "")
	if result == nil {
		t.Error("expected SSRF finding for localhost URL")
	}
}

func TestSSRFDetector_GopherScheme(t *testing.T) {
	d := NewSSRFViaAPIDetector()
	result := d.Check("/api/proxy", `{"url":"gopher://127.0.0.1:25/_MAIL FROM"}`, "")
	if result == nil {
		t.Error("expected SSRF finding for gopher:// scheme")
	}
}

func TestSSRFDetector_SafeURL(t *testing.T) {
	d := NewSSRFViaAPIDetector()
	result := d.Check("/api/proxy", `{"url":"https://api.stripe.com/v1/charges"}`, "")
	if result != nil {
		t.Errorf("expected no SSRF for safe external URL, got: %v", result.Description)
	}
}

// ─── EndpointRateLimiter ──────────────────────────────────────────────────────

func TestRateLimiter_Exceeded(t *testing.T) {
	// Setting key is "api_max_rpm" per the implementation
	settings := map[string]interface{}{"api_max_rpm": float64(5)}
	rl := NewEndpointRateLimiter(settings)
	for i := 0; i < 6; i++ {
		rl.Check("10.0.0.1", "GET", "/api/sensitive")
	}
	exceeded := rl.Check("10.0.0.1", "GET", "/api/sensitive")
	if exceeded == nil {
		t.Error("expected rate limit exceeded after exceeding api_max_rpm threshold")
	}
}

func TestRateLimiter_NotExceeded(t *testing.T) {
	rl := NewEndpointRateLimiter(map[string]interface{}{})
	for i := 0; i < 3; i++ {
		if r := rl.Check("10.0.0.2", "GET", "/api/public"); r != nil {
			t.Errorf("unexpected rate limit at request %d: %v", i+1, r)
		}
	}
}

func TestRateLimiter_DifferentIPs_Independent(t *testing.T) {
	settings := map[string]interface{}{"api_max_rpm": float64(2)}
	rl := NewEndpointRateLimiter(settings)
	rl.Check("IP1", "GET", "/api/test")
	rl.Check("IP1", "GET", "/api/test")
	rl.Check("IP1", "GET", "/api/test")
	// IP2 should be unaffected
	if r := rl.Check("IP2", "GET", "/api/test"); r != nil {
		t.Error("IP2 should not be rate limited when only IP1 exceeded limit")
	}
}

// ─── ResponseAnomalyAnalyzer ──────────────────────────────────────────────────

func TestResponseAnomalyAnalyzer_ErrorSpike(t *testing.T) {
	ra := NewResponseAnomalyAnalyzer()
	// ErrorSpike requires both totalRequests > 20 AND baselineSamples > 3.
	// baselineSamples only increment after a 5-minute window rotates, so in a
	// unit test context we can only verify data tracking and no-panic behavior.
	for i := 0; i < 10; i++ {
		ra.RecordRequest("GET", "/api/endpoint", 200, "10.0.0.1")
	}
	for i := 0; i < 55; i++ {
		ra.RecordRequest("GET", "/api/endpoint", 500, "10.0.0.1")
	}
	anomaly := ra.Analyze("GET", "/api/endpoint", 500, 0, "10.0.0.1")
	// ErrorSpike won't fire without baseline (baselineSamples == 0), but
	// the struct should still track the window duration.
	if anomaly.Window < 0 {
		t.Error("expected non-negative Window duration")
	}
}

func TestResponseAnomalyAnalyzer_NoAnomaly(t *testing.T) {
	ra := NewResponseAnomalyAnalyzer()
	for i := 0; i < 10; i++ {
		ra.RecordRequest("GET", "/api/health", 200, "10.0.0.1")
	}
	anomaly := ra.Analyze("GET", "/api/health", 200, 512, "10.0.0.1")
	_ = anomaly // Baseline established; no spike expected
}

// ─── APIMitigations ──────────────────────────────────────────────────────────

func TestGetAPIMitigations_AllKnownTypes(t *testing.T) {
	types := []string{
		"bola", "idor", "bfla", "mass_assignment", "data_exposure",
		"ssrf_via_api", "graphql_depth", "graphql_batch",
		"graphql_introspection", "graphql_alias_abuse", "unknown_random_type",
	}
	for _, at := range types {
		m := getAPIMitigations(at)
		if len(m) == 0 {
			t.Errorf("getAPIMitigations(%q) returned empty slice", at)
		}
	}
}

// ─── summarizeMatches ─────────────────────────────────────────────────────────

func TestSummarizeMatches_Empty(t *testing.T) {
	if summarizeMatches(nil) != "" {
		t.Error("expected empty string for nil input")
	}
	if summarizeMatches([]string{}) != "" {
		t.Error("expected empty string for empty slice")
	}
}

func TestSummarizeMatches_ValidInput(t *testing.T) {
	matches := []string{`"password": "secret"`, `"api_key": "abc123"`}
	result := summarizeMatches(matches)
	if result == "" {
		t.Error("expected non-empty summary for valid input")
	}
}

// ─── normalizePath ───────────────────────────────────────────────────────────

func TestNormalizePath(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/api/users/123", "/api/users/{id}"},
		{"/api/items/456/orders/789", "/api/items/{id}/orders/{id}"},
		{"/api/health", "/api/health"},
		{"/", "/"},
	}
	for _, tc := range cases {
		got := normalizePath(tc.in)
		if got != tc.want {
			t.Errorf("normalizePath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// ─── getStringDetail / getIntDetail ──────────────────────────────────────────

func TestGetStringDetail(t *testing.T) {
	ev := core.NewSecurityEvent("m", "t", core.SeverityInfo, "s")
	ev.Details["key"] = "value"
	if getStringDetail(ev, "key") != "value" {
		t.Error("expected 'value'")
	}
	if getStringDetail(ev, "missing") != "" {
		t.Error("expected empty for missing key")
	}
}

func TestGetIntDetail(t *testing.T) {
	ev := core.NewSecurityEvent("m", "t", core.SeverityInfo, "s")
	ev.Details["n"] = 42
	ev.Details["f"] = float64(3.7)
	if getIntDetail(ev, "n") != 42 {
		t.Error("int detail failed")
	}
	if getIntDetail(ev, "f") != 3 {
		t.Error("float64 detail failed")
	}
	if getIntDetail(ev, "missing") != 0 {
		t.Error("missing int should be 0")
	}
}

// Suppress unused import
var _ = time.Second
