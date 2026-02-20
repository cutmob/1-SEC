package ingest

import (
	"testing"
	"time"

	"github.com/1sec-project/1sec/internal/core"
	"github.com/rs/zerolog"
)

// ─── parseSyslog ──────────────────────────────────────────────────────────────

func TestParseSyslog_RFC5424(t *testing.T) {
	raw := `<134>1 2025-06-15T10:30:00Z myhost myapp 1234 ID47 This is a test message`
	msg := parseSyslog(raw)
	if msg == nil {
		t.Fatal("expected non-nil message for RFC 5424 input")
	}
	// PRI 134 = facility 16 (local0), severity 6 (informational)
	if msg.Facility != 16 {
		t.Errorf("Facility = %d, want 16", msg.Facility)
	}
	if msg.Severity != 6 {
		t.Errorf("Severity = %d, want 6", msg.Severity)
	}
	if msg.Hostname != "myhost" {
		t.Errorf("Hostname = %q, want %q", msg.Hostname, "myhost")
	}
	if msg.AppName != "myapp" {
		t.Errorf("AppName = %q, want %q", msg.AppName, "myapp")
	}
	if msg.ProcID != "1234" {
		t.Errorf("ProcID = %q, want %q", msg.ProcID, "1234")
	}
	if msg.MsgID != "ID47" {
		t.Errorf("MsgID = %q, want %q", msg.MsgID, "ID47")
	}
	if msg.Timestamp == nil {
		t.Error("expected non-nil Timestamp")
	}
}

func TestParseSyslog_RFC3164(t *testing.T) {
	raw := `<38>Jun 15 10:30:00 myhost sshd[1234]: Failed password for root from 1.2.3.4 port 22`
	msg := parseSyslog(raw)
	if msg == nil {
		t.Fatal("expected non-nil message for RFC 3164 input")
	}
	// PRI 38 = facility 4 (auth), severity 6 (informational)
	if msg.Facility != 4 {
		t.Errorf("Facility = %d, want 4", msg.Facility)
	}
	if msg.Severity != 6 {
		t.Errorf("Severity = %d, want 6", msg.Severity)
	}
	if msg.Hostname != "myhost" {
		t.Errorf("Hostname = %q, want %q", msg.Hostname, "myhost")
	}
	if msg.AppName != "sshd" {
		t.Errorf("AppName = %q, want %q", msg.AppName, "sshd")
	}
	if msg.ProcID != "1234" {
		t.Errorf("ProcID = %q, want %q", msg.ProcID, "1234")
	}
}

func TestParseSyslog_RFC3164_NoAppName(t *testing.T) {
	raw := `<13>Jun 15 10:30:00 myhost just a plain message`
	msg := parseSyslog(raw)
	if msg == nil {
		t.Fatal("expected non-nil message")
	}
	if msg.Hostname != "myhost" {
		t.Errorf("Hostname = %q, want %q", msg.Hostname, "myhost")
	}
}

func TestParseSyslog_BarePriority(t *testing.T) {
	raw := `<13>Some bare message without timestamp`
	msg := parseSyslog(raw)
	if msg == nil {
		t.Fatal("expected non-nil message for bare priority input")
	}
	// PRI 13 = facility 1 (user), severity 5 (notice)
	if msg.Facility != 1 {
		t.Errorf("Facility = %d, want 1", msg.Facility)
	}
	if msg.Severity != 5 {
		t.Errorf("Severity = %d, want 5", msg.Severity)
	}
	if msg.Message != "Some bare message without timestamp" {
		t.Errorf("Message = %q", msg.Message)
	}
}

func TestParseSyslog_Empty(t *testing.T) {
	if parseSyslog("") != nil {
		t.Error("expected nil for empty input")
	}
	if parseSyslog("   ") != nil {
		t.Error("expected nil for whitespace-only input")
	}
}

func TestParseSyslog_Unparseable(t *testing.T) {
	// No angle brackets = no PRI = nil
	if parseSyslog("just some random text") != nil {
		t.Error("expected nil for unparseable input")
	}
}

// ─── syslogSeverityToCore ─────────────────────────────────────────────────────

func TestSyslogSeverityToCore(t *testing.T) {
	tests := []struct {
		syslogSev int
		want      core.Severity
	}{
		{0, core.SeverityCritical}, // emergency
		{1, core.SeverityCritical}, // alert
		{2, core.SeverityHigh},     // critical
		{3, core.SeverityHigh},     // error
		{4, core.SeverityMedium},   // warning
		{5, core.SeverityLow},      // notice
		{6, core.SeverityInfo},     // informational
		{7, core.SeverityInfo},     // debug
	}
	for _, tc := range tests {
		got := syslogSeverityToCore(tc.syslogSev)
		if got != tc.want {
			t.Errorf("syslogSeverityToCore(%d) = %v, want %v", tc.syslogSev, got, tc.want)
		}
	}
}

// ─── classifySyslogEvent ──────────────────────────────────────────────────────

func TestClassifySyslogEvent_AuthFailure(t *testing.T) {
	msg := &syslogMessage{AppName: "sshd", Message: "Failed password for root from 1.2.3.4 port 22"}
	if classifySyslogEvent(msg) != "auth_failure" {
		t.Errorf("expected auth_failure, got %q", classifySyslogEvent(msg))
	}
}

func TestClassifySyslogEvent_AuthSuccess(t *testing.T) {
	msg := &syslogMessage{AppName: "sshd", Message: "Accepted publickey for admin from 10.0.0.1 port 22"}
	if classifySyslogEvent(msg) != "auth_success" {
		t.Errorf("expected auth_success, got %q", classifySyslogEvent(msg))
	}
}

func TestClassifySyslogEvent_SessionActivity(t *testing.T) {
	msg := &syslogMessage{AppName: "sshd", Message: "session closed for user admin"}
	if classifySyslogEvent(msg) != "session_activity" {
		t.Errorf("expected session_activity, got %q", classifySyslogEvent(msg))
	}
}

func TestClassifySyslogEvent_PrivilegeChange(t *testing.T) {
	msg := &syslogMessage{AppName: "sudo", Message: "sudo: admin : COMMAND=/bin/bash"}
	if classifySyslogEvent(msg) != "privilege_change" {
		t.Errorf("expected privilege_change, got %q", classifySyslogEvent(msg))
	}
}

func TestClassifySyslogEvent_Firewall(t *testing.T) {
	msg := &syslogMessage{AppName: "kernel", Message: "iptables DROP IN=eth0 SRC=1.2.3.4"}
	if classifySyslogEvent(msg) != "network_connection" {
		t.Errorf("expected network_connection, got %q", classifySyslogEvent(msg))
	}
}

func TestClassifySyslogEvent_Kernel(t *testing.T) {
	msg := &syslogMessage{AppName: "kernel", Message: "segfault at 0000000000000000 ip 00007f"}
	if classifySyslogEvent(msg) != "process_exec" {
		t.Errorf("expected process_exec, got %q", classifySyslogEvent(msg))
	}
}

func TestClassifySyslogEvent_FileChange(t *testing.T) {
	msg := &syslogMessage{AppName: "auditd", Message: "file changed /etc/passwd"}
	if classifySyslogEvent(msg) != "file_change" {
		t.Errorf("expected file_change, got %q", classifySyslogEvent(msg))
	}
}

func TestClassifySyslogEvent_Process(t *testing.T) {
	msg := &syslogMessage{AppName: "systemd", Message: "process started /usr/bin/evil"}
	if classifySyslogEvent(msg) != "process_exec" {
		t.Errorf("expected process_exec, got %q", classifySyslogEvent(msg))
	}
}

func TestClassifySyslogEvent_GenericAuth(t *testing.T) {
	msg := &syslogMessage{AppName: "sshd", Message: "Connection from 10.0.0.1"}
	if classifySyslogEvent(msg) != "auth_attempt" {
		t.Errorf("expected auth_attempt, got %q", classifySyslogEvent(msg))
	}
}

func TestClassifySyslogEvent_AuthFacility(t *testing.T) {
	msg := &syslogMessage{Facility: 4, Message: "some auth message"}
	if classifySyslogEvent(msg) != "auth_attempt" {
		t.Errorf("expected auth_attempt for facility 4, got %q", classifySyslogEvent(msg))
	}
}

func TestClassifySyslogEvent_AuthPrivFacility(t *testing.T) {
	msg := &syslogMessage{Facility: 10, Message: "some authpriv message"}
	if classifySyslogEvent(msg) != "auth_attempt" {
		t.Errorf("expected auth_attempt for facility 10, got %q", classifySyslogEvent(msg))
	}
}

func TestClassifySyslogEvent_KernFacility(t *testing.T) {
	msg := &syslogMessage{Facility: 0, Message: "some kernel message"}
	if classifySyslogEvent(msg) != "process_exec" {
		t.Errorf("expected process_exec for facility 0, got %q", classifySyslogEvent(msg))
	}
}

func TestClassifySyslogEvent_Default(t *testing.T) {
	msg := &syslogMessage{Facility: 1, Message: "some random message"}
	if classifySyslogEvent(msg) != "syslog_event" {
		t.Errorf("expected syslog_event, got %q", classifySyslogEvent(msg))
	}
}

// ─── enrichEventFromSyslog ────────────────────────────────────────────────────

func TestEnrichEventFromSyslog_Username(t *testing.T) {
	msg := &syslogMessage{
		AppName: "sshd",
		Message: "Failed password for user admin from 1.2.3.4 port 22",
	}
	event := core.NewSecurityEvent("syslog", "auth_failure", core.SeverityHigh, msg.Message)
	enrichEventFromSyslog(event, msg)

	if event.Details["username"] != "admin" {
		t.Errorf("username = %q, want %q", event.Details["username"], "admin")
	}
}

func TestEnrichEventFromSyslog_InvalidUser(t *testing.T) {
	msg := &syslogMessage{
		AppName: "sshd",
		Message: "Failed password for invalid user hacker from 5.6.7.8 port 22",
	}
	event := core.NewSecurityEvent("syslog", "auth_failure", core.SeverityHigh, msg.Message)
	enrichEventFromSyslog(event, msg)

	if event.Details["username"] != "hacker" {
		t.Errorf("username = %q, want %q", event.Details["username"], "hacker")
	}
}

func TestEnrichEventFromSyslog_SourceIP(t *testing.T) {
	msg := &syslogMessage{
		AppName: "sshd",
		Message: "Failed password for root from 1.2.3.4 port 22",
	}
	event := core.NewSecurityEvent("syslog", "auth_failure", core.SeverityHigh, msg.Message)
	event.SourceIP = "127.0.0.1" // relay IP
	enrichEventFromSyslog(event, msg)

	if event.Details["syslog_reported_ip"] != "1.2.3.4" {
		t.Errorf("syslog_reported_ip = %q, want %q", event.Details["syslog_reported_ip"], "1.2.3.4")
	}
	// Should override relay IP
	if event.SourceIP != "1.2.3.4" {
		t.Errorf("SourceIP = %q, want %q (should override relay)", event.SourceIP, "1.2.3.4")
	}
}

func TestEnrichEventFromSyslog_SourceIP_NoOverride(t *testing.T) {
	msg := &syslogMessage{
		AppName: "sshd",
		Message: "Failed password for root from 1.2.3.4 port 22",
	}
	event := core.NewSecurityEvent("syslog", "auth_failure", core.SeverityHigh, msg.Message)
	event.SourceIP = "10.0.0.5" // non-relay IP
	enrichEventFromSyslog(event, msg)

	// Should NOT override non-relay IP
	if event.SourceIP != "10.0.0.5" {
		t.Errorf("SourceIP = %q, want %q (should not override non-relay)", event.SourceIP, "10.0.0.5")
	}
}

func TestEnrichEventFromSyslog_ProcessInfo(t *testing.T) {
	msg := &syslogMessage{
		AppName: "sshd",
		ProcID:  "1234",
		Message: "some message",
	}
	event := core.NewSecurityEvent("syslog", "auth_attempt", core.SeverityInfo, msg.Message)
	enrichEventFromSyslog(event, msg)

	if event.Details["process_name"] != "sshd" {
		t.Errorf("process_name = %q, want %q", event.Details["process_name"], "sshd")
	}
	if event.Details["pid"] != "1234" {
		t.Errorf("pid = %q, want %q", event.Details["pid"], "1234")
	}
}

// ─── truncate ─────────────────────────────────────────────────────────────────

func TestTruncate(t *testing.T) {
	if truncate("hello", 10) != "hello" {
		t.Error("short string should not be truncated")
	}
	if truncate("hello world", 5) != "hello..." {
		t.Errorf("truncate = %q, want %q", truncate("hello world", 5), "hello...")
	}
	if truncate("", 5) != "" {
		t.Error("empty string should stay empty")
	}
}

// ─── NewSyslogServer ──────────────────────────────────────────────────────────

func TestNewSyslogServer(t *testing.T) {
	cfg := &core.SyslogConfig{
		Enabled:  true,
		Protocol: "udp",
		Host:     "127.0.0.1",
		Port:     1514,
	}
	s := NewSyslogServer(cfg, nil, zerolog.Nop())
	if s == nil {
		t.Fatal("expected non-nil SyslogServer")
	}
	if s.cfg != cfg {
		t.Error("cfg not stored correctly")
	}
}

func TestSyslogServer_StopWithoutStart(t *testing.T) {
	cfg := &core.SyslogConfig{
		Enabled:  true,
		Protocol: "udp",
		Host:     "127.0.0.1",
		Port:     1514,
	}
	s := NewSyslogServer(cfg, nil, zerolog.Nop())
	// Should not panic
	if err := s.Stop(); err != nil {
		t.Fatalf("Stop() without Start() should not error: %v", err)
	}
}

// ─── Regex patterns ───────────────────────────────────────────────────────────

func TestAuthFailureRegex(t *testing.T) {
	matches := []string{
		"Failed password for root",
		"authentication failure",
		"invalid user admin",
		"failed login attempt",
		"access denied for user",
		"bad password for admin",
		"account locked out",
	}
	for _, m := range matches {
		if !authFailureRe.MatchString(m) {
			t.Errorf("expected authFailureRe to match %q", m)
		}
	}
}

func TestAuthSuccessRegex(t *testing.T) {
	matches := []string{
		"Accepted password for admin",
		"Accepted publickey for root",
		"session opened for user admin",
		"successful login from 10.0.0.1",
	}
	for _, m := range matches {
		if !authSuccessRe.MatchString(m) {
			t.Errorf("expected authSuccessRe to match %q", m)
		}
	}
}

func TestFirewallRegex(t *testing.T) {
	matches := []string{
		"iptables DROP IN=eth0",
		"firewall blocked connection",
		"nftables rule matched",
		"ufw BLOCK",
		"connection refused from 1.2.3.4",
	}
	for _, m := range matches {
		if !firewallRe.MatchString(m) {
			t.Errorf("expected firewallRe to match %q", m)
		}
	}
}

func TestSyslogUsernameRegex(t *testing.T) {
	tests := []struct {
		input    string
		wantUser string
	}{
		{"for user admin from 1.2.3.4", "admin"},
		{"for invalid user hacker from 5.6.7.8", "hacker"},
		{"user=testuser action=login", "testuser"},
	}
	for _, tc := range tests {
		m := syslogUsernameRe.FindStringSubmatch(tc.input)
		if m == nil {
			t.Errorf("expected match for %q", tc.input)
			continue
		}
		if m[1] != tc.wantUser {
			t.Errorf("for %q: got user %q, want %q", tc.input, m[1], tc.wantUser)
		}
	}
}

func TestSyslogSrcIPRegex(t *testing.T) {
	tests := []struct {
		input  string
		wantIP string
	}{
		{"from 1.2.3.4 port 22", "1.2.3.4"},
		{"SRC=10.0.0.1 DST=10.0.0.2", "10.0.0.1"},
		{"source 192.168.1.1", "192.168.1.1"},
	}
	for _, tc := range tests {
		m := syslogSrcIPRe.FindStringSubmatch(tc.input)
		if m == nil {
			t.Errorf("expected match for %q", tc.input)
			continue
		}
		if m[1] != tc.wantIP {
			t.Errorf("for %q: got IP %q, want %q", tc.input, m[1], tc.wantIP)
		}
	}
}

// Suppress unused import
var _ = time.Now
