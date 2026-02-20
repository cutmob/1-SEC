package aicontainment

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/1sec-project/1sec/internal/core"
	"github.com/rs/zerolog"
)

// ─── Helpers ─────────────────────────────────────────────────────────────────

type capturingPipeline struct {
	pipeline *core.AlertPipeline
	mu       sync.Mutex
	alerts   []*core.Alert
}

func makeCapturingPipeline() *capturingPipeline {
	cp := &capturingPipeline{}
	cp.pipeline = core.NewAlertPipeline(zerolog.Nop(), 10000)
	cp.pipeline.AddHandler(func(a *core.Alert) {
		cp.mu.Lock()
		cp.alerts = append(cp.alerts, a)
		cp.mu.Unlock()
	})
	return cp
}

func (cp *capturingPipeline) count() int {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	return len(cp.alerts)
}

func startedModule(t *testing.T) *Containment {
	t.Helper()
	c := New()
	cfg := core.DefaultConfig()
	if err := c.Start(context.Background(), nil, nil, cfg); err != nil {
		t.Fatalf("Containment.Start() error: %v", err)
	}
	return c
}

func startedModuleWithPipeline(t *testing.T, cp *capturingPipeline) *Containment {
	t.Helper()
	c := New()
	cfg := core.DefaultConfig()
	if err := c.Start(context.Background(), nil, cp.pipeline, cfg); err != nil {
		t.Fatalf("Containment.Start() error: %v", err)
	}
	return c
}

// ─── Module Interface ─────────────────────────────────────────────────────────

func TestContainment_Name(t *testing.T) {
	c := New()
	if c.Name() != ModuleName {
		t.Errorf("Name() = %q, want %q", c.Name(), ModuleName)
	}
}

func TestContainment_Description(t *testing.T) {
	c := New()
	if c.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

func TestContainment_Start_Stop(t *testing.T) {
	c := New()
	cfg := core.DefaultConfig()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := c.Start(ctx, nil, nil, cfg); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	if c.policyEng == nil {
		t.Error("policyEng should be initialized after Start")
	}
	if c.shadowDet == nil {
		t.Error("shadowDet should be initialized after Start")
	}
	if c.agentTracker == nil {
		t.Error("agentTracker should be initialized after Start")
	}
	if err := c.Stop(); err != nil {
		t.Fatalf("Stop() error: %v", err)
	}
}

// ─── PolicyEngine ─────────────────────────────────────────────────────────────

func TestPolicyEngine_BlockedTools(t *testing.T) {
	pe := NewPolicyEngine()
	blocked := []string{
		"shell_exec", "system_command", "raw_sql", "file_delete",
		"network_scan", "credential_access", "registry_edit",
		"firewall_modify", "user_create",
	}
	for _, tool := range blocked {
		v := pe.Check("agent-1", "do-something", tool, "/tmp/safe")
		if v == nil {
			t.Errorf("Check() should block tool %q", tool)
			continue
		}
		if v.Severity != core.SeverityCritical {
			t.Errorf("blocked tool %q severity = %v, want Critical", tool, v.Severity)
		}
	}
}

func TestPolicyEngine_BlockedActions(t *testing.T) {
	pe := NewPolicyEngine()
	actions := []string{
		"delete database production",
		"DROP TABLE users",
		"rm -rf /",
		"format c:",
		"shutdown now",
		"reboot server",
		"disable firewall",
		"disable antivirus",
	}
	for _, action := range actions {
		v := pe.Check("agent-1", action, "safe_tool", "/tmp/safe")
		if v == nil {
			t.Errorf("Check() should block action %q", action)
			continue
		}
		if v.Severity != core.SeverityCritical {
			t.Errorf("blocked action %q severity = %v, want Critical", action, v.Severity)
		}
	}
}

func TestPolicyEngine_SensitiveTargets(t *testing.T) {
	pe := NewPolicyEngine()
	targets := []string{
		"/etc/shadow",
		"/home/user/.ssh/id_rsa",
		"/home/user/.aws/credentials",
		"/app/.env",
		"/deploy/secrets.yml",
		"/config/password_store",
		"/keys/private_key.pem",
	}
	for _, target := range targets {
		v := pe.Check("agent-1", "read", "safe_tool", target)
		if v == nil {
			t.Errorf("Check() should flag sensitive target %q", target)
			continue
		}
		if v.Severity != core.SeverityHigh {
			t.Errorf("sensitive target %q severity = %v, want High", target, v.Severity)
		}
	}
}

func TestPolicyEngine_AllowedActions(t *testing.T) {
	pe := NewPolicyEngine()
	cases := []struct {
		action string
		tool   string
		target string
	}{
		{"read file", "file_read", "/tmp/data.txt"},
		{"list directory", "dir_list", "/home/user/docs"},
		{"search logs", "log_search", "/var/log/app.log"},
		{"create report", "report_gen", "/reports/daily.pdf"},
	}
	for _, tc := range cases {
		v := pe.Check("agent-1", tc.action, tc.tool, tc.target)
		if v != nil {
			t.Errorf("Check() should allow action=%q tool=%q target=%q, got violation: %s",
				tc.action, tc.tool, tc.target, v.Reason)
		}
	}
}

// ─── ShadowAIDetector ─────────────────────────────────────────────────────────

func TestShadowAIDetector_KnownEndpoints(t *testing.T) {
	sd := NewShadowAIDetector()
	known := []string{
		"api.openai.com", "api.anthropic.com",
		"generativelanguage.googleapis.com",
		"api.cohere.ai", "api.mistral.ai",
		"api-inference.huggingface.co",
		"api.replicate.com", "api.together.xyz",
		"api.groq.com", "api.perplexity.ai",
		"api.deepseek.com",
	}
	for _, host := range known {
		if !sd.IsKnownAIEndpoint(host) {
			t.Errorf("IsKnownAIEndpoint(%q) = false, want true", host)
		}
	}
}

func TestShadowAIDetector_UnknownEndpoints(t *testing.T) {
	sd := NewShadowAIDetector()
	unknown := []string{
		"api.example.com",
		"google.com",
		"internal.corp.net",
		"",
	}
	for _, host := range unknown {
		if sd.IsKnownAIEndpoint(host) {
			t.Errorf("IsKnownAIEndpoint(%q) = true, want false", host)
		}
	}
}

func TestShadowAIDetector_RecordAPICall(t *testing.T) {
	sd := NewShadowAIDetector()
	sd.RecordAPICall("api.openai.com", "gpt-4", "10.0.0.1", "alice")
	sd.RecordAPICall("api.openai.com", "gpt-4", "10.0.0.1", "alice")
	sd.RecordAPICall("api.openai.com", "gpt-4", "10.0.0.1", "alice")

	val, ok := sd.apiCalls.Get("10.0.0.1")
	if !ok {
		t.Fatal("expected IP to be recorded in apiCalls cache")
	}
	if val != 3 {
		t.Errorf("apiCalls count = %d, want 3", val)
	}
}

// ─── AgentTracker ─────────────────────────────────────────────────────────────

func TestAgentTracker_RegisterAgent(t *testing.T) {
	at := NewAgentTracker()
	at.RegisterAgent("agent-1", "parent-0")

	profile, ok := at.agents.Get("agent-1")
	if !ok {
		t.Fatal("expected agent-1 to be registered")
	}
	if profile.ID != "agent-1" {
		t.Errorf("profile.ID = %q, want %q", profile.ID, "agent-1")
	}
	if profile.Parent != "parent-0" {
		t.Errorf("profile.Parent = %q, want %q", profile.Parent, "parent-0")
	}
}

func TestAgentTracker_RecordAction_NewAgent(t *testing.T) {
	at := NewAgentTracker()
	anomaly := at.RecordAction("new-agent", "read", "file_read", "/tmp/data")

	// First action for a new agent should not trigger any anomalies
	if anomaly.RapidActions {
		t.Error("first action should not trigger RapidActions")
	}
	if anomaly.NewToolUsage {
		t.Error("first action should not trigger NewToolUsage")
	}
	if anomaly.EscalatingScope {
		t.Error("first action should not trigger EscalatingScope")
	}
}

func TestAgentTracker_RecordAction_RapidActions(t *testing.T) {
	at := NewAgentTracker()
	at.RegisterAgent("agent-rapid", "parent")

	var lastAnomaly AgentAnomaly
	for i := 0; i < 105; i++ {
		lastAnomaly = at.RecordAction("agent-rapid", "read", "file_read", "/tmp/data")
	}

	if !lastAnomaly.RapidActions {
		t.Error("expected RapidActions after >100 actions in a minute")
	}
	if lastAnomaly.ActionCount <= 100 {
		t.Errorf("ActionCount = %d, want >100", lastAnomaly.ActionCount)
	}
}

func TestAgentTracker_RecordAction_NewToolUsage(t *testing.T) {
	at := NewAgentTracker()
	at.RegisterAgent("agent-tool", "parent")

	// Use a known tool
	at.RecordAction("agent-tool", "read", "file_read", "/tmp/data")

	// Manipulate CreatedAt to simulate baseline period elapsed
	profile, _ := at.agents.Get("agent-tool")
	profile.CreatedAt = time.Now().Add(-2 * time.Hour)

	// Use a new tool after baseline period
	anomaly := at.RecordAction("agent-tool", "write", "new_tool_xyz", "/tmp/out")
	if !anomaly.NewToolUsage {
		t.Error("expected NewToolUsage for a new tool after baseline period")
	}
}

func TestAgentTracker_RecordAction_EscalatingScope(t *testing.T) {
	at := NewAgentTracker()
	at.RegisterAgent("agent-esc", "parent")

	// Fill with some normal targets first
	at.RecordAction("agent-esc", "read", "tool", "/tmp/normal1")
	at.RecordAction("agent-esc", "read", "tool", "/tmp/normal2")

	// Now add sensitive targets (need 3+ in last 5)
	at.RecordAction("agent-esc", "read", "tool", "/etc/admin/config")
	at.RecordAction("agent-esc", "read", "tool", "/root/secrets")
	anomaly := at.RecordAction("agent-esc", "read", "tool", "/home/.ssh/keys")

	if !anomaly.EscalatingScope {
		t.Error("expected EscalatingScope with 3+ sensitive targets in last 5")
	}
}

// ─── HandleEvent Integration ──────────────────────────────────────────────────

func TestContainment_HandleEvent_AgentAction(t *testing.T) {
	cp := makeCapturingPipeline()
	c := startedModuleWithPipeline(t, cp)
	defer c.Stop()

	ev := core.NewSecurityEvent("test", "agent_action", core.SeverityInfo, "agent action")
	ev.Details["agent_id"] = "agent-1"
	ev.Details["action"] = "read file"
	ev.Details["tool"] = "shell_exec" // blocked tool
	ev.Details["target"] = "/tmp/data"
	ev.SourceIP = "10.0.0.1"

	if err := c.HandleEvent(ev); err != nil {
		t.Fatalf("HandleEvent() error: %v", err)
	}

	if cp.count() == 0 {
		t.Error("expected alert for blocked tool shell_exec")
	}
}

func TestContainment_HandleEvent_AIAPICall(t *testing.T) {
	cp := makeCapturingPipeline()
	c := startedModuleWithPipeline(t, cp)
	defer c.Stop()

	ev := core.NewSecurityEvent("test", "ai_api_call", core.SeverityInfo, "AI API call")
	ev.Details["endpoint"] = "api.openai.com"
	ev.Details["model"] = "gpt-4"
	ev.Details["user"] = "alice"
	ev.Details["authorized"] = "false"
	ev.SourceIP = "10.0.0.5"

	if err := c.HandleEvent(ev); err != nil {
		t.Fatalf("HandleEvent() error: %v", err)
	}

	if cp.count() == 0 {
		t.Error("expected alert for unauthorized AI API call")
	}
}

func TestContainment_HandleEvent_NetworkShadowAI(t *testing.T) {
	cp := makeCapturingPipeline()
	c := startedModuleWithPipeline(t, cp)
	defer c.Stop()

	ev := core.NewSecurityEvent("test", "network_request", core.SeverityInfo, "network request")
	ev.Details["dest_host"] = "api.openai.com"
	ev.Details["user"] = "bob"
	ev.SourceIP = "10.0.0.2"

	if err := c.HandleEvent(ev); err != nil {
		t.Fatalf("HandleEvent() error: %v", err)
	}

	if cp.count() == 0 {
		t.Error("expected alert for shadow AI endpoint detection")
	}
}

func TestContainment_HandleEvent_AgentSpawn(t *testing.T) {
	cp := makeCapturingPipeline()
	c := startedModuleWithPipeline(t, cp)
	defer c.Stop()

	ev := core.NewSecurityEvent("test", "agent_spawn", core.SeverityInfo, "agent spawned")
	ev.Details["agent_id"] = "child-agent-1"
	ev.Details["parent_agent"] = "parent-agent-0"
	ev.Details["capabilities"] = "file_read,file_write,network"
	ev.SourceIP = "10.0.0.3"

	if err := c.HandleEvent(ev); err != nil {
		t.Fatalf("HandleEvent() error: %v", err)
	}

	if cp.count() == 0 {
		t.Error("expected alert for agent spawn")
	}

	// Verify agent was registered
	profile, ok := c.agentTracker.agents.Get("child-agent-1")
	if !ok {
		t.Error("expected spawned agent to be registered in tracker")
	}
	if profile.Parent != "parent-agent-0" {
		t.Errorf("parent = %q, want %q", profile.Parent, "parent-agent-0")
	}
}

// Compile-time interface check
var _ core.Module = (*Containment)(nil)
