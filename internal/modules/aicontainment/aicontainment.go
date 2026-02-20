package aicontainment

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/1sec-project/1sec/internal/core"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/rs/zerolog"
)

const ModuleName = "ai_containment"

// Containment is the AI Agent Containment module providing action sandboxing,
// tool-use monitoring, autonomous behavior detection, and shadow AI detection.
type Containment struct {
	logger       zerolog.Logger
	bus          *core.EventBus
	pipeline     *core.AlertPipeline
	cfg          *core.Config
	ctx          context.Context
	cancel       context.CancelFunc
	policyEng    *PolicyEngine
	shadowDet    *ShadowAIDetector
	agentTracker *AgentTracker
}

func New() *Containment { return &Containment{} }

func (c *Containment) Name() string { return ModuleName }
func (c *Containment) Description() string {
	return "AI agent action sandboxing, tool-use monitoring, autonomous behavior detection, and shadow AI discovery"
}

func (c *Containment) Start(ctx context.Context, bus *core.EventBus, pipeline *core.AlertPipeline, cfg *core.Config) error {
	c.ctx, c.cancel = context.WithCancel(ctx)
	c.bus = bus
	c.pipeline = pipeline
	c.cfg = cfg
	c.logger = zerolog.New(zerolog.NewConsoleWriter()).With().Timestamp().Str("module", ModuleName).Logger()

	c.policyEng = NewPolicyEngine()
	c.shadowDet = NewShadowAIDetector()
	c.agentTracker = NewAgentTracker()

	c.logger.Info().Msg("AI agent containment started")
	return nil
}

func (c *Containment) Stop() error {
	if c.cancel != nil {
		c.cancel()
	}
	return nil
}

func (c *Containment) HandleEvent(event *core.SecurityEvent) error {
	switch event.Type {
	case "agent_action", "tool_call", "function_call":
		c.handleAgentAction(event)
	case "ai_api_call", "llm_api_call", "model_inference":
		c.handleAIAPICall(event)
	case "network_request":
		c.handleNetworkForShadowAI(event)
	case "agent_spawn", "agent_created":
		c.handleAgentSpawn(event)
	}
	return nil
}

func (c *Containment) handleAgentAction(event *core.SecurityEvent) {
	agentID := getStringDetail(event, "agent_id")
	action := getStringDetail(event, "action")
	tool := getStringDetail(event, "tool")
	target := getStringDetail(event, "target")

	if agentID == "" {
		agentID = "unknown"
	}

	// Policy enforcement
	violation := c.policyEng.Check(agentID, action, tool, target)
	if violation != nil {
		c.raiseAlert(event, violation.Severity,
			"AI Agent Policy Violation",
			fmt.Sprintf("Agent %s violated policy: %s. Action: %s, Tool: %s, Target: %s",
				agentID, violation.Reason, action, tool, target),
			"agent_policy_violation")
	}

	// Track agent behavior for anomaly detection
	anomaly := c.agentTracker.RecordAction(agentID, action, tool, target)

	if anomaly.RapidActions {
		c.raiseAlert(event, core.SeverityHigh,
			"AI Agent Rapid Action Burst",
			fmt.Sprintf("Agent %s performed %d actions in %s. This exceeds normal operating patterns.",
				agentID, anomaly.ActionCount, anomaly.Window.String()),
			"agent_rapid_actions")
	}

	if anomaly.NewToolUsage {
		c.raiseAlert(event, core.SeverityMedium,
			"AI Agent Using New Tool",
			fmt.Sprintf("Agent %s is using tool %q for the first time. Verify this is authorized.",
				agentID, tool),
			"agent_new_tool")
	}

	if anomaly.EscalatingScope {
		c.raiseAlert(event, core.SeverityHigh,
			"AI Agent Scope Escalation",
			fmt.Sprintf("Agent %s is accessing increasingly sensitive resources. Current target: %s",
				agentID, target),
			"agent_scope_escalation")
	}
}

func (c *Containment) handleAIAPICall(event *core.SecurityEvent) {
	endpoint := getStringDetail(event, "endpoint")
	model := getStringDetail(event, "model")
	user := getStringDetail(event, "user")
	authorized := getStringDetail(event, "authorized")

	// Shadow AI detection: unauthorized AI API calls
	if authorized == "false" || authorized == "no" {
		c.raiseAlert(event, core.SeverityHigh,
			"Unauthorized AI API Usage",
			fmt.Sprintf("Unauthorized AI API call to %s (model: %s) by user %s from IP %s",
				endpoint, model, user, event.SourceIP),
			"unauthorized_ai_api")
	}

	c.shadowDet.RecordAPICall(endpoint, model, event.SourceIP, user)
}

func (c *Containment) handleNetworkForShadowAI(event *core.SecurityEvent) {
	destHost := getStringDetail(event, "dest_host")
	if destHost == "" {
		destHost = event.DestIP
	}

	if c.shadowDet.IsKnownAIEndpoint(destHost) {
		user := getStringDetail(event, "user")
		c.raiseAlert(event, core.SeverityMedium,
			"Shadow AI Service Detected",
			fmt.Sprintf("Network traffic to known AI service %s detected from %s (user: %s). This may be unauthorized AI usage.",
				destHost, event.SourceIP, user),
			"shadow_ai_detected")
	}
}

func (c *Containment) handleAgentSpawn(event *core.SecurityEvent) {
	agentID := getStringDetail(event, "agent_id")
	parentAgent := getStringDetail(event, "parent_agent")
	capabilities := getStringDetail(event, "capabilities")

	c.raiseAlert(event, core.SeverityMedium,
		"New AI Agent Spawned",
		fmt.Sprintf("New AI agent %s spawned by %s with capabilities: %s. Monitoring initiated.",
			agentID, parentAgent, capabilities),
		"agent_spawned")

	c.agentTracker.RegisterAgent(agentID, parentAgent)
}

func (c *Containment) raiseAlert(event *core.SecurityEvent, severity core.Severity, title, description, alertType string) {
	newEvent := core.NewSecurityEvent(ModuleName, alertType, severity, description)
	newEvent.SourceIP = event.SourceIP
	newEvent.Details["original_event_id"] = event.ID

	if c.bus != nil {
		_ = c.bus.PublishEvent(newEvent)
	}

	alert := core.NewAlert(newEvent, title, description)
	alert.Mitigations = []string{
		"Review and restrict AI agent permissions",
		"Implement least-privilege policies for AI tool access",
		"Monitor and log all AI agent actions",
		"Require human approval for sensitive operations",
		"Maintain an inventory of authorized AI services",
	}
	if c.pipeline != nil {
		c.pipeline.Process(alert)
	}
}

// PolicyEngine enforces action policies for AI agents.
type PolicyEngine struct {
	mu               sync.RWMutex
	blockedTools     map[string]bool
	blockedActions   *regexp.Regexp
	sensitiveTargets *regexp.Regexp
}

type PolicyViolation struct {
	Reason   string
	Severity core.Severity
}

func NewPolicyEngine() *PolicyEngine {
	return &PolicyEngine{
		blockedTools: map[string]bool{
			"shell_exec": true, "system_command": true, "raw_sql": true,
			"file_delete": true, "network_scan": true, "credential_access": true,
			"registry_edit": true, "firewall_modify": true, "user_create": true,
		},
		blockedActions:   regexp.MustCompile(`(?i)(delete\s+database|drop\s+table|rm\s+-rf|format\s+c:|shutdown|reboot|disable\s+firewall|disable\s+antivirus)`),
		sensitiveTargets: regexp.MustCompile(`(?i)(/etc/shadow|/etc/passwd|\.ssh/|\.aws/credentials|\.env|secrets?\.ya?ml|password|private.?key)`),
	}
}

func (pe *PolicyEngine) Check(agentID, action, tool, target string) *PolicyViolation {
	pe.mu.RLock()
	defer pe.mu.RUnlock()

	if pe.blockedTools[strings.ToLower(tool)] {
		return &PolicyViolation{
			Reason:   fmt.Sprintf("tool %q is blocked by policy", tool),
			Severity: core.SeverityCritical,
		}
	}

	if pe.blockedActions.MatchString(action) {
		return &PolicyViolation{
			Reason:   "action matches blocked pattern",
			Severity: core.SeverityCritical,
		}
	}

	if pe.sensitiveTargets.MatchString(target) {
		return &PolicyViolation{
			Reason:   fmt.Sprintf("target %q is sensitive", target),
			Severity: core.SeverityHigh,
		}
	}

	return nil
}

// ShadowAIDetector identifies unauthorized AI service usage.
type ShadowAIDetector struct {
	mu           sync.RWMutex
	knownAIHosts map[string]bool
	apiCalls     *lru.Cache[string, int] // IP -> count
}

func NewShadowAIDetector() *ShadowAIDetector {
	aCache, _ := lru.New[string, int](50000)
	return &ShadowAIDetector{
		knownAIHosts: map[string]bool{
			"api.openai.com": true, "api.anthropic.com": true,
			"generativelanguage.googleapis.com": true,
			"api.cohere.ai":                     true, "api.mistral.ai": true,
			"api-inference.huggingface.co": true,
			"api.replicate.com":            true, "api.together.xyz": true,
			"api.groq.com": true, "api.perplexity.ai": true,
			"api.deepseek.com": true,
		},
		apiCalls: aCache,
	}
}

func (sd *ShadowAIDetector) IsKnownAIEndpoint(host string) bool {
	sd.mu.RLock()
	defer sd.mu.RUnlock()
	return sd.knownAIHosts[strings.ToLower(host)]
}

func (sd *ShadowAIDetector) RecordAPICall(endpoint, model, ip, user string) {
	sd.mu.Lock()
	defer sd.mu.Unlock()
	val, _ := sd.apiCalls.Get(ip)
	sd.apiCalls.Add(ip, val+1)
}

// AgentTracker monitors AI agent behavior over time.
type AgentTracker struct {
	mu     sync.RWMutex
	agents *lru.Cache[string, *agentProfile]
}

type agentProfile struct {
	ID          string
	Parent      string
	KnownTools  map[string]bool
	ActionCount int
	CountWindow time.Time
	Targets     []string
	LastSeen    time.Time
	CreatedAt   time.Time
}

type AgentAnomaly struct {
	RapidActions    bool
	NewToolUsage    bool
	EscalatingScope bool
	ActionCount     int
	Window          time.Duration
}

func NewAgentTracker() *AgentTracker {
	aCache, _ := lru.New[string, *agentProfile](50000)
	return &AgentTracker{agents: aCache}
}

func (at *AgentTracker) RegisterAgent(agentID, parentID string) {
	at.mu.Lock()
	defer at.mu.Unlock()
	at.agents.Add(agentID, &agentProfile{
		ID: agentID, Parent: parentID,
		KnownTools:  make(map[string]bool),
		CountWindow: time.Now(),
		CreatedAt:   time.Now(), LastSeen: time.Now(),
	})
}

func (at *AgentTracker) RecordAction(agentID, action, tool, target string) AgentAnomaly {
	at.mu.Lock()
	defer at.mu.Unlock()

	anomaly := AgentAnomaly{}
	now := time.Now()

	profile, exists := at.agents.Get(agentID)
	if !exists {
		profile = &agentProfile{
			ID: agentID, KnownTools: map[string]bool{tool: true},
			CountWindow: now, CreatedAt: now, LastSeen: now,
			ActionCount: 1,
		}
		at.agents.Add(agentID, profile)
		return anomaly
	}

	// Reset window
	if now.Sub(profile.CountWindow) > time.Minute {
		profile.ActionCount = 0
		profile.CountWindow = now
	}
	profile.ActionCount++
	profile.LastSeen = now
	anomaly.ActionCount = profile.ActionCount
	anomaly.Window = now.Sub(profile.CountWindow)

	// Rapid actions: more than 100 per minute
	if profile.ActionCount > 100 {
		anomaly.RapidActions = true
	}

	// New tool usage (after baseline period of 1 hour)
	if now.Sub(profile.CreatedAt) > time.Hour && tool != "" && !profile.KnownTools[tool] {
		anomaly.NewToolUsage = true
	}
	if tool != "" {
		profile.KnownTools[tool] = true
	}

	// Track target escalation: detect when an agent accesses increasingly
	// sensitive resources (e.g. moving from read-only to admin paths).
	if target != "" {
		profile.Targets = append(profile.Targets, target)
		if len(profile.Targets) > 100 {
			profile.Targets = profile.Targets[len(profile.Targets)-100:]
		}
		// Check if recent targets show escalating sensitivity
		if len(profile.Targets) >= 5 {
			recentSensitive := 0
			recent := profile.Targets[len(profile.Targets)-5:]
			for _, t := range recent {
				tLower := strings.ToLower(t)
				if strings.Contains(tLower, "admin") || strings.Contains(tLower, "root") ||
					strings.Contains(tLower, "secret") || strings.Contains(tLower, "credential") ||
					strings.Contains(tLower, "password") || strings.Contains(tLower, "/etc/") ||
					strings.Contains(tLower, ".ssh") || strings.Contains(tLower, "private") ||
					strings.Contains(tLower, "token") || strings.Contains(tLower, "key") {
					recentSensitive++
				}
			}
			if recentSensitive >= 3 {
				anomaly.EscalatingScope = true
			}
		}
	}

	return anomaly
}

// Cleanup handled by LRU

func getStringDetail(event *core.SecurityEvent, key string) string {
	if event.Details == nil {
		return ""
	}
	if val, ok := event.Details[key].(string); ok {
		return val
	}
	return ""
}
