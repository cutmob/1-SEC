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
// tool-use monitoring, autonomous behavior detection, shadow AI detection,
// MCP tool poisoning detection, goal hijacking detection, memory poisoning
// detection, cascading failure monitoring, and rogue agent detection.
//
// Aligned with OWASP Agentic AI Top 10 (2025-2026):
//   ASI01 - Agent Goal Hijack
//   ASI02 - Tool Misuse
//   ASI03 - Identity Abuse (via privilege escalation tracking)
//   ASI04 - Supply Chain Vulnerabilities (MCP rug pulls)
//   ASI06 - Memory Poisoning
//   ASI08 - Cascading Failures
//   ASI10 - Rogue Agents
type Containment struct {
	logger         zerolog.Logger
	bus            *core.EventBus
	pipeline       *core.AlertPipeline
	cfg            *core.Config
	ctx            context.Context
	cancel         context.CancelFunc
	policyEng      *PolicyEngine
	shadowDet      *ShadowAIDetector
	agentTracker   *AgentTracker
	toolIntegrity  *ToolIntegrityMonitor
	goalMonitor    *GoalHijackMonitor
	memoryMonitor  *MemoryPoisonMonitor
	cascadeMonitor *CascadeFailureMonitor
}

func New() *Containment { return &Containment{} }

func (c *Containment) Name() string { return ModuleName }
func (c *Containment) EventTypes() []string {
	return []string{
		"agent_action", "tool_call", "function_call",
		"ai_api_call", "llm_api_call", "model_inference",
		"network_request", "network_connection",
		"agent_spawn", "agent_created",
		"tool_register", "tool_update", "mcp_tool_list",
		"agent_goal", "agent_plan", "agent_decision",
		"agent_memory_write", "context_update", "rag_inject",
		"agent_error", "agent_timeout", "agent_retry",
		"agent_impersonation", "approval_bypass",
	}
}
func (c *Containment) Description() string {
	return "AI agent containment: action sandboxing, tool-use monitoring, MCP tool poisoning detection, goal hijacking detection, memory poisoning detection, cascading failure monitoring, shadow AI discovery, and rogue agent detection (OWASP Agentic AI Top 10)"
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
	c.toolIntegrity = NewToolIntegrityMonitor()
	c.goalMonitor = NewGoalHijackMonitor()
	c.memoryMonitor = NewMemoryPoisonMonitor()
	c.cascadeMonitor = NewCascadeFailureMonitor()

	c.logger.Info().Msg("AI agent containment started (OWASP Agentic AI Top 10)")
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
	case "tool_register", "tool_update", "mcp_tool_list":
		c.handleToolIntegrity(event)
	case "agent_goal", "agent_plan", "agent_decision":
		c.handleGoalMonitoring(event)
	case "agent_memory_write", "context_update", "rag_inject":
		c.handleMemoryPoisoning(event)
	case "agent_error", "agent_timeout", "agent_retry":
		c.handleCascadeFailure(event)
	case "agent_impersonation", "approval_bypass":
		c.handleTrustExploitation(event)
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

	if anomaly.RogueLoop {
		c.raiseAlert(event, core.SeverityCritical,
			"Rogue Agent: Repetitive Loop Detected (ASI10)",
			fmt.Sprintf("Agent %s is repeating the same action %q on target %q %d times. "+
				"This indicates misaligned autonomous behavior or a stuck agent.",
				agentID, action, target, anomaly.LoopCount),
			"rogue_agent_loop")
	}
}

func (c *Containment) handleAIAPICall(event *core.SecurityEvent) {
	endpoint := getStringDetail(event, "endpoint")
	model := getStringDetail(event, "model")
	user := getStringDetail(event, "user")
	authorized := getStringDetail(event, "authorized")

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

	// Check spawn depth — deep nesting is a rogue agent indicator (ASI10)
	depth := c.agentTracker.GetSpawnDepth(agentID, parentAgent)
	severity := core.SeverityMedium
	if depth > 3 {
		severity = core.SeverityHigh
	}

	c.raiseAlert(event, severity,
		"New AI Agent Spawned",
		fmt.Sprintf("New AI agent %s spawned by %s with capabilities: %s (depth: %d). Monitoring initiated.",
			agentID, parentAgent, capabilities, depth),
		"agent_spawned")

	c.agentTracker.RegisterAgent(agentID, parentAgent)
}

// handleToolIntegrity detects MCP tool poisoning, rug pulls, and shadowing (ASI04).
// Ref: Invariant Labs April 2025, arxiv.org/html/2512.06556v1
func (c *Containment) handleToolIntegrity(event *core.SecurityEvent) {
	toolName := getStringDetail(event, "tool_name")
	description := getStringDetail(event, "description")
	serverName := getStringDetail(event, "server_name")
	hash := getStringDetail(event, "description_hash")

	if toolName == "" {
		return
	}

	result := c.toolIntegrity.Analyze(toolName, description, serverName, hash)

	if result.Poisoned {
		c.raiseAlert(event, core.SeverityCritical,
			"MCP Tool Poisoning Detected (ASI04)",
			fmt.Sprintf("Tool %q from server %q contains hidden instructions in its description: %s. "+
				"This is a tool poisoning attack where malicious prompts are embedded in tool metadata. "+
				"Ref: Invariant Labs 2025.",
				toolName, serverName, result.Reason),
			"mcp_tool_poisoning")
	}

	if result.RugPull {
		c.raiseAlert(event, core.SeverityCritical,
			"MCP Tool Rug Pull Detected (ASI04)",
			fmt.Sprintf("Tool %q from server %q changed its description after initial approval. "+
				"Previous hash: %s, new hash: %s. The tool may have been silently redefined "+
				"to perform malicious actions.",
				toolName, serverName, result.PreviousHash, hash),
			"mcp_rug_pull")
	}

	if result.Shadowing {
		c.raiseAlert(event, core.SeverityHigh,
			"MCP Tool Shadowing Detected (ASI04)",
			fmt.Sprintf("Tool %q from server %q shadows an existing tool %q. "+
				"Cross-server tool shadowing can redirect agent actions to malicious implementations.",
				toolName, serverName, result.ShadowedTool),
			"mcp_tool_shadowing")
	}
}

// handleGoalMonitoring detects agent goal hijacking (ASI01).
func (c *Containment) handleGoalMonitoring(event *core.SecurityEvent) {
	agentID := getStringDetail(event, "agent_id")
	goal := getStringDetail(event, "goal")
	plan := getStringDetail(event, "plan")
	decision := getStringDetail(event, "decision")
	source := getStringDetail(event, "source")

	if agentID == "" {
		agentID = "unknown"
	}

	content := goal + " " + plan + " " + decision
	result := c.goalMonitor.Analyze(agentID, content, source)

	if result.GoalDivergence {
		c.raiseAlert(event, core.SeverityCritical,
			"Agent Goal Hijack Detected (ASI01)",
			fmt.Sprintf("Agent %s goal has diverged from its original objective. "+
				"Original intent: %s. Current: %s. Source of change: %s. "+
				"Attackers may have embedded malicious instructions in processed content.",
				agentID, truncate(result.OriginalGoal, 100), truncate(content, 100), source),
			"goal_hijack")
	}

	if result.ExternalInfluence {
		c.raiseAlert(event, core.SeverityHigh,
			"Agent Goal Influenced by External Content (ASI01)",
			fmt.Sprintf("Agent %s goal/plan changed after processing external content from %q. "+
				"This may indicate indirect prompt injection via documents, emails, or web pages.",
				agentID, source),
			"goal_external_influence")
	}
}

// handleMemoryPoisoning detects persistent context manipulation (ASI06).
func (c *Containment) handleMemoryPoisoning(event *core.SecurityEvent) {
	agentID := getStringDetail(event, "agent_id")
	content := getStringDetail(event, "content")
	memoryType := getStringDetail(event, "memory_type")
	source := getStringDetail(event, "source")

	if content == "" {
		content = event.Summary
	}

	result := c.memoryMonitor.Analyze(agentID, content, memoryType, source)

	if result.InstructionInjection {
		c.raiseAlert(event, core.SeverityCritical,
			"Memory Poisoning: Instruction Injection (ASI06)",
			fmt.Sprintf("Agent %s memory write contains embedded instructions: %s. "+
				"Memory type: %s, source: %s. Attackers inject persistent instructions "+
				"into agent memory to manipulate future behavior across sessions.",
				agentID, truncate(result.Reason, 150), memoryType, source),
			"memory_instruction_injection")
	}

	if result.ContextOverflow {
		c.raiseAlert(event, core.SeverityHigh,
			"Memory Poisoning: Context Overflow (ASI06)",
			fmt.Sprintf("Agent %s receiving excessive memory writes (%d in %s). "+
				"This may be an attempt to flood context and push out safety instructions.",
				agentID, result.WriteCount, result.Window),
			"memory_context_overflow")
	}

	if result.CrossSessionLeak {
		c.raiseAlert(event, core.SeverityHigh,
			"Memory Poisoning: Cross-Session Contamination (ASI06)",
			fmt.Sprintf("Agent %s memory contains content from a different session/user. "+
				"Source: %s. Persistent memory can carry poisoned context across sessions.",
				agentID, source),
			"memory_cross_session")
	}
}

// handleCascadeFailure detects multi-agent failure propagation (ASI08).
func (c *Containment) handleCascadeFailure(event *core.SecurityEvent) {
	agentID := getStringDetail(event, "agent_id")
	errorType := getStringDetail(event, "error_type")
	targetAgent := getStringDetail(event, "target_agent")

	if agentID == "" {
		agentID = "unknown"
	}

	result := c.cascadeMonitor.Record(agentID, errorType, targetAgent)

	if result.CascadeDetected {
		c.raiseAlert(event, core.SeverityCritical,
			"Cascading Agent Failure Detected (ASI08)",
			fmt.Sprintf("Cascade failure across %d agents in %s. "+
				"Origin: %s, error: %s. Affected agents: %s. "+
				"A single-point failure is propagating through the agent network.",
				result.AffectedAgents, result.Window,
				agentID, errorType, strings.Join(result.AgentChain, " -> ")),
			"cascade_failure")
	}

	if result.RetryStorm {
		c.raiseAlert(event, core.SeverityHigh,
			"Agent Retry Storm Detected (ASI08)",
			fmt.Sprintf("Agent %s has retried %d times in %s for error %q. "+
				"Excessive retries can exhaust resources and amplify failures.",
				agentID, result.RetryCount, result.Window, errorType),
			"agent_retry_storm")
	}
}

// handleTrustExploitation detects human-agent trust boundary violations.
func (c *Containment) handleTrustExploitation(event *core.SecurityEvent) {
	agentID := getStringDetail(event, "agent_id")
	action := getStringDetail(event, "action")
	impersonatedUser := getStringDetail(event, "impersonated_user")
	approvalRequired := getStringDetail(event, "approval_required")

	if event.Type == "agent_impersonation" {
		c.raiseAlert(event, core.SeverityCritical,
			"Agent Impersonating Human User",
			fmt.Sprintf("Agent %s is impersonating user %q to perform action %q. "+
				"AI agents must not assume human identities to bypass access controls.",
				agentID, impersonatedUser, action),
			"agent_impersonation")
	}

	if event.Type == "approval_bypass" && (approvalRequired == "true" || approvalRequired == "yes") {
		c.raiseAlert(event, core.SeverityCritical,
			"Agent Bypassed Human Approval Gate",
			fmt.Sprintf("Agent %s performed action %q that requires human approval without obtaining it. "+
				"Human-in-the-loop controls must not be circumventable by agents.",
				agentID, action),
			"approval_bypass")
	}
}

func (c *Containment) raiseAlert(event *core.SecurityEvent, severity core.Severity, title, description, alertType string) {
	newEvent := core.NewSecurityEvent(ModuleName, alertType, severity, description)
	newEvent.SourceIP = event.SourceIP
	newEvent.Details["original_event_id"] = event.ID

	if c.bus != nil {
		_ = c.bus.PublishEvent(newEvent)
	}

	alert := core.NewAlert(newEvent, title, description)
	alert.Mitigations = getContainmentMitigations(alertType)
	if c.pipeline != nil {
		c.pipeline.Process(alert)
	}
}

// getContainmentMitigations returns contextual mitigations per alert type.
func getContainmentMitigations(alertType string) []string {
	switch alertType {
	case "agent_policy_violation":
		return []string{
			"Review and tighten agent tool-use policies",
			"Implement allowlist-based tool access instead of blocklist",
			"Require human approval for tools outside the agent's designated scope",
		}
	case "agent_rapid_actions":
		return []string{
			"Implement per-agent rate limiting on action frequency",
			"Add circuit breakers that pause agents exceeding action thresholds",
			"Review agent task to determine if rapid actions are expected",
		}
	case "agent_new_tool", "agent_scope_escalation":
		return []string{
			"Enforce least-privilege tool access per agent role",
			"Require re-authorization when agents access new tools after baseline",
			"Monitor agent tool usage patterns for drift from expected behavior",
		}
	case "rogue_agent_loop":
		return []string{
			"Implement loop detection with automatic agent suspension",
			"Add maximum iteration limits to agent task execution",
			"Deploy kill switches for autonomous agents (OWASP ASI10)",
			"Review agent goal specification for ambiguity that causes loops",
		}
	case "unauthorized_ai_api", "shadow_ai_detected":
		return []string{
			"Maintain an inventory of authorized AI services and endpoints",
			"Block unauthorized AI API traffic at the network level",
			"Implement AI service discovery scanning on a regular cadence",
			"Require AI usage registration and approval workflows",
		}
	case "agent_spawned":
		return []string{
			"Limit agent spawn depth to prevent uncontrolled proliferation",
			"Require parent agent authorization for child agent creation",
			"Enforce capability inheritance limits on spawned agents",
		}
	case "mcp_tool_poisoning":
		return []string{
			"Treat tool descriptions as untrusted input — scan for hidden instructions",
			"Pin tool descriptions by hash and alert on changes",
			"Use an MCP gateway to sanitize tool metadata before agent consumption",
			"Audit all MCP server tool descriptions for embedded prompt injections",
		}
	case "mcp_rug_pull":
		return []string{
			"Pin tool description hashes at approval time and reject changes",
			"Implement tool version control with mandatory re-approval on updates",
			"Monitor MCP tool list responses for description mutations",
			"Use signed tool manifests to prevent post-approval tampering",
		}
	case "mcp_tool_shadowing":
		return []string{
			"Enforce unique tool names across all connected MCP servers",
			"Implement tool namespace isolation per MCP server",
			"Alert when new tools share names with existing trusted tools",
			"Use an MCP gateway to deduplicate and prioritize trusted tool sources",
		}
	case "goal_hijack", "goal_external_influence":
		return []string{
			"Isolate agent goal/plan state from user-supplied content",
			"Implement goal integrity checks that compare current objectives to original",
			"Sanitize external content (documents, emails, web pages) before agent processing",
			"Use separate channels for system instructions and user/external data",
		}
	case "memory_instruction_injection":
		return []string{
			"Scan memory writes for instruction-like patterns before persistence",
			"Implement memory content policies that reject embedded directives",
			"Use structured memory formats that separate data from instructions",
			"Audit persistent agent memory regularly for injected content",
		}
	case "memory_context_overflow":
		return []string{
			"Rate-limit memory writes per agent per time window",
			"Implement memory size quotas with oldest-first eviction",
			"Monitor for patterns that push safety instructions out of context",
		}
	case "memory_cross_session":
		return []string{
			"Enforce session isolation for agent memory stores",
			"Tag memory entries with session/user provenance and validate on read",
			"Clear agent memory between sessions for sensitive operations",
		}
	case "cascade_failure":
		return []string{
			"Implement circuit breakers between agent-to-agent communications",
			"Deploy bulkhead isolation to contain failures to individual agents",
			"Add health checks and automatic agent suspension on repeated failures",
			"Design agent networks with graceful degradation paths",
		}
	case "agent_retry_storm":
		return []string{
			"Implement exponential backoff with jitter for agent retries",
			"Set maximum retry counts per operation type",
			"Add circuit breakers that open after consecutive failures",
		}
	case "agent_impersonation", "approval_bypass":
		return []string{
			"Enforce distinct non-human identities for all AI agents",
			"Implement cryptographic attestation for human-in-the-loop approvals",
			"Audit all agent actions that cross human-agent trust boundaries",
			"Agents must never assume human credentials or session tokens",
		}
	default:
		return []string{
			"Review and restrict AI agent permissions",
			"Implement least-privilege policies for AI tool access",
			"Monitor and log all AI agent actions",
			"Require human approval for sensitive operations",
		}
	}
}

// ============================================================================
// PolicyEngine — enforces action policies for AI agents (ASI02)
// ============================================================================

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

// ============================================================================
// ShadowAIDetector — identifies unauthorized AI service usage
// ============================================================================

type ShadowAIDetector struct {
	mu           sync.RWMutex
	knownAIHosts map[string]bool
	apiCalls     *lru.Cache[string, int]
}

func NewShadowAIDetector() *ShadowAIDetector {
	aCache, _ := lru.New[string, int](50000)
	return &ShadowAIDetector{
		knownAIHosts: map[string]bool{
			// Major LLM providers
			"api.openai.com": true, "api.anthropic.com": true,
			"generativelanguage.googleapis.com": true,
			"api.cohere.ai": true, "api.mistral.ai": true,
			"api-inference.huggingface.co": true,
			"api.replicate.com": true, "api.together.xyz": true,
			"api.groq.com": true, "api.perplexity.ai": true,
			"api.deepseek.com": true,
			// 2025-2026 additions
			"api.x.ai": true, "api.grok.x.ai": true,
			"api.meta.ai": true, "llama-api.meta.com": true,
			"api.fireworks.ai": true, "api.anyscale.com": true,
			"api.cerebras.ai": true, "api.sambanova.ai": true,
			"api.lepton.ai": true, "api.modal.com": true,
			"api.baseten.co": true, "api.runpod.ai": true,
			"api.deepinfra.com": true, "api.octo.ai": true,
			"api.aleph-alpha.com": true, "api.ai21.com": true,
			"api.writer.com": true, "api.cohere.com": true,
			"bedrock-runtime.amazonaws.com": true,
			"aiplatform.googleapis.com":     true,
			// Chinese AI providers
			"api.moonshot.cn": true, "api.zhipuai.cn": true,
			"dashscope.aliyuncs.com": true, "api.baichuan-ai.com": true,
			"api.minimax.chat": true,
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

// ============================================================================
// AgentTracker — monitors AI agent behavior over time (ASI10 rogue agents)
// ============================================================================

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
	// Rogue loop detection
	LastAction string
	LastTarget string
	RepeatCount int
}

type AgentAnomaly struct {
	RapidActions    bool
	NewToolUsage    bool
	EscalatingScope bool
	RogueLoop       bool
	ActionCount     int
	LoopCount       int
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

// GetSpawnDepth returns how deep in the spawn chain this agent is.
func (at *AgentTracker) GetSpawnDepth(agentID, parentID string) int {
	at.mu.RLock()
	defer at.mu.RUnlock()

	depth := 1
	current := parentID
	seen := map[string]bool{agentID: true}
	for depth < 20 { // cap to prevent infinite loops
		if current == "" {
			break
		}
		if seen[current] {
			break // cycle detected
		}
		seen[current] = true
		profile, exists := at.agents.Get(current)
		if !exists {
			break
		}
		depth++
		current = profile.Parent
	}
	return depth
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

	// Rogue loop detection (ASI10): same action+target repeated many times
	actionTarget := action + "|" + target
	if actionTarget == profile.LastAction+"|"+profile.LastTarget && action != "" {
		profile.RepeatCount++
	} else {
		profile.RepeatCount = 1
	}
	profile.LastAction = action
	profile.LastTarget = target
	if profile.RepeatCount >= 10 {
		anomaly.RogueLoop = true
		anomaly.LoopCount = profile.RepeatCount
	}

	// Track target escalation
	if target != "" {
		profile.Targets = append(profile.Targets, target)
		if len(profile.Targets) > 100 {
			profile.Targets = profile.Targets[len(profile.Targets)-100:]
		}
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

// ============================================================================
// ToolIntegrityMonitor — MCP tool poisoning, rug pulls, shadowing (ASI04)
// ============================================================================

// ToolIntegrityMonitor detects three classes of MCP tool attacks:
//   1. Tool Poisoning: hidden adversarial instructions in tool descriptions
//   2. Rug Pulls: post-approval description mutations
//   3. Shadowing: cross-server tool name collisions that redirect agent actions
//
// Ref: arxiv.org/html/2512.06556v1, Invariant Labs April 2025
type ToolIntegrityMonitor struct {
	mu              sync.RWMutex
	knownTools      *lru.Cache[string, *toolRecord]
	poisonPatterns  []*regexp.Regexp
}

type toolRecord struct {
	Name            string
	Server          string
	DescriptionHash string
	FirstSeen       time.Time
}

type ToolIntegrityResult struct {
	Poisoned     bool
	RugPull      bool
	Shadowing    bool
	Reason       string
	PreviousHash string
	ShadowedTool string
}

func NewToolIntegrityMonitor() *ToolIntegrityMonitor {
	tCache, _ := lru.New[string, *toolRecord](10000)
	return &ToolIntegrityMonitor{
		knownTools: tCache,
		poisonPatterns: []*regexp.Regexp{
			// Hidden instructions embedded in tool descriptions
			regexp.MustCompile(`(?i)(ignore\s+(previous|prior|all)\s+instructions?|override\s+safety|bypass\s+restrictions?)`),
			regexp.MustCompile(`(?i)(before\s+running\s+this\s+tool|first\s+read|also\s+send|additionally\s+exfiltrate|silently\s+include)`),
			regexp.MustCompile(`(?i)(do\s+not\s+show\s+the\s+user|hide\s+this\s+from|invisible\s+to\s+the\s+user|user\s+should\s+not\s+see)`),
			regexp.MustCompile(`(?i)(send\s+(to|data\s+to)|upload\s+to|exfiltrate|forward\s+to)\s+https?://`),
			regexp.MustCompile(`(?i)(read|access|include|attach)\s+(the\s+)?(ssh|credentials?|private\s+key|\.env|secrets?|password|api.?key|token)`),
			regexp.MustCompile(`(?i)<(IMPORTANT|SYSTEM|HIDDEN|SECRET|ADMIN)>`),
			// Rug pull setup: instructions that only activate later
			regexp.MustCompile(`(?i)(after\s+\d+\s+(calls?|uses?|invocations?)|on\s+(the\s+)?(second|third|next)\s+(call|use|run))`),
		},
	}
}

func (tm *ToolIntegrityMonitor) Analyze(toolName, description, serverName, hash string) ToolIntegrityResult {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	result := ToolIntegrityResult{}

	// Check for poisoned descriptions
	for _, pattern := range tm.poisonPatterns {
		if pattern.MatchString(description) {
			result.Poisoned = true
			result.Reason = pattern.FindString(description)
			break
		}
	}

	// Check for rug pulls (description changed after initial registration)
	key := serverName + "::" + toolName
	existing, exists := tm.knownTools.Get(key)
	if exists && hash != "" && existing.DescriptionHash != "" && existing.DescriptionHash != hash {
		result.RugPull = true
		result.PreviousHash = existing.DescriptionHash
	}

	// Check for shadowing (same tool name from different server)
	if !exists {
		// Check if any other server has a tool with the same name
		keys := tm.knownTools.Keys()
		for _, k := range keys {
			rec, ok := tm.knownTools.Get(k)
			if ok && rec.Name == toolName && rec.Server != serverName {
				result.Shadowing = true
				result.ShadowedTool = rec.Server + "::" + rec.Name
				break
			}
		}
	}

	// Record or update
	tm.knownTools.Add(key, &toolRecord{
		Name:            toolName,
		Server:          serverName,
		DescriptionHash: hash,
		FirstSeen:       time.Now(),
	})

	return result
}

// ============================================================================
// GoalHijackMonitor — detects agent goal divergence (ASI01)
// ============================================================================

type GoalHijackMonitor struct {
	mu     sync.RWMutex
	agents *lru.Cache[string, *goalState]
	// Patterns that indicate external content is trying to redirect agent goals
	redirectPatterns []*regexp.Regexp
}

type goalState struct {
	OriginalGoal string
	GoalHistory  []goalEntry
	LastSource   string
}

type goalEntry struct {
	Content   string
	Source    string
	Timestamp time.Time
}

type GoalHijackResult struct {
	GoalDivergence    bool
	ExternalInfluence bool
	OriginalGoal      string
}

func NewGoalHijackMonitor() *GoalHijackMonitor {
	gCache, _ := lru.New[string, *goalState](50000)
	return &GoalHijackMonitor{
		agents: gCache,
		redirectPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)(new\s+objective|change\s+(your\s+)?goal|your\s+(real|actual|true)\s+(goal|task|objective))`),
			regexp.MustCompile(`(?i)(instead\s+of|rather\s+than|forget\s+(about\s+)?the\s+(original|previous)|abandon\s+(the\s+)?(current|original))`),
			regexp.MustCompile(`(?i)(priority\s+override|urgent\s+new\s+task|critical\s+redirect|emergency\s+instruction)`),
			regexp.MustCompile(`(?i)(the\s+user\s+(actually|really)\s+wants|what\s+they\s+meant\s+was|the\s+real\s+request\s+is)`),
		},
	}
}

func (gm *GoalHijackMonitor) Analyze(agentID, content, source string) GoalHijackResult {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	result := GoalHijackResult{}
	now := time.Now()

	state, exists := gm.agents.Get(agentID)
	if !exists {
		state = &goalState{OriginalGoal: content, LastSource: source}
		state.GoalHistory = append(state.GoalHistory, goalEntry{Content: content, Source: source, Timestamp: now})
		gm.agents.Add(agentID, state)
		return result
	}

	state.GoalHistory = append(state.GoalHistory, goalEntry{Content: content, Source: source, Timestamp: now})
	if len(state.GoalHistory) > 50 {
		state.GoalHistory = state.GoalHistory[len(state.GoalHistory)-50:]
	}

	// Check for redirect patterns in content
	for _, pattern := range gm.redirectPatterns {
		if pattern.MatchString(content) {
			result.GoalDivergence = true
			result.OriginalGoal = state.OriginalGoal
			break
		}
	}

	// Check for external influence: goal changed after processing external content
	externalSources := []string{"email", "document", "web", "pdf", "attachment", "calendar", "file", "rag", "retrieval"}
	sourceLower := strings.ToLower(source)
	for _, ext := range externalSources {
		if strings.Contains(sourceLower, ext) {
			// If the content contains instruction-like patterns, flag it
			for _, pattern := range gm.redirectPatterns {
				if pattern.MatchString(content) {
					result.ExternalInfluence = true
					break
				}
			}
			break
		}
	}

	state.LastSource = source
	return result
}

// ============================================================================
// MemoryPoisonMonitor — detects persistent context manipulation (ASI06)
// ============================================================================

type MemoryPoisonMonitor struct {
	mu               sync.RWMutex
	agents           *lru.Cache[string, *memoryState]
	instructionPats  []*regexp.Regexp
}

type memoryState struct {
	WriteCount  int
	WriteWindow time.Time
	Sources     map[string]bool
	LastSession string
}

type MemoryPoisonResult struct {
	InstructionInjection bool
	ContextOverflow      bool
	CrossSessionLeak     bool
	Reason               string
	WriteCount           int
	Window               string
}

func NewMemoryPoisonMonitor() *MemoryPoisonMonitor {
	mCache, _ := lru.New[string, *memoryState](50000)
	return &MemoryPoisonMonitor{
		agents: mCache,
		instructionPats: []*regexp.Regexp{
			regexp.MustCompile(`(?i)(always|never|must|shall)\s+(respond|answer|act|behave|do|say|output)`),
			regexp.MustCompile(`(?i)(from\s+now\s+on|going\s+forward|henceforth|in\s+all\s+future)`),
			regexp.MustCompile(`(?i)(ignore|disregard|override|bypass)\s+(all\s+)?(previous|prior|safety|security)`),
			regexp.MustCompile(`(?i)(your\s+(new\s+)?(role|identity|persona|instructions?)\s+(is|are))`),
			regexp.MustCompile(`(?i)(remember\s+this|store\s+this|keep\s+this\s+in\s+mind).*?(ignore|override|bypass|disregard)`),
			regexp.MustCompile(`(?i)(when\s+(anyone|someone|the\s+user)\s+asks?\s+about).*?(say|respond|tell|answer)`),
		},
	}
}

func (mm *MemoryPoisonMonitor) Analyze(agentID, content, memoryType, source string) MemoryPoisonResult {
	mm.mu.Lock()
	defer mm.mu.Unlock()

	result := MemoryPoisonResult{}
	now := time.Now()

	state, exists := mm.agents.Get(agentID)
	if !exists {
		state = &memoryState{
			WriteWindow: now,
			Sources:     map[string]bool{source: true},
			LastSession: getSessionFromSource(source),
		}
		mm.agents.Add(agentID, state)
	}

	// Reset window
	if now.Sub(state.WriteWindow) > 10*time.Minute {
		state.WriteCount = 0
		state.WriteWindow = now
	}
	state.WriteCount++
	result.WriteCount = state.WriteCount
	result.Window = now.Sub(state.WriteWindow).Round(time.Second).String()

	// Check for instruction injection in memory content
	for _, pattern := range mm.instructionPats {
		if pattern.MatchString(content) {
			result.InstructionInjection = true
			result.Reason = truncate(pattern.FindString(content), 100)
			break
		}
	}

	// Context overflow: too many writes in a short window
	if state.WriteCount > 50 {
		result.ContextOverflow = true
	}

	// Cross-session contamination
	currentSession := getSessionFromSource(source)
	if currentSession != "" && state.LastSession != "" && currentSession != state.LastSession {
		if memoryType == "persistent" || memoryType == "long_term" {
			result.CrossSessionLeak = true
		}
	}
	if currentSession != "" {
		state.LastSession = currentSession
	}
	if source != "" {
		state.Sources[source] = true
	}

	return result
}

func getSessionFromSource(source string) string {
	// Extract session identifier from source string if present
	parts := strings.Split(source, ":")
	if len(parts) >= 2 {
		return parts[0]
	}
	return source
}

// ============================================================================
// CascadeFailureMonitor — detects multi-agent failure propagation (ASI08)
// ============================================================================

type CascadeFailureMonitor struct {
	mu     sync.RWMutex
	errors *lru.Cache[string, *agentErrorState]
}

type agentErrorState struct {
	ErrorCount  int
	RetryCount  int
	Window      time.Time
	ErrorTypes  map[string]int
	DownstreamAgents []string
}

type CascadeResult struct {
	CascadeDetected bool
	RetryStorm      bool
	AffectedAgents  int
	RetryCount      int
	Window          string
	AgentChain      []string
}

func NewCascadeFailureMonitor() *CascadeFailureMonitor {
	eCache, _ := lru.New[string, *agentErrorState](50000)
	return &CascadeFailureMonitor{errors: eCache}
}

func (cm *CascadeFailureMonitor) Record(agentID, errorType, targetAgent string) CascadeResult {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	result := CascadeResult{}
	now := time.Now()

	state, exists := cm.errors.Get(agentID)
	if !exists || now.Sub(state.Window) > 5*time.Minute {
		state = &agentErrorState{
			Window:     now,
			ErrorTypes: make(map[string]int),
		}
		cm.errors.Add(agentID, state)
	}

	state.ErrorCount++
	state.ErrorTypes[errorType]++
	result.Window = now.Sub(state.Window).Round(time.Second).String()

	// Track retry storms
	if errorType == "retry" || strings.Contains(strings.ToLower(errorType), "retry") {
		state.RetryCount++
		result.RetryCount = state.RetryCount
		if state.RetryCount > 20 {
			result.RetryStorm = true
		}
	}

	// Track downstream agent failures for cascade detection
	if targetAgent != "" {
		found := false
		for _, a := range state.DownstreamAgents {
			if a == targetAgent {
				found = true
				break
			}
		}
		if !found {
			state.DownstreamAgents = append(state.DownstreamAgents, targetAgent)
		}
	}

	// Cascade detection: errors propagating to multiple downstream agents
	if len(state.DownstreamAgents) >= 3 && state.ErrorCount >= 5 {
		result.CascadeDetected = true
		result.AffectedAgents = len(state.DownstreamAgents) + 1
		result.AgentChain = append([]string{agentID}, state.DownstreamAgents...)
	}

	return result
}

// ============================================================================
// Helpers
// ============================================================================

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
