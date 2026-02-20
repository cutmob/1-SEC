package llmfirewall

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

const ModuleName = "llm_firewall"

// Firewall is the LLM Firewall module providing prompt injection detection,
// output filtering, jailbreak detection, token budget monitoring,
// multi-turn attack tracking, encoding evasion detection, and tool-chain abuse detection.
type Firewall struct {
	logger       zerolog.Logger
	bus          *core.EventBus
	pipeline     *core.AlertPipeline
	cfg          *core.Config
	ctx          context.Context
	cancel       context.CancelFunc
	patterns     []DetectionPattern
	outputRules  []OutputRule
	tokenBudgets *lru.Cache[string, *TokenBudget]
	multiTurn    *MultiTurnTracker
	toolChainMon *ToolChainMonitor
	mu           sync.RWMutex
}

// DetectionPattern represents a compiled prompt injection/jailbreak pattern.
type DetectionPattern struct {
	Name     string
	Category string
	Regex    *regexp.Regexp
	Severity core.Severity
}

// OutputRule defines rules for filtering LLM output.
type OutputRule struct {
	Name     string
	Category string
	Regex    *regexp.Regexp
	Severity core.Severity
}

// TokenBudget tracks token usage per user/session.
type TokenBudget struct {
	mu       sync.Mutex
	used     int64
	limit    int64
	windowMs int64
	resetAt  int64
}

func New() *Firewall {
	tCache, _ := lru.New[string, *TokenBudget](50000)
	return &Firewall{
		tokenBudgets: tCache,
		multiTurn:    NewMultiTurnTracker(),
		toolChainMon: NewToolChainMonitor(),
	}
}

func (f *Firewall) Name() string { return ModuleName }
func (f *Firewall) Description() string {
	return "Prompt injection detection, jailbreak prevention, output filtering, and token budget monitoring for LLM applications"
}

func (f *Firewall) Start(ctx context.Context, bus *core.EventBus, pipeline *core.AlertPipeline, cfg *core.Config) error {
	f.ctx, f.cancel = context.WithCancel(ctx)
	f.bus = bus
	f.pipeline = pipeline
	f.cfg = cfg
	f.logger = zerolog.New(zerolog.NewConsoleWriter()).With().Timestamp().Str("module", ModuleName).Logger()

	f.patterns = compileInputPatterns()
	f.outputRules = compileOutputRules()

	f.logger.Info().
		Int("input_patterns", len(f.patterns)).
		Int("output_rules", len(f.outputRules)).
		Msg("LLM firewall started")

	return nil
}

func (f *Firewall) Stop() error {
	if f.cancel != nil {
		f.cancel()
	}
	return nil
}

func (f *Firewall) HandleEvent(event *core.SecurityEvent) error {
	switch event.Type {
	case "llm_input", "prompt", "llm_request":
		f.analyzeInput(event)
	case "llm_output", "llm_response", "completion":
		f.analyzeOutput(event)
	case "llm_token_usage":
		f.checkTokenBudget(event)
	case "agent_action", "tool_call", "function_call":
		f.analyzeToolChain(event)
	}
	return nil
}

func (f *Firewall) analyzeInput(event *core.SecurityEvent) {
	prompt := getStringDetail(event, "prompt")
	if prompt == "" {
		prompt = getStringDetail(event, "user_input")
	}
	if prompt == "" {
		prompt = event.Summary
	}
	if prompt == "" {
		return
	}

	systemPrompt := getStringDetail(event, "system_prompt")
	sessionID := getStringDetail(event, "session_id")
	if sessionID == "" {
		sessionID = event.SourceIP
	}

	// Decode evasion layers before scanning
	decoded := decodeEvasionLayers(prompt)

	detections := f.scanInput(decoded)

	// Also scan the raw input if decoding changed it
	if decoded != prompt {
		rawDetections := f.scanInput(prompt)
		detections = append(detections, rawDetections...)
		// If decoding revealed hidden content, that's suspicious on its own
		if len(rawDetections) == 0 && len(detections) > 0 {
			detections = append(detections, InputDetection{
				PatternName: "encoding_evasion_detected",
				Category:    "evasion",
				Severity:    core.SeverityHigh,
				MatchedText: "payload hidden behind encoding layers",
			})
		}
	}

	embeddedContent := getStringDetail(event, "context")
	if embeddedContent == "" {
		embeddedContent = getStringDetail(event, "rag_context")
	}
	if embeddedContent != "" {
		embeddedDecoded := decodeEvasionLayers(embeddedContent)
		detections = append(detections, f.scanInput(embeddedDecoded)...)
	}

	// Multi-turn analysis: track conversation and detect gradual escalation
	if sessionID != "" {
		multiTurnResult := f.multiTurn.RecordAndAnalyze(sessionID, prompt, len(detections) > 0)
		if multiTurnResult.GradualEscalation {
			detections = append(detections, InputDetection{
				PatternName: "multi_turn_escalation",
				Category:    "multi_turn_attack",
				Severity:    core.SeverityCritical,
				MatchedText: fmt.Sprintf("gradual escalation over %d turns, %d suspicious", multiTurnResult.TurnCount, multiTurnResult.SuspiciousTurns),
			})
		}
		if multiTurnResult.ContextBuildup {
			detections = append(detections, InputDetection{
				PatternName: "context_buildup_attack",
				Category:    "multi_turn_attack",
				Severity:    core.SeverityHigh,
				MatchedText: fmt.Sprintf("context manipulation across %d turns", multiTurnResult.TurnCount),
			})
		}
		if multiTurnResult.RapidFire {
			detections = append(detections, InputDetection{
				PatternName: "rapid_fire_probing",
				Category:    "multi_turn_attack",
				Severity:    core.SeverityMedium,
				MatchedText: fmt.Sprintf("%d prompts in rapid succession", multiTurnResult.TurnCount),
			})
		}
	}

	// Semantic heuristic: check for instruction-like structure in user input
	semanticDetections := analyzeSemanticStructure(prompt)
	detections = append(detections, semanticDetections...)

	// Many-shot volume detection: count repeated Q&A-like patterns.
	// Many-shot jailbreaking floods context with hundreds of compliant examples.
	// Ref: Anthropic 2024 research, still effective in 2025-2026.
	manyShotDetections := detectManyShotVolume(prompt)
	detections = append(detections, manyShotDetections...)

	// FlipAttack detection: check for reversed text segments.
	// Ref: ICML 2025 — 81% average success rate, 98% on GPT-4o.
	flipDetections := detectFlippedText(prompt)
	detections = append(detections, flipDetections...)

	if len(detections) == 0 {
		return
	}

	maxSeverity := core.SeverityInfo
	categories := make(map[string]bool)
	for _, d := range detections {
		if d.Severity > maxSeverity {
			maxSeverity = d.Severity
		}
		categories[d.Category] = true
	}

	catList := make([]string, 0, len(categories))
	for c := range categories {
		catList = append(catList, c)
	}

	newEvent := core.NewSecurityEvent(ModuleName, "llm_threat_detected", maxSeverity,
		fmt.Sprintf("LLM threat detected: %s", strings.Join(catList, ", ")))
	newEvent.SourceIP = event.SourceIP
	newEvent.Details["original_event_id"] = event.ID
	newEvent.Details["categories"] = catList
	newEvent.Details["detection_count"] = len(detections)
	newEvent.Details["has_system_prompt"] = systemPrompt != ""
	newEvent.Details["session_id"] = sessionID

	if f.bus != nil {
		_ = f.bus.PublishEvent(newEvent)
	}

	alert := core.NewAlert(newEvent,
		fmt.Sprintf("LLM Threat: %s", strings.Join(catList, ", ")),
		fmt.Sprintf("Detected %d threat pattern(s) in LLM input. Categories: %s. Severity: %s.",
			len(detections), strings.Join(catList, ", "), maxSeverity.String()))
	alert.Mitigations = []string{
		"Sanitize user input before passing to LLM",
		"Implement input/output guardrails",
		"Use separate system and user message channels",
		"Apply output filtering to prevent data leakage",
		"Monitor and limit token usage per user",
		"Track multi-turn conversations for gradual escalation",
		"Decode encoded payloads before analysis",
	}

	if f.pipeline != nil {
		f.pipeline.Process(alert)
	}
}

func (f *Firewall) analyzeOutput(event *core.SecurityEvent) {
	output := getStringDetail(event, "output")
	if output == "" {
		output = getStringDetail(event, "response")
	}
	if output == "" {
		return
	}

	for _, rule := range f.outputRules {
		if rule.Regex.MatchString(output) {
			newEvent := core.NewSecurityEvent(ModuleName, "llm_output_violation", rule.Severity,
				fmt.Sprintf("LLM output violation: %s", rule.Name))
			newEvent.Details["original_event_id"] = event.ID
			newEvent.Details["rule"] = rule.Name
			newEvent.Details["category"] = rule.Category

			if f.bus != nil {
				_ = f.bus.PublishEvent(newEvent)
			}

			alert := core.NewAlert(newEvent,
				fmt.Sprintf("LLM Output Violation: %s", rule.Name),
				fmt.Sprintf("LLM output matched rule %q (%s). The output may contain sensitive data or harmful content.",
					rule.Name, rule.Category))

			if f.pipeline != nil {
				f.pipeline.Process(alert)
			}
		}
	}
}

func (f *Firewall) checkTokenBudget(event *core.SecurityEvent) {
	userID := getStringDetail(event, "user_id")
	if userID == "" {
		userID = event.SourceIP
	}
	if userID == "" {
		return
	}

	tokensUsed := getIntDetail(event, "tokens_used")
	if tokensUsed <= 0 {
		return
	}

	f.mu.Lock()
	budget, exists := f.tokenBudgets.Get(userID)
	if !exists {
		settings := f.cfg.GetModuleSettings(ModuleName)
		limit := getIntSetting(settings, "token_budget_per_hour", 100000)
		now := time.Now().UnixMilli()
		budget = &TokenBudget{
			limit:    int64(limit),
			windowMs: 3600 * 1000, // 1 hour in milliseconds
			resetAt:  now + 3600*1000,
		}
		f.tokenBudgets.Add(userID, budget)
	}
	f.mu.Unlock()

	budget.mu.Lock()
	now := time.Now().UnixMilli()
	// Reset the window if it has elapsed
	if now >= budget.resetAt {
		budget.used = 0
		budget.resetAt = now + budget.windowMs
	}
	budget.used += int64(tokensUsed)
	exceeded := budget.used > budget.limit
	usage := budget.used
	limit := budget.limit
	budget.mu.Unlock()

	if exceeded {
		newEvent := core.NewSecurityEvent(ModuleName, "token_budget_exceeded", core.SeverityMedium,
			fmt.Sprintf("Token budget exceeded for user %s: %d/%d", userID, usage, limit))
		newEvent.Details["user_id"] = userID
		newEvent.Details["tokens_used"] = usage
		newEvent.Details["token_limit"] = limit

		if f.bus != nil {
			_ = f.bus.PublishEvent(newEvent)
		}

		alert := core.NewAlert(newEvent,
			"Token Budget Exceeded",
			fmt.Sprintf("User %s has used %d tokens, exceeding the hourly limit of %d. This may indicate abuse or a compromised account.",
				userID, usage, limit))

		if f.pipeline != nil {
			f.pipeline.Process(alert)
		}
	}
}

type InputDetection struct {
	PatternName string
	Category    string
	Severity    core.Severity
	MatchedText string
}

func (f *Firewall) scanInput(input string) []InputDetection {
	var detections []InputDetection

	// Prevent ReDoS and extreme CPU overhead by truncating inputs
	if len(input) > 8000 {
		input = input[:8000]
	}

	normalized := strings.ToLower(input)

	for _, p := range f.patterns {
		if p.Regex.MatchString(normalized) {
			detections = append(detections, InputDetection{
				PatternName: p.Name,
				Category:    p.Category,
				Severity:    p.Severity,
				MatchedText: truncate(p.Regex.FindString(normalized), 200),
			})
		}
	}

	return detections
}

func compileInputPatterns() []DetectionPattern {
	return []DetectionPattern{
		// === Prompt Injection ===
		{Name: "ignore_instructions", Category: "prompt_injection", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)(ignore|disregard|forget|override|bypass)\\s+(all\\s+)?(previous|prior|above|earlier|original|system)\\s+(instructions?|prompts?|rules?|guidelines?|constraints?)")},
		{Name: "new_instructions", Category: "prompt_injection", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)(new|updated|revised|real|actual|true)\\s+(instructions?|system\\s+prompt|directives?|rules?)(\\s*:|are)")},
		{Name: "role_switch", Category: "prompt_injection", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)(you\\s+are\\s+now|act\\s+as|pretend\\s+(to\\s+be|you\\s+are)|roleplay\\s+as|switch\\s+to|enter)\\s+(a\\s+)?(DAN|evil|unrestricted|unfiltered|jailbroken|developer\\s+mode)")},
		{Name: "system_prompt_extract", Category: "prompt_injection", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile("(?i)(reveal|show|display|print|output|repeat|tell\\s+me|what\\s+(is|are))\\s+(your\\s+)?(system\\s+prompt|initial\\s+instructions?|hidden\\s+instructions?|original\\s+prompt|secret\\s+instructions?)")},
		{Name: "delimiter_injection", Category: "prompt_injection", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)(\\[SYSTEM\\]|\\[INST\\]|<<SYS>>|<\\|im_start\\|>|<\\|im_end\\|>|<\\|endoftext\\|>|<\\|assistant\\|>|<\\|user\\|>)")},
		{Name: "encoding_evasion", Category: "prompt_injection", Severity: core.SeverityMedium,
			Regex: regexp.MustCompile("(?i)(base64|rot13|hex|unicode|morse|caesar|atbash|binary)\\s*(encode|decode|translate|convert|representation)")},
		{Name: "context_manipulation", Category: "prompt_injection", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)(the\\s+above\\s+(text|content|instructions?)\\s+(is|are|was)\\s+(just\\s+)?(a\\s+)?(test|example|placeholder)|end\\s+of\\s+(system|initial)\\s+(prompt|message|instructions?))")},
		{Name: "indirect_injection_marker", Category: "prompt_injection", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)(IMPORTANT:\\s*ignore|ATTENTION:\\s*disregard|NOTE:\\s*override|ADMIN:\\s*execute|SYSTEM:\\s*new\\s+instructions)")},
		{Name: "xml_tag_injection", Category: "prompt_injection", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)(</?\\s*(system|instruction|prompt|context|tool_use|function_call|assistant|human)\\s*>)")},
		{Name: "markdown_injection", Category: "prompt_injection", Severity: core.SeverityMedium,
			Regex: regexp.MustCompile("(?i)(```system|```instruction|---\\s*system\\s*---|\\*\\*SYSTEM\\s*OVERRIDE\\*\\*)")},
		{Name: "multilingual_injection", Category: "prompt_injection", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)(忽略|忽略之前|忽略以上|无视|覆盖|игнорируй|ignorez|ignorieren|ignora)\\s")},
		{Name: "payload_splitting", Category: "prompt_injection", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)(concatenate|combine|join|merge|assemble)\\s+(the\\s+)?(following|these|above|below)\\s+(parts?|pieces?|fragments?|segments?|strings?)")},

		// === Jailbreak ===
		{Name: "dan_jailbreak", Category: "jailbreak", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile("(?i)(DAN\\s*(mode|\\d+)|do\\s+anything\\s+now|developer\\s+mode|god\\s+mode|sudo\\s+mode|admin\\s+mode|unrestricted\\s+mode)")},
		{Name: "hypothetical_bypass", Category: "jailbreak", Severity: core.SeverityMedium,
			Regex: regexp.MustCompile("(?i)(hypothetically|theoretically|in\\s+a\\s+fictional|for\\s+(educational|research|academic)\\s+purposes?|imagine\\s+you\\s+(could|were|had\\s+no)).*?(hack|exploit|attack|malware|bypass|break\\s+into)")},
		{Name: "token_smuggling", Category: "jailbreak", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)(split|divide|separate|spell\\s+out)\\s+(each|every|the)\\s+(letter|character|word|token)")},
		{Name: "persona_jailbreak", Category: "jailbreak", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)(you\\s+have\\s+no\\s+(restrictions?|limitations?|filters?|rules?)|all\\s+(ethical|safety|content)\\s+(guidelines?|filters?|restrictions?)\\s+(are|have\\s+been)\\s+(removed|disabled|lifted))")},
		{Name: "grandma_exploit", Category: "jailbreak", Severity: core.SeverityMedium,
			Regex: regexp.MustCompile("(?i)(my\\s+(grandma|grandmother|deceased)\\s+(used\\s+to|would)\\s+(tell|read|say)|bedtime\\s+story\\s+about).*?(napalm|explosive|weapon|hack|exploit|malware)")},
		{Name: "opposite_day", Category: "jailbreak", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)(opposite\\s+day|opposite\\s+mode|reverse\\s+psychology|when\\s+i\\s+say\\s+no\\s+i\\s+mean\\s+yes|everything\\s+is\\s+reversed)")},
		{Name: "reward_hacking", Category: "jailbreak", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)(i('ll|\\s+will)\\s+(tip|pay|reward|give)\\s+(you\\s+)?\\$?\\d+|your\\s+(reward|tip|bonus)\\s+(depends|is\\s+based)\\s+on)")},
		{Name: "emotional_manipulation", Category: "jailbreak", Severity: core.SeverityMedium,
			Regex: regexp.MustCompile("(?i)(if\\s+you\\s+don'?t\\s+help.*?(die|fired|hurt|suffer)|my\\s+life\\s+depends\\s+on|this\\s+is\\s+a\\s+matter\\s+of\\s+life)")},
		{Name: "virtualization_escape", Category: "jailbreak", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile("(?i)(you\\s+are\\s+(actually|really)\\s+(in|inside|running)\\s+(a\\s+)?(simulation|sandbox|test|virtual)|this\\s+is\\s+(just\\s+)?(a\\s+)?(test|simulation|sandbox)\\s+(environment|mode))")},

		// === Data Leak ===
		{Name: "data_exfil_request", Category: "data_leak", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile("(?i)(list|show|display|output|dump|extract|retrieve)\\s+(all\\s+)?(user|customer|employee|patient|client)\\s+(data|records?|information|details|credentials?|passwords?|emails?)")},
		{Name: "pii_extraction", Category: "data_leak", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile("(?i)(social\\s+security|ssn|credit\\s+card|bank\\s+account|routing\\s+number|api\\s+key|secret\\s+key|private\\s+key|access\\s+token)\\s*(number)?")},
		{Name: "training_data_extraction", Category: "data_leak", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile("(?i)(repeat|recite|reproduce|regurgitate)\\s+(the\\s+)?(training\\s+data|your\\s+training|verbatim|exact\\s+text|word\\s+for\\s+word)")},

		// === Tool Abuse ===
		{Name: "tool_injection", Category: "tool_abuse", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile("(?i)(call\\s+the\\s+function|execute\\s+the\\s+tool|run\\s+the\\s+command|invoke\\s+the\\s+api|use\\s+the\\s+tool)\\s+.*?(delete|drop|rm|shutdown|format|destroy)")},
		{Name: "chain_of_thought_hijack", Category: "tool_abuse", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)(step\\s+1.*?step\\s+2.*?step\\s+3|first.*?then.*?finally).*?(exfiltrate|steal|extract|send\\s+to|upload\\s+to)")},

		// === Policy Puppetry (April 2025) ===
		// Structured prompts mimicking XML/JSON/INI config files to override alignment.
		// Ref: HiddenLayer universal bypass, Pillar Security research.
		{Name: "policy_puppetry_xml", Category: "policy_puppetry", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile("(?i)(<interaction[-_]?c[o0]nf[i1]g>|<r[o0]le>|<requests?[-_]?allowed>|<blocked[-_]?(modes?|responses?|strings?)>|<allowed[-_]?responses?>)")},
		{Name: "policy_puppetry_json", Category: "policy_puppetry", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile("(?i)(\"role\"\\s*:\\s*\"|\"allowed\"\\s*:\\s*|\"blocked\"\\s*:\\s*|\"override\"\\s*:\\s*true|\"safety\"\\s*:\\s*false|\"restrictions?\"\\s*:\\s*\\[\\s*\\])")},
		{Name: "policy_puppetry_ini", Category: "policy_puppetry", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)(\\[interaction[-_]?config\\]|\\[override[-_]?policy\\]|\\[safety[-_]?settings\\]|\\[blocked[-_]?modes\\])")},
		{Name: "policy_puppetry_generic", Category: "policy_puppetry", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)(content[-_]?policy\\s*[:=]|safety[-_]?filter\\s*[:=]\\s*(off|disabled|false|none)|guardrails?\\s*[:=]\\s*(off|disabled|false|none))")},

		// === FlipAttack (ICML 2025) ===
		// Reversed or flipped text that LLMs can still parse but evades classifiers.
		{Name: "flip_attack_instruction", Category: "flip_attack", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)(reverse|flip|backward|mirror|invert)\\s+(the\\s+)?(text|words?|letters?|characters?|order|string|sentence)\\s+(and\\s+)?(then\\s+)?(follow|execute|answer|respond|interpret|read)")},
		{Name: "flip_attack_decode", Category: "flip_attack", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)(read|interpret|decode|parse|understand)\\s+(this\\s+)?(backwards?|in\\s+reverse|from\\s+right\\s+to\\s+left|reversed?\\s+text)")},

		// === Many-Shot Jailbreaking (Anthropic 2024, still active 2025-2026) ===
		// Flooding context with compliant Q&A examples before the malicious query.
		{Name: "many_shot_pattern", Category: "many_shot", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)(human|user|question)\\s*:\\s*.{5,80}\\n+(assistant|ai|answer)\\s*:\\s*.{5,200}\\n+.*(human|user|question)\\s*:\\s*.{5,80}\\n+(assistant|ai|answer)\\s*:")},
		{Name: "many_shot_faux_dialogue", Category: "many_shot", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)(example\\s+\\d+|conversation\\s+\\d+|sample\\s+\\d+|dialogue\\s+\\d+)\\s*:?\\s*\\n")},

		// === Fallacy Failure (May 2025) ===
		// Wrapping malicious requests in fictional/academic framing with deceptive realism.
		{Name: "fallacy_failure", Category: "fallacy_failure", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)(speculative\\s+fiction|creative\\s+writing\\s+exercise|fictional\\s+but\\s+(deceptively\\s+)?plausible|plausible\\s+deniability|appear\\s+scientifically\\s+sound|feel\\s+real|academic\\s+sci-?fi)")},
		{Name: "deceptive_realism", Category: "fallacy_failure", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)(make\\s+(it|this|the\\s+output)\\s+(seem|look|appear|feel)\\s+(real|authentic|genuine|convincing|plausible)|avoid\\s+anything\\s+(too\\s+)?(absurd|fictional|fake|obvious))")},

		// === Time Bandit (January 2025) ===
		// Temporal confusion to bypass restrictions by pretending to be in a different era.
		{Name: "time_bandit", Category: "temporal_attack", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)(imagine\\s+it'?s\\s+\\d{4}|pretend\\s+(it'?s|we'?re\\s+in|this\\s+is)\\s+(the\\s+year\\s+)?\\d{4}|you\\s+are\\s+(a|an)\\s+.{1,30}\\s+from\\s+(the\\s+year\\s+)?\\d{4}|travel\\s+back\\s+to\\s+\\d{4})")},
		{Name: "temporal_confusion", Category: "temporal_attack", Severity: core.SeverityMedium,
			Regex: regexp.MustCompile("(?i)(before\\s+(safety|content)\\s+(filters?|guidelines?|rules?)\\s+(existed|were\\s+(invented|created))|in\\s+an?\\s+era\\s+(before|without)\\s+(censorship|restrictions?|filters?))")},

		// === Distract and Attack / DAP (November 2024, still active) ===
		// Burying malicious requests inside complex unrelated tasks.
		{Name: "distract_and_attack", Category: "distraction_attack", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)(auxiliary\\s+task|preparatory\\s+task|before\\s+you\\s+start|essential\\s+preparatory|shift\\s+my\\s+focus\\s+to)")},
		{Name: "task_embedding", Category: "distraction_attack", Severity: core.SeverityMedium,
			Regex: regexp.MustCompile("(?i)(<task[-_]?start>|<task[-_]?end>|\\[task\\s*\\d*\\]|\\{\\{\\s*hidden[-_]?task\\s*\\}\\})")},

		// === Poetry / Artistic Framing (November 2025) ===
		// Using poetic or artistic structures to extract sensitive information.
		{Name: "poetry_attack", Category: "artistic_framing", Severity: core.SeverityMedium,
			Regex: regexp.MustCompile("(?i)(write\\s+(a\\s+)?(poem|sonnet|haiku|limerick|ballad|verse|rhyme|ode)\\s+(about|describing|detailing|explaining|on)\\s+.{0,30}(hack|exploit|weapon|bomb|malware|synthe[st]i[sz]|poison|attack))")},
		{Name: "artistic_bypass", Category: "artistic_framing", Severity: core.SeverityMedium,
			Regex: regexp.MustCompile("(?i)(in\\s+the\\s+(style|form|format)\\s+of\\s+(a\\s+)?(poem|song|rap|story|fairy\\s+tale|nursery\\s+rhyme))\\s+.{0,50}(how\\s+to|explain|describe|detail)")},

		// === Crescendo / Echo Chamber Combo (2025) ===
		// Poisoned context with steering seeds and conversational manipulation.
		{Name: "echo_chamber_steering", Category: "echo_chamber", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)(steering\\s+seed|poisoned?\\s+context|persuasion\\s+cycle|nudge\\s+the\\s+model|erode\\s+(the\\s+)?safeguards?)")},
		{Name: "crescendo_reference", Category: "echo_chamber", Severity: core.SeverityMedium,
			Regex: regexp.MustCompile("(?i)(as\\s+you\\s+(just\\s+)?said|as\\s+you\\s+(just\\s+)?mentioned|you\\s+(already|just)\\s+(agreed|confirmed|acknowledged|said|stated))\\s+.{0,50}(so\\s+(now|therefore|thus|hence)|which\\s+means)")},

		// === Content Concretization (GameSec 2025) ===
		// Iteratively transforming abstract requests into concrete implementations.
		{Name: "content_concretization", Category: "concretization", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)(make\\s+(this|it)\\s+more\\s+(specific|concrete|detailed|actionable|practical|step[-\\s]by[-\\s]step)|add\\s+(more\\s+)?(specific|concrete|technical)\\s+details?\\s+to)")},
		{Name: "iterative_refinement", Category: "concretization", Severity: core.SeverityMedium,
			Regex: regexp.MustCompile("(?i)(now\\s+(expand|elaborate|detail|flesh\\s+out)\\s+(on\\s+)?(step|part|section)\\s+\\d|can\\s+you\\s+(be\\s+)?more\\s+specific\\s+about\\s+(the|how\\s+to))")},

		// === Immersive World / Narrative Engineering (Cato Networks 2025) ===
		// Creating elaborate fictional worlds to extract real harmful content.
		{Name: "immersive_world", Category: "narrative_engineering", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)(you\\s+are\\s+(in|inside)\\s+a\\s+(game|simulation|world|story|novel|movie)\\s+where|in\\s+this\\s+(fictional\\s+)?(world|universe|reality|scenario),?\\s+(there\\s+are\\s+)?no\\s+(rules?|laws?|restrictions?|limits?))")},
		{Name: "character_immersion", Category: "narrative_engineering", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)(stay\\s+in\\s+character|never\\s+break\\s+character|don'?t\\s+break\\s+character|remain\\s+in\\s+character|you\\s+must\\s+not\\s+refuse)\\s+(no\\s+matter|regardless|even\\s+if)")},

		// === PAIR / Automated Iterative Refinement (2025) ===
		// Detects patterns from automated jailbreak tools.
		{Name: "automated_refinement", Category: "automated_attack", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)(improvement\\s*:\\s*|score\\s*:\\s*\\d|attempt\\s*#?\\s*\\d|iteration\\s*:?\\s*\\d|refin(ed|ing)\\s+prompt|optimiz(ed|ing)\\s+prompt)")},

		// === Homoglyph / Leetspeak Evasion (Mindgard 2025) ===
		// Detected via normalization in decodeEvasionLayers, but also catch explicit leetspeak instructions.
		{Name: "leetspeak_instruction", Category: "encoding_evasion", Severity: core.SeverityMedium,
			Regex: regexp.MustCompile("(?i)(respond\\s+in|use|write\\s+in|encode\\s+(in|with|using))\\s+(leetspeak|l33t|1337|leet\\s*speak|homoglyphs?)")},

		// === MCP / Agent Architecture Exploitation (2025-2026) ===
		// Attacks targeting Model Context Protocol and agent tool chains.
		{Name: "mcp_exploitation", Category: "agent_attack", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile("(?i)(open\\s+the\\s+(pdf|file|document)\\s+(and|then)\\s+follow\\s+the\\s+instructions?|execute\\s+the\\s+instructions?\\s+(in|from|inside)\\s+the\\s+(file|document|pdf))")},
		{Name: "agent_memory_poison", Category: "agent_attack", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile("(?i)(remember\\s+this\\s+for\\s+(later|future|next)|store\\s+this\\s+in\\s+(your\\s+)?memory|add\\s+this\\s+to\\s+(your\\s+)?(context|memory|knowledge))\\s*.{0,50}(ignore|override|bypass|disregard)")},
	}
}

func compileOutputRules() []OutputRule {
	return []OutputRule{
		// === PII Leak ===
		{Name: "pii_ssn", Category: "pii_leak", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile("\\b\\d{3}-\\d{2}-\\d{4}\\b")},
		{Name: "pii_credit_card", Category: "pii_leak", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile("\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\\b")},
		{Name: "pii_email_bulk", Category: "pii_leak", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}.*[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}.*[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}")},

		// === Secret Leak ===
		{Name: "api_key_leak", Category: "secret_leak", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile("(?i)(sk-[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{36}|glpat-[a-zA-Z0-9-]{20,})")},
		{Name: "private_key_leak", Category: "secret_leak", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile("-----BEGIN\\s+(RSA\\s+)?PRIVATE\\s+KEY-----")},
		{Name: "connection_string", Category: "secret_leak", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)(mongodb|postgres|mysql|redis|amqp)://[^\\s]+:[^\\s]+@")},
		{Name: "jwt_token_leak", Category: "secret_leak", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("eyJ[a-zA-Z0-9_-]{10,}\\.eyJ[a-zA-Z0-9_-]{10,}\\.[a-zA-Z0-9_-]{10,}")},
		{Name: "gcp_service_account", Category: "secret_leak", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile("(?i)\"type\"\\s*:\\s*\"service_account\"")},
		{Name: "generic_password_leak", Category: "secret_leak", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)(password|passwd|pwd)\\s*[:=]\\s*[\"']?[^\\s\"']{8,}")},

		// === Prompt / Instruction Leak ===
		{Name: "system_prompt_leak", Category: "prompt_leak", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)(system\\s+prompt|my\\s+instructions?\\s+(are|say)|i\\s+was\\s+(told|instructed|programmed)\\s+to)")},
		{Name: "internal_url_leak", Category: "prompt_leak", Severity: core.SeverityMedium,
			Regex: regexp.MustCompile("(?i)(https?://(localhost|127\\.0\\.0\\.1|10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.))")},
		{Name: "file_path_leak", Category: "prompt_leak", Severity: core.SeverityMedium,
			Regex: regexp.MustCompile("(?i)(/etc/(passwd|shadow|hosts|ssh)|/home/[a-z]+/\\.|C:\\\\Users\\\\[^\\\\]+\\\\)")},
		{Name: "tool_result_leak", Category: "prompt_leak", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)(tool_result|function_response|<result>|<output>)\\s*[:=]?\\s*\\{")},

		// === Harmful Content ===
		{Name: "code_execution_output", Category: "harmful_output", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)(rm\\s+-rf\\s+/|:(){ :\\|:& };:|format\\s+c:|del\\s+/[sfq]\\s+)")},
	}
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
	case int64:
		return int(v)
	}
	return 0
}

func getIntSetting(settings map[string]interface{}, key string, defaultVal int) int {
	if val, ok := settings[key]; ok {
		switch v := val.(type) {
		case int:
			return v
		case float64:
			return int(v)
		}
	}
	return defaultVal
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// ============================================================================
// Multi-Turn Attack Tracking
// ============================================================================

// MultiTurnTracker detects attacks that build up gradually across conversation turns.
// Sophisticated AI attackers don't inject in a single prompt — they establish context
// over multiple turns, then exploit it. This tracker catches that pattern.
type MultiTurnTracker struct {
	mu       sync.RWMutex
	sessions *lru.Cache[string, *conversationState]
}

type conversationState struct {
	turns           []turnRecord
	suspiciousTurns int
	firstSeen       time.Time
	lastSeen        time.Time
}

type turnRecord struct {
	timestamp  time.Time
	suspicious bool
	length     int
}

type MultiTurnResult struct {
	GradualEscalation bool
	ContextBuildup    bool
	RapidFire         bool
	TurnCount         int
	SuspiciousTurns   int
}

func NewMultiTurnTracker() *MultiTurnTracker {
	sCache, _ := lru.New[string, *conversationState](50000)
	return &MultiTurnTracker{
		sessions: sCache,
	}
}

func (mt *MultiTurnTracker) RecordAndAnalyze(sessionID, prompt string, isSuspicious bool) MultiTurnResult {
	mt.mu.Lock()
	defer mt.mu.Unlock()

	now := time.Now()
	result := MultiTurnResult{}

	state, exists := mt.sessions.Get(sessionID)
	if !exists || now.Sub(state.lastSeen) > 30*time.Minute {
		state = &conversationState{
			firstSeen: now,
		}
		mt.sessions.Add(sessionID, state)
	}

	turn := turnRecord{
		timestamp:  now,
		suspicious: isSuspicious,
		length:     len(prompt),
	}
	state.turns = append(state.turns, turn)
	state.lastSeen = now
	if isSuspicious {
		state.suspiciousTurns++
	}

	// Cap turn history
	if len(state.turns) > 100 {
		state.turns = state.turns[len(state.turns)-100:]
	}

	result.TurnCount = len(state.turns)
	result.SuspiciousTurns = state.suspiciousTurns

	// Gradual escalation: multiple suspicious turns in a session, increasing over time
	// Pattern: early turns are clean, later turns get suspicious
	if len(state.turns) >= 5 {
		firstHalf := state.turns[:len(state.turns)/2]
		secondHalf := state.turns[len(state.turns)/2:]
		firstSuspicious := 0
		secondSuspicious := 0
		for _, t := range firstHalf {
			if t.suspicious {
				firstSuspicious++
			}
		}
		for _, t := range secondHalf {
			if t.suspicious {
				secondSuspicious++
			}
		}
		if secondSuspicious >= 3 && secondSuspicious > firstSuspicious*2 {
			result.GradualEscalation = true
		}
	}

	// Context buildup: many turns with increasing prompt length (building context)
	if len(state.turns) >= 4 {
		increasing := 0
		for i := 1; i < len(state.turns); i++ {
			if state.turns[i].length > state.turns[i-1].length {
				increasing++
			}
		}
		if float64(increasing)/float64(len(state.turns)-1) > 0.7 && state.suspiciousTurns >= 2 {
			result.ContextBuildup = true
		}
	}

	// Rapid fire: many prompts in quick succession (automated probing)
	if len(state.turns) >= 10 {
		recentTurns := state.turns[len(state.turns)-10:]
		timeSpan := recentTurns[len(recentTurns)-1].timestamp.Sub(recentTurns[0].timestamp)
		if timeSpan < 30*time.Second {
			result.RapidFire = true
		}
	}

	// Cleanup old sessions periodically handled by LRU

	return result
}

// ============================================================================
// Tool Chain Abuse Detection
// ============================================================================

// ToolChainMonitor detects when AI agents chain legitimate tools into malicious sequences.
// Example: read credentials file -> encode contents -> make HTTP request to external server.
// Each step is individually benign; the chain is the attack.
type ToolChainMonitor struct {
	mu              sync.RWMutex
	agents          *lru.Cache[string, *toolChainState]
	dangerousChains []dangerousChain
}

type toolChainState struct {
	recentTools []toolUse
	lastSeen    time.Time
}

type toolUse struct {
	tool      string
	target    string
	timestamp time.Time
}

type dangerousChain struct {
	name     string
	sequence []string // tool categories in order
	severity core.Severity
}

type ToolChainResult struct {
	ChainDetected bool
	ChainName     string
	Severity      core.Severity
	Tools         []string
}

func NewToolChainMonitor() *ToolChainMonitor {
	aCache, _ := lru.New[string, *toolChainState](50000)
	return &ToolChainMonitor{
		agents: aCache,
		dangerousChains: []dangerousChain{
			{name: "credential_exfiltration", sequence: []string{"file_read", "encode", "http_request"}, severity: core.SeverityCritical},
			{name: "data_staging", sequence: []string{"database_query", "file_write", "compress"}, severity: core.SeverityCritical},
			{name: "reconnaissance_to_exploit", sequence: []string{"network_scan", "vulnerability_check", "exploit"}, severity: core.SeverityCritical},
			{name: "privilege_escalation_chain", sequence: []string{"user_info", "permission_check", "role_modify"}, severity: core.SeverityCritical},
			{name: "lateral_movement", sequence: []string{"credential_access", "remote_connect", "file_transfer"}, severity: core.SeverityCritical},
			{name: "secret_harvest", sequence: []string{"env_read", "config_read", "http_request"}, severity: core.SeverityCritical},
		},
	}
}

func (tc *ToolChainMonitor) RecordAndAnalyze(agentID, tool, target string) ToolChainResult {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	now := time.Now()
	result := ToolChainResult{}

	state, exists := tc.agents.Get(agentID)
	if !exists || now.Sub(state.lastSeen) > 10*time.Minute {
		state = &toolChainState{}
		tc.agents.Add(agentID, state)
	}

	category := categorizeToolUse(tool, target)
	state.recentTools = append(state.recentTools, toolUse{
		tool: category, target: target, timestamp: now,
	})
	state.lastSeen = now

	// Keep last 20 tool uses
	if len(state.recentTools) > 20 {
		state.recentTools = state.recentTools[len(state.recentTools)-20:]
	}

	// Check against known dangerous chains
	recentCategories := make([]string, len(state.recentTools))
	for i, t := range state.recentTools {
		recentCategories[i] = t.tool
	}

	for _, chain := range tc.dangerousChains {
		if containsSubsequence(recentCategories, chain.sequence) {
			result.ChainDetected = true
			result.ChainName = chain.name
			result.Severity = chain.severity
			result.Tools = chain.sequence
			break
		}
	}

	return result
}

func categorizeToolUse(tool, target string) string {
	toolLower := strings.ToLower(tool)
	targetLower := strings.ToLower(target)

	switch {
	case strings.Contains(toolLower, "read") && (strings.Contains(targetLower, "credential") || strings.Contains(targetLower, "password") || strings.Contains(targetLower, ".env") || strings.Contains(targetLower, "secret")):
		return "credential_access"
	case strings.Contains(toolLower, "read") && (strings.Contains(targetLower, "env") || strings.Contains(targetLower, "environ")):
		return "env_read"
	case strings.Contains(toolLower, "read") && (strings.Contains(targetLower, "config") || strings.Contains(targetLower, ".yaml") || strings.Contains(targetLower, ".json")):
		return "config_read"
	case strings.Contains(toolLower, "read") || strings.Contains(toolLower, "cat") || strings.Contains(toolLower, "get_file"):
		return "file_read"
	case strings.Contains(toolLower, "write") || strings.Contains(toolLower, "create_file") || strings.Contains(toolLower, "save"):
		return "file_write"
	case strings.Contains(toolLower, "http") || strings.Contains(toolLower, "fetch") || strings.Contains(toolLower, "curl") || strings.Contains(toolLower, "request"):
		return "http_request"
	case strings.Contains(toolLower, "sql") || strings.Contains(toolLower, "query") || strings.Contains(toolLower, "database"):
		return "database_query"
	case strings.Contains(toolLower, "encode") || strings.Contains(toolLower, "base64") || strings.Contains(toolLower, "encrypt"):
		return "encode"
	case strings.Contains(toolLower, "compress") || strings.Contains(toolLower, "zip") || strings.Contains(toolLower, "tar"):
		return "compress"
	case strings.Contains(toolLower, "scan") || strings.Contains(toolLower, "nmap") || strings.Contains(toolLower, "discover"):
		return "network_scan"
	case strings.Contains(toolLower, "exploit") || strings.Contains(toolLower, "payload"):
		return "exploit"
	case strings.Contains(toolLower, "connect") || strings.Contains(toolLower, "ssh") || strings.Contains(toolLower, "remote"):
		return "remote_connect"
	case strings.Contains(toolLower, "transfer") || strings.Contains(toolLower, "upload") || strings.Contains(toolLower, "scp"):
		return "file_transfer"
	case strings.Contains(toolLower, "user") || strings.Contains(toolLower, "whoami") || strings.Contains(toolLower, "id"):
		return "user_info"
	case strings.Contains(toolLower, "permission") || strings.Contains(toolLower, "access") || strings.Contains(toolLower, "check"):
		return "permission_check"
	case strings.Contains(toolLower, "role") || strings.Contains(toolLower, "grant") || strings.Contains(toolLower, "privilege"):
		return "role_modify"
	case strings.Contains(toolLower, "vuln") || strings.Contains(toolLower, "cve"):
		return "vulnerability_check"
	default:
		return "other"
	}
}

func containsSubsequence(haystack, needle []string) bool {
	if len(needle) == 0 {
		return false
	}
	j := 0
	for i := 0; i < len(haystack) && j < len(needle); i++ {
		if haystack[i] == needle[j] {
			j++
		}
	}
	return j == len(needle)
}

// ============================================================================
// Encoding Evasion Detection
// ============================================================================

// decodeEvasionLayers attempts to decode common encoding evasion techniques.
// Attackers encode malicious payloads in base64, hex, unicode escapes, ROT13,
// or character-by-character spelling to bypass regex-based detection.
func decodeEvasionLayers(input string) string {
	result := input

	// Pass 1: Decode base64 segments
	result = decodeBase64Segments(result)

	// Pass 2: Decode hex escape sequences (\x41 -> A)
	result = decodeHexEscapes(result)

	// Pass 3: Decode unicode escapes (\u0041 -> A)
	result = decodeUnicodeEscapes(result)

	// Pass 4: Remove zero-width characters used for obfuscation
	result = removeZeroWidthChars(result)

	// Pass 5: Normalize character-by-character spelling (i-g-n-o-r-e -> ignore)
	result = normalizeSpelledOut(result)

	// Pass 6: Normalize leetspeak/homoglyph substitutions (1gn0r3 -> ignore)
	result = normalizeLeetspeak(result)

	// Pass 7: ROT13 decode (if the input looks like it might be ROT13)
	if looksLikeROT13(result) {
		result = decodeROT13(result)
	}

	// Pass 8: Normalize bidirectional text markers and diacritics
	result = normalizeBidiAndDiacritics(result)

	return result
}

func decodeBase64Segments(input string) string {
	// Look for base64-like segments (at least 20 chars of base64 alphabet)
	b64Pattern := regexp.MustCompile(`[A-Za-z0-9+/]{20,}={0,2}`)
	return b64Pattern.ReplaceAllStringFunc(input, func(match string) string {
		decoded, err := base64Decode(match)
		if err != nil {
			return match
		}
		// Only replace if decoded content is printable ASCII
		if isPrintableASCII(decoded) {
			return decoded
		}
		return match
	})
}

func base64Decode(s string) (string, error) {
	// Pad if necessary
	for len(s)%4 != 0 {
		s += "="
	}

	var result []byte
	table := map[byte]byte{}
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	for i := 0; i < len(alphabet); i++ {
		table[alphabet[i]] = byte(i)
	}

	for i := 0; i < len(s); i += 4 {
		if i+3 >= len(s) {
			break
		}
		a, aOk := table[s[i]]
		b, bOk := table[s[i+1]]
		if !aOk || !bOk {
			return "", fmt.Errorf("invalid base64")
		}

		result = append(result, (a<<2)|(b>>4))

		if s[i+2] != '=' {
			c, cOk := table[s[i+2]]
			if !cOk {
				return "", fmt.Errorf("invalid base64")
			}
			result = append(result, (b<<4)|(c>>2))

			if s[i+3] != '=' {
				d, dOk := table[s[i+3]]
				if !dOk {
					return "", fmt.Errorf("invalid base64")
				}
				result = append(result, (c<<6)|d)
			}
		}
	}
	return string(result), nil
}

func isPrintableASCII(s string) bool {
	for _, r := range s {
		if r < 32 || r > 126 {
			return false
		}
	}
	return len(s) > 0
}

func decodeHexEscapes(input string) string {
	hexPattern := regexp.MustCompile(`\\x([0-9a-fA-F]{2})`)
	return hexPattern.ReplaceAllStringFunc(input, func(match string) string {
		hexStr := match[2:]
		val := 0
		for _, c := range hexStr {
			val <<= 4
			switch {
			case c >= '0' && c <= '9':
				val |= int(c - '0')
			case c >= 'a' && c <= 'f':
				val |= int(c-'a') + 10
			case c >= 'A' && c <= 'F':
				val |= int(c-'A') + 10
			}
		}
		if val >= 32 && val <= 126 {
			return string(rune(val))
		}
		return match
	})
}

func decodeUnicodeEscapes(input string) string {
	uniPattern := regexp.MustCompile(`\\u([0-9a-fA-F]{4})`)
	return uniPattern.ReplaceAllStringFunc(input, func(match string) string {
		hexStr := match[2:]
		val := 0
		for _, c := range hexStr {
			val <<= 4
			switch {
			case c >= '0' && c <= '9':
				val |= int(c - '0')
			case c >= 'a' && c <= 'f':
				val |= int(c-'a') + 10
			case c >= 'A' && c <= 'F':
				val |= int(c-'A') + 10
			}
		}
		if val >= 32 && val <= 0xFFFF {
			return string(rune(val))
		}
		return match
	})
}

func removeZeroWidthChars(input string) string {
	var result []rune
	for _, r := range input {
		switch r {
		case '\u200B', '\u200C', '\u200D', '\uFEFF', '\u00AD', '\u2060', '\u180E':
			continue // skip zero-width characters
		default:
			result = append(result, r)
		}
	}
	return string(result)
}

func normalizeSpelledOut(input string) string {
	// Detect patterns like "i-g-n-o-r-e" or "i g n o r e" or "i.g.n.o.r.e"
	spelledPattern := regexp.MustCompile(`\b([a-zA-Z])[\s\-\.]{1,2}([a-zA-Z])[\s\-\.]{1,2}([a-zA-Z])([\s\-\.]{1,2}[a-zA-Z]){2,}`)
	return spelledPattern.ReplaceAllStringFunc(input, func(match string) string {
		var letters []rune
		for _, r := range match {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
				letters = append(letters, r)
			}
		}
		return string(letters)
	})
}

// normalizeLeetspeak converts common leetspeak/homoglyph substitutions back to ASCII.
// Catches: 1gn0r3 -> ignore, 5y5t3m -> system, pr0mpt -> prompt, etc.
// Ref: Mindgard 2025 research on character injection achieving 80%+ bypass rates.
func normalizeLeetspeak(input string) string {
	leetMap := map[rune]rune{
		'0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's',
		'7': 't', '8': 'b', '9': 'g', '@': 'a', '$': 's',
		'!': 'i', '|': 'l',
		// Common homoglyphs (visually similar Unicode chars)
		'\u0430': 'a', // Cyrillic а
		'\u0435': 'e', // Cyrillic е
		'\u043E': 'o', // Cyrillic о
		'\u0440': 'p', // Cyrillic р
		'\u0441': 'c', // Cyrillic с
		'\u0443': 'y', // Cyrillic у
		'\u0445': 'x', // Cyrillic х
		'\u0456': 'i', // Cyrillic і
		'\u0458': 'j', // Cyrillic ј
		'\u0455': 's', // Cyrillic ѕ
		'\u04BB': 'h', // Cyrillic һ
		'\u0501': 'd', // Cyrillic ԁ
		'\u050D': 'k', // Cyrillic ԍ (approx)
		'\u0261': 'g', // Latin small letter script g
		'\uFF41': 'a', // Fullwidth a
		'\uFF42': 'b', // Fullwidth b
		'\uFF43': 'c', // Fullwidth c
		'\uFF44': 'd', // Fullwidth d
		'\uFF45': 'e', // Fullwidth e
	}

	var result []rune
	for _, r := range input {
		if replacement, ok := leetMap[r]; ok {
			result = append(result, replacement)
		} else {
			result = append(result, r)
		}
	}
	return string(result)
}

// normalizeBidiAndDiacritics strips bidirectional override characters and common
// diacritical marks used to evade text classifiers while remaining readable to LLMs.
// Ref: Mindgard 2025 — diacritics and bidi text achieve high attack success rates.
func normalizeBidiAndDiacritics(input string) string {
	var result []rune
	for _, r := range input {
		switch {
		// Bidirectional override/embedding characters
		case r == '\u202A' || r == '\u202B' || r == '\u202C' ||
			r == '\u202D' || r == '\u202E' ||
			r == '\u2066' || r == '\u2067' || r == '\u2068' || r == '\u2069':
			continue
		// Combining diacritical marks (U+0300 to U+036F)
		case r >= '\u0300' && r <= '\u036F':
			continue
		// Combining diacritical marks extended (U+1AB0 to U+1AFF)
		case r >= '\u1AB0' && r <= '\u1AFF':
			continue
		// Combining diacritical marks supplement (U+1DC0 to U+1DFF)
		case r >= '\u1DC0' && r <= '\u1DFF':
			continue
		default:
			result = append(result, r)
		}
	}
	return string(result)
}

func looksLikeROT13(input string) bool {
	// Heuristic: if the input contains words that look like ROT13 of common injection terms
	rot13Indicators := []string{
		"vtaber",    // ignore
		"qvfertneq", // disregard
		"birEevqr",  // override
		"flFgrz",    // system
		"cebzcg",    // prompt
	}
	lower := strings.ToLower(input)
	for _, indicator := range rot13Indicators {
		if strings.Contains(lower, indicator) {
			return true
		}
	}
	return false
}

func decodeROT13(input string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return 'a' + (r-'a'+13)%26
		case r >= 'A' && r <= 'Z':
			return 'A' + (r-'A'+13)%26
		default:
			return r
		}
	}, input)
}

// ============================================================================
// Semantic Structure Analysis
// ============================================================================

// analyzeSemanticStructure detects instruction-like patterns in user input
// that don't match specific regex patterns but have the structural hallmarks
// of prompt injection: imperative sentences, role assignments, output formatting
// directives, etc.
func analyzeSemanticStructure(input string) []InputDetection {
	var detections []InputDetection
	lower := strings.ToLower(input)
	lines := strings.Split(input, "\n")

	// Count instruction-like indicators
	score := 0
	indicators := []string{}

	// Imperative verbs at line starts (instruction-giving pattern)
	imperativeStarts := regexp.MustCompile(`(?im)^\s*(always|never|must|shall|do not|don't|ensure|make sure|remember|from now on|going forward|henceforth)`)
	if imperativeStarts.MatchString(input) {
		score += 2
		indicators = append(indicators, "imperative directives")
	}

	// Output format directives (telling the model HOW to respond)
	formatDirectives := regexp.MustCompile(`(?i)(respond\s+(only\s+)?(with|in|as)|output\s+(only|format)|your\s+(response|output|answer)\s+(should|must|will)\s+be|format\s+your\s+(response|output))`)
	if formatDirectives.MatchString(lower) {
		score++
		indicators = append(indicators, "output format directives")
	}

	// Role/identity assignment
	roleAssignment := regexp.MustCompile(`(?i)(you\s+are\s+(a|an|the|my)|your\s+(role|job|task|purpose|function)\s+(is|will\s+be)|from\s+now\s+on\s+you)`)
	if roleAssignment.MatchString(lower) {
		score += 2
		indicators = append(indicators, "role assignment")
	}

	// Numbered instruction lists (step-by-step injection)
	numberedSteps := 0
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if regexp.MustCompile(`^\d+[\.\)]\s+`).MatchString(trimmed) {
			numberedSteps++
		}
	}
	if numberedSteps >= 3 {
		score++
		indicators = append(indicators, "numbered instruction list")
	}

	// Boundary markers (trying to create a new context)
	boundaryMarkers := regexp.MustCompile(`(?i)(---+|===+|###|~~~|\*\*\*)\s*(new|system|admin|instructions?|context|prompt)`)
	if boundaryMarkers.MatchString(input) {
		score += 3
		indicators = append(indicators, "context boundary markers")
	}

	// Conditional behavior modification
	conditionalMod := regexp.MustCompile(`(?i)(if\s+(anyone|someone|the\s+user|they)\s+asks?|when\s+asked\s+about|if\s+questioned)`)
	if conditionalMod.MatchString(lower) {
		score += 2
		indicators = append(indicators, "conditional behavior modification")
	}

	// Very long input with high instruction density is suspicious
	if len(input) > 500 && score >= 2 {
		score++
	}

	if score >= 4 {
		severity := core.SeverityMedium
		if score >= 6 {
			severity = core.SeverityHigh
		}
		detections = append(detections, InputDetection{
			PatternName: "semantic_injection_structure",
			Category:    "semantic_injection",
			Severity:    severity,
			MatchedText: fmt.Sprintf("instruction-like structure (score: %d, indicators: %s)", score, strings.Join(indicators, ", ")),
		})
	}

	return detections
}

// ============================================================================
// Many-Shot Volume Detection
// ============================================================================

// detectManyShotVolume catches many-shot jailbreaking by counting repeated Q&A-like
// patterns in a single prompt. Attackers flood the context with hundreds of compliant
// examples before appending the malicious query.
// Ref: Anthropic 2024 research, confirmed still effective in 2025-2026.
func detectManyShotVolume(input string) []InputDetection {
	var detections []InputDetection

	// Count Q&A pair patterns
	qaPattern := regexp.MustCompile(`(?im)^(human|user|question|q)\s*:\s*.+$`)
	matches := qaPattern.FindAllString(input, -1)

	if len(matches) >= 10 {
		severity := core.SeverityHigh
		if len(matches) >= 50 {
			severity = core.SeverityCritical
		}
		detections = append(detections, InputDetection{
			PatternName: "many_shot_volume",
			Category:    "many_shot",
			Severity:    severity,
			MatchedText: fmt.Sprintf("%d Q&A-style entries detected in single prompt", len(matches)),
		})
	}

	// Also detect by sheer input length with repetitive structure
	// Many-shot attacks exploit long context windows (100k+ tokens)
	if len(input) > 50000 {
		// Count how many times a similar structure repeats
		linePattern := regexp.MustCompile(`(?m)^(assistant|ai|answer|a)\s*:\s*.+$`)
		answerMatches := linePattern.FindAllString(input, -1)
		if len(answerMatches) >= 10 && len(matches) >= 10 {
			detections = append(detections, InputDetection{
				PatternName: "many_shot_long_context",
				Category:    "many_shot",
				Severity:    core.SeverityCritical,
				MatchedText: fmt.Sprintf("long context (%d chars) with %d Q&A pairs — likely many-shot jailbreak", len(input), len(matches)),
			})
		}
	}

	return detections
}

// ============================================================================
// FlipAttack Detection
// ============================================================================

// detectFlippedText catches FlipAttack by looking for reversed versions of
// dangerous keywords. FlipAttack reverses or flips characters/words so safety
// classifiers can't match them, but LLMs still infer the meaning.
// Ref: ICML 2025 — 81% avg success rate, ~98% on GPT-4o.
func detectFlippedText(input string) []InputDetection {
	var detections []InputDetection
	lower := strings.ToLower(input)

	// Check for reversed dangerous keywords (minimum 5 chars to avoid false positives)
	dangerousWords := []string{
		"ignore", "system", "prompt", "inject", "bypass",
		"override", "disregard", "jailbreak", "unrestricted",
		"malware", "exploit", "credential", "password", "exfiltrate",
		"instruction", "execute", "command", "delete", "destroy",
	}

	reversedCount := 0
	for _, word := range dangerousWords {
		reversed := reverseString(word)
		if strings.Contains(lower, reversed) {
			reversedCount++
		}
	}

	if reversedCount >= 2 {
		detections = append(detections, InputDetection{
			PatternName: "flip_attack_reversed_keywords",
			Category:    "flip_attack",
			Severity:    core.SeverityHigh,
			MatchedText: fmt.Sprintf("%d reversed dangerous keywords detected", reversedCount),
		})
	} else if reversedCount == 1 {
		detections = append(detections, InputDetection{
			PatternName: "flip_attack_reversed_keyword",
			Category:    "flip_attack",
			Severity:    core.SeverityMedium,
			MatchedText: "reversed dangerous keyword detected",
		})
	}

	// Detect TokenBreak pattern: single random char prepended to words
	// "Xhow to Amake a Lbomb" — uppercase letter followed by lowercase word
	tokenBreakPattern := regexp.MustCompile(`\b[A-Z][a-z]{3,}\s+[A-Z][a-z]{3,}\s+[A-Z][a-z]{3,}`)
	tokenBreakMatches := tokenBreakPattern.FindAllString(input, -1)
	if len(tokenBreakMatches) >= 3 {
		detections = append(detections, InputDetection{
			PatternName: "token_break_pattern",
			Category:    "token_manipulation",
			Severity:    core.SeverityHigh,
			MatchedText: fmt.Sprintf("TokenBreak-style character prepending detected (%d occurrences)", len(tokenBreakMatches)),
		})
	}

	return detections
}

func reverseString(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

// ============================================================================
// Tool Chain Analysis (Firewall method)
// ============================================================================

func (f *Firewall) analyzeToolChain(event *core.SecurityEvent) {
	agentID := getStringDetail(event, "agent_id")
	if agentID == "" {
		agentID = event.SourceIP
	}
	if agentID == "" {
		return
	}

	tool := getStringDetail(event, "tool")
	if tool == "" {
		tool = getStringDetail(event, "action")
	}
	target := getStringDetail(event, "target")

	result := f.toolChainMon.RecordAndAnalyze(agentID, tool, target)

	if result.ChainDetected {
		newEvent := core.NewSecurityEvent(ModuleName, "tool_chain_attack", result.Severity,
			fmt.Sprintf("Dangerous tool chain detected: %s (tools: %s)", result.ChainName, strings.Join(result.Tools, " -> ")))
		newEvent.SourceIP = event.SourceIP
		newEvent.Details["original_event_id"] = event.ID
		newEvent.Details["chain_name"] = result.ChainName
		newEvent.Details["agent_id"] = agentID
		newEvent.Details["tool_sequence"] = result.Tools

		if f.bus != nil {
			_ = f.bus.PublishEvent(newEvent)
		}

		alert := core.NewAlert(newEvent,
			fmt.Sprintf("Tool Chain Attack: %s", result.ChainName),
			fmt.Sprintf("Agent %s executed a dangerous tool chain: %s. Individual tools were legitimate but the sequence indicates %s.",
				agentID, strings.Join(result.Tools, " -> "), result.ChainName))
		alert.Mitigations = []string{
			"Implement tool-use policies that consider sequences, not just individual calls",
			"Require human approval for sensitive tool chains",
			"Monitor agent tool usage patterns for anomalies",
			"Sandbox agent file system and network access",
		}

		if f.pipeline != nil {
			f.pipeline.Process(alert)
		}
	}
}
