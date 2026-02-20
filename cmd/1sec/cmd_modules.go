package main

// ---------------------------------------------------------------------------
// cmd_modules.go — list/inspect/enable/disable defense modules
// ---------------------------------------------------------------------------

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/1sec-project/1sec/internal/core"
)

type moduleInfo struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Tier        int      `json:"tier"`
	TierName    string   `json:"tier_name"`
	EventTypes  []string `json:"event_types,omitempty"`
}

var allModules = []moduleInfo{
	{"network_guardian", "DDoS mitigation, rate limiting, IP reputation, geo-fencing, DNS tunneling, C2 detection, lateral movement, port scan detection", 1, "Network & Perimeter",
		[]string{"dns_query", "dns_response", "network_connection", "connection_established", "lateral_movement", "smb_connection", "rdp_connection", "port_scan", "syn_scan", "amplification_attack"}},
	{"api_fortress", "BOLA detection, schema validation, shadow API discovery", 1, "Network & Perimeter",
		[]string{"api_request", "api_response", "schema_violation"}},
	{"iot_shield", "Device fingerprinting, protocol anomaly, firmware integrity", 1, "Network & Perimeter",
		[]string{"device_connect", "firmware_update", "protocol_anomaly"}},
	{"injection_shield", "SQLi, XSS, SSRF, command injection, template injection, NoSQL injection, path traversal", 2, "Application Layer",
		[]string{"http_request", "query_exec", "command_exec", "template_render"}},
	{"supply_chain", "SBOM analysis, package integrity, CI/CD hardening, typosquatting detection", 2, "Application Layer",
		[]string{"package_install", "dependency_update", "ci_pipeline", "sbom_scan"}},
	{"ransomware", "Encryption detection, canary files, exfiltration detection", 2, "Application Layer",
		[]string{"file_encrypt", "file_modify", "process_exec", "data_exfil"}},
	{"auth_fortress", "Brute force, credential stuffing, session theft, impossible travel, MFA bypass, password spraying, OAuth token abuse", 3, "Identity & Access",
		[]string{"login_attempt", "login_success", "login_failure", "session_activity", "mfa_attempt", "oauth_grant", "password_spray"}},
	{"deepfake_shield", "Synthetic voice/video detection, AI phishing detection", 3, "Identity & Access",
		[]string{"media_upload", "voice_call", "video_stream", "email_received"}},
	{"identity_monitor", "Synthetic identity, privilege escalation, service account monitoring", 3, "Identity & Access",
		[]string{"identity_create", "privilege_change", "service_account_activity"}},
	{"llm_firewall", "Prompt injection, output filtering, jailbreak detection", 4, "AI-Specific Defense",
		[]string{"llm_prompt", "llm_response", "prompt_injection", "jailbreak_attempt"}},
	{"ai_containment", "Action sandboxing, shadow AI detection", 4, "AI-Specific Defense",
		[]string{"ai_action", "model_deploy", "shadow_ai_detected"}},
	{"data_poisoning", "Training data integrity, RAG verification, adversarial input detection", 4, "AI-Specific Defense",
		[]string{"training_data", "rag_query", "adversarial_input"}},
	{"quantum_crypto", "Crypto inventory, PQC migration readiness, crypto-agility", 5, "Cryptography",
		[]string{"crypto_operation", "certificate_issue", "key_exchange"}},
	{"runtime_watcher", "File integrity, container escape, privilege escalation detection", 6, "Runtime & Infrastructure",
		[]string{"file_change", "container_event", "privilege_escalation", "process_exec"}},
	{"cloud_posture", "Config drift, misconfiguration, secrets sprawl detection", 6, "Runtime & Infrastructure",
		[]string{"config_change", "secret_detected", "misconfiguration"}},
	{"ai_analysis_engine", "Two-tier LLM pipeline: triage + deep classification", 0, "Cross-Cutting",
		[]string{"*"}},
}

func cmdModules(args []string) {
	if len(args) > 0 {
		switch args[0] {
		case "info":
			cmdModulesInfo(args[1:])
			return
		case "enable":
			cmdModulesToggle(args[1:], true)
			return
		case "disable":
			cmdModulesToggle(args[1:], false)
			return
		}
	}

	fs := flag.NewFlagSet("modules", flag.ExitOnError)
	format := fs.String("format", "table", "Output format: table, json, csv")
	jsonOut := fs.Bool("json", false, "Output as JSON")
	tier := fs.Int("tier", 0, "Filter by tier (1-6)")
	fs.Parse(args)

	if *jsonOut {
		*format = "json"
	}
	outFmt := parseFormat(*format)

	filtered := allModules
	if *tier > 0 {
		filtered = make([]moduleInfo, 0)
		for _, m := range allModules {
			if m.Tier == *tier {
				filtered = append(filtered, m)
			}
		}
	}

	switch outFmt {
	case FormatJSON:
		data, _ := json.MarshalIndent(map[string]interface{}{
			"modules": filtered,
			"total":   len(filtered),
		}, "", "  ")
		fmt.Println(string(data))
		return
	case FormatCSV:
		headers := []string{"name", "tier", "tier_name", "description"}
		rows := make([][]string, 0, len(filtered))
		for _, m := range filtered {
			rows = append(rows, []string{
				m.Name,
				fmt.Sprintf("%d", m.Tier),
				m.TierName,
				m.Description,
			})
		}
		writeCSV(os.Stdout, headers, rows)
		return
	}

	// Table (default) — grouped by tier
	fmt.Printf("%s Defense Modules (%d)\n\n", bold("🛡"), len(filtered))

	tbl := NewTable(os.Stdout, "MODULE", "TIER", "CATEGORY", "DESCRIPTION")
	for _, m := range filtered {
		tierStr := fmt.Sprintf("%d", m.Tier)
		if m.Tier == 0 {
			tierStr = "-"
		}
		desc := m.Description
		if len(desc) > 60 {
			desc = desc[:57] + "..."
		}
		tbl.AddRow(m.Name, tierStr, m.TierName, desc)
	}
	tbl.Render()
	fmt.Println()
}

func cmdModulesInfo(args []string) {
	fs := flag.NewFlagSet("modules-info", flag.ExitOnError)
	configPath := fs.String("config", "configs/default.yaml", "Config file path")
	format := fs.String("format", "table", "Output format: table, json")
	jsonOut := fs.Bool("json", false, "Output as JSON")
	profileFlag := fs.String("profile", "", "Named profile to use")
	fs.Parse(args)

	*configPath = resolveProfile(*profileFlag, envConfig(*configPath))

	if *jsonOut {
		*format = "json"
	}

	remaining := fs.Args()
	if len(remaining) == 0 {
		errorf("module name required — usage: 1sec modules info <name>")
	}
	name := remaining[0]

	var found *moduleInfo
	for i := range allModules {
		if allModules[i].Name == name {
			found = &allModules[i]
			break
		}
	}
	if found == nil {
		errorf("unknown module %q — run '1sec modules' to see all available modules", name)
	}

	cfg, _ := core.LoadConfig(*configPath)
	enabled := true
	var settings map[string]interface{}
	if cfg != nil {
		enabled = cfg.IsModuleEnabled(name)
		settings = cfg.GetModuleSettings(name)
	}

	if parseFormat(*format) == FormatJSON {
		data, _ := json.MarshalIndent(map[string]interface{}{
			"name":        found.Name,
			"description": found.Description,
			"tier":        found.Tier,
			"tier_name":   found.TierName,
			"event_types": found.EventTypes,
			"enabled":     enabled,
			"settings":    settings,
		}, "", "  ")
		fmt.Println(string(data))
		return
	}

	statusIcon := green("●")
	statusText := green("enabled")
	if !enabled {
		statusIcon = red("○")
		statusText = red("disabled")
	}

	fmt.Printf("%s Module: %s\n\n", bold("🛡"), bold(found.Name))
	fmt.Printf("  %-16s %s\n", "Description:", found.Description)
	if found.Tier > 0 {
		fmt.Printf("  %-16s Tier %d: %s\n", "Tier:", found.Tier, found.TierName)
	} else {
		fmt.Printf("  %-16s %s\n", "Tier:", found.TierName)
	}
	fmt.Printf("  %-16s %s %s\n", "Status:", statusIcon, statusText)

	if len(found.EventTypes) > 0 {
		fmt.Printf("  %-16s %s\n", "Event Types:", strings.Join(found.EventTypes, ", "))
	}

	if len(settings) > 0 {
		fmt.Printf("\n  %s\n", bold("Settings:"))
		for k, v := range settings {
			fmt.Printf("    %-32s %v\n", k+":", v)
		}
	}
	fmt.Println()
}

func cmdModulesToggle(args []string, enable bool) {
	fs := flag.NewFlagSet("modules-toggle", flag.ExitOnError)
	configPath := fs.String("config", "configs/default.yaml", "Config file path")
	profileFlag := fs.String("profile", "", "Named profile to use")
	fs.Parse(args)

	*configPath = resolveProfile(*profileFlag, envConfig(*configPath))

	remaining := fs.Args()
	if len(remaining) == 0 {
		action := "enable"
		if !enable {
			action = "disable"
		}
		errorf("module name required — usage: 1sec modules %s <name>", action)
	}
	name := remaining[0]

	validModule := false
	for _, m := range allModules {
		if m.Name == name {
			validModule = true
			break
		}
	}
	if !validModule {
		errorf("unknown module %q — run '1sec modules' to see all available modules", name)
	}

	cfg, err := core.LoadConfig(*configPath)
	if err != nil {
		errorf("loading config: %v", err)
	}

	mod, ok := cfg.Modules[name]
	if !ok {
		mod = core.ModuleConfig{Settings: map[string]interface{}{}}
	}
	mod.Enabled = enable
	cfg.Modules[name] = mod

	if err := core.SaveConfig(cfg, *configPath); err != nil {
		errorf("saving config: %v", err)
	}

	action := "enabled"
	icon := green("✓")
	if !enable {
		action = "disabled"
		icon = yellow("!")
	}
	fmt.Fprintf(os.Stdout, "%s Module %s %s in %s\n", icon, bold(name), action, *configPath)
}
