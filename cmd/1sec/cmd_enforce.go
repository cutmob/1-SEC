package main

// ---------------------------------------------------------------------------
// cmd_enforce.go — manage the automated response / enforcement layer
//
// Subcommands:
//   1sec enforce status          — show enforcement engine status & stats
//   1sec enforce policies        — list all response policies
//   1sec enforce history         — show response action history
//   1sec enforce enable <module> — enable enforcement for a module
//   1sec enforce disable <module>— disable enforcement for a module
//   1sec enforce dry-run [on|off]— toggle global dry-run mode
//   1sec enforce test <module>   — simulate an alert and show what would happen
// ---------------------------------------------------------------------------

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/1sec-project/1sec/internal/core"
)

func cmdEnforce(args []string) {
	if len(args) == 0 {
		cmdEnforceUsage()
		os.Exit(0)
	}

	subcmd := args[0]
	subArgs := args[1:]

	switch subcmd {
	case "status":
		cmdEnforceStatus(subArgs)
	case "policies":
		cmdEnforcePolicies(subArgs)
	case "history":
		cmdEnforceHistory(subArgs)
	case "enable":
		cmdEnforceToggle(subArgs, true)
	case "disable":
		cmdEnforceToggle(subArgs, false)
	case "dry-run":
		cmdEnforceDryRun(subArgs)
	case "test":
		cmdEnforceTest(subArgs)
	case "preset":
		cmdEnforcePreset(subArgs)
	case "webhooks":
		cmdEnforceWebhooks(subArgs)
	case "approvals":
		cmdEnforceApprovals(subArgs)
	case "batching":
		cmdEnforceBatching(subArgs)
	case "escalations":
		cmdEnforceEscalations(subArgs)
	case "chains":
		cmdEnforceChains(subArgs)
	default:
		fmt.Fprintf(os.Stderr, red("error: ")+"unknown enforce subcommand %q\n\n", subcmd)
		cmdEnforceUsage()
		os.Exit(1)
	}
}

func cmdEnforceUsage() {
	fmt.Fprintf(os.Stderr, `%s — automated threat response management

%s
  1sec enforce <subcommand> [flags]

%s
  status              Show enforcement engine status and statistics
  policies            List all configured response policies
  history             Show response action execution history
  enable  <module>    Enable enforcement for a specific module
  disable <module>    Disable enforcement for a specific module
  dry-run [on|off]    Toggle global dry-run mode
  test    <module>    Simulate an alert to preview enforcement actions
  preset  <name>      Apply an enforcement preset (lax, balanced, strict)
  webhooks            Webhook dispatcher stats, dead letters, and retry
  approvals           Manage pending human approval gates
  batching            Alert batcher stats and active batches
  escalations         Escalation timer stats and tracked alerts
  chains              Action chain definitions and execution records

%s
  lax        Log and webhook only. Never blocks, kills, or quarantines.
             Safe for initial rollout and auditing.
  balanced   Blocks IPs on HIGH, kills processes on CRITICAL.
             Good default for production environments.
  strict     Aggressive enforcement on MEDIUM+. Short cooldowns,
             high rate limits. For high-security environments.

%s
  --host     API host (default: from config or 127.0.0.1)
  --port     API port (default: from config or 1780)
  --config   Config file path
  --api-key  API key for authentication
  --format   Output format: table, json (default: table)

%s
  1sec enforce status
  1sec enforce policies --format json
  1sec enforce history --limit 20 --module network_guardian
  1sec enforce enable ransomware
  1sec enforce disable auth_fortress
  1sec enforce dry-run on
  1sec enforce test injection_shield
  1sec enforce preset balanced
  1sec enforce preset strict --dry-run
  1sec enforce webhooks stats
  1sec enforce webhooks dead-letters
  1sec enforce webhooks retry <id>
  1sec enforce approvals pending
  1sec enforce approvals approve <id>
  1sec enforce approvals reject <id>
  1sec enforce approvals history
  1sec enforce batching
  1sec enforce escalations
  1sec enforce chains list
  1sec enforce chains records
`,
		bold("1sec enforce"),
		bold("USAGE"),
		bold("SUBCOMMANDS"),
		bold("PRESETS"),
		bold("FLAGS"),
		bold("EXAMPLES"),
	)
}

func cmdEnforceStatus(args []string) {
	fs := flag.NewFlagSet("enforce status", flag.ExitOnError)
	configPath := fs.String("config", "configs/default.yaml", "Config file path")
	host := fs.String("host", "", "API host")
	port := fs.Int("port", 0, "API port")
	apiKey := fs.String("api-key", "", "API key")
	format := fs.String("format", "table", "Output format: table, json")
	fs.Parse(args)

	*configPath = envConfig(*configPath)
	base := apiBase(*configPath, envHost(*host), envPort(*port))
	key := resolveAPIKey(*apiKey, *configPath)

	resp, err := doGet(base+"/api/v1/enforce/status", key)
	if err != nil {
		errorf("fetching enforcement status: %v", err)
	}
	defer resp.Body.Close()

	var data map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&data)

	if parseFormat(*format) == FormatJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(data)
		return
	}

	fmt.Fprintf(os.Stdout, "\n%s\n\n", bold("Enforcement Engine Status"))

	enabled, _ := data["enabled"].(bool)
	dryRun, _ := data["dry_run"].(bool)

	if enabled {
		fmt.Fprintf(os.Stdout, "  Status:    %s\n", green("ACTIVE"))
	} else {
		fmt.Fprintf(os.Stdout, "  Status:    %s\n", red("DISABLED"))
	}

	if dryRun {
		fmt.Fprintf(os.Stdout, "  Mode:      %s\n", yellow("DRY RUN"))
	} else {
		fmt.Fprintf(os.Stdout, "  Mode:      %s\n", green("LIVE"))
	}

	if stats, ok := data["stats"].(map[string]interface{}); ok {
		fmt.Fprintf(os.Stdout, "  Policies:  %v\n", stats["total_policies"])
		fmt.Fprintf(os.Stdout, "  Actions:   %v\n", stats["total_records"])

		if byStatus, ok := stats["by_status"].(map[string]interface{}); ok {
			parts := make([]string, 0)
			for k, v := range byStatus {
				parts = append(parts, fmt.Sprintf("%s=%v", k, v))
			}
			if len(parts) > 0 {
				fmt.Fprintf(os.Stdout, "  Breakdown: %s\n", strings.Join(parts, ", "))
			}
		}
	}
	fmt.Println()
}

func cmdEnforcePolicies(args []string) {
	fs := flag.NewFlagSet("enforce policies", flag.ExitOnError)
	configPath := fs.String("config", "configs/default.yaml", "Config file path")
	host := fs.String("host", "", "API host")
	port := fs.Int("port", 0, "API port")
	apiKey := fs.String("api-key", "", "API key")
	format := fs.String("format", "table", "Output format: table, json")
	fs.Parse(args)

	*configPath = envConfig(*configPath)
	base := apiBase(*configPath, envHost(*host), envPort(*port))
	key := resolveAPIKey(*apiKey, *configPath)

	resp, err := doGet(base+"/api/v1/enforce/policies", key)
	if err != nil {
		errorf("fetching policies: %v", err)
	}
	defer resp.Body.Close()

	var data map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&data)

	if parseFormat(*format) == FormatJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(data)
		return
	}

	policies, _ := data["policies"].(map[string]interface{})
	if len(policies) == 0 {
		fmt.Fprintf(os.Stdout, "\n%s No enforcement policies configured.\n", yellow("⚠"))
		fmt.Fprintf(os.Stdout, "  Add policies to the 'enforcement' section of your config file.\n\n")
		return
	}

	tbl := NewTable(os.Stdout, "MODULE", "ENABLED", "DRY RUN", "MIN SEVERITY", "ACTIONS", "COOLDOWN", "RATE LIMIT")
	for module, policyRaw := range policies {
		p, _ := policyRaw.(map[string]interface{})
		enabled := fmt.Sprintf("%v", p["enabled"])
		dryRun := fmt.Sprintf("%v", p["dry_run"])
		minSev := fmt.Sprintf("%v", p["min_severity"])
		actions, _ := p["actions"].([]interface{})
		actionCount := fmt.Sprintf("%d", len(actions))
		cooldown := fmt.Sprintf("%vs", p["cooldown"])
		rateLimit := fmt.Sprintf("%v/min", p["max_actions_per_min"])

		if enabled == "true" {
			enabled = green("✓")
		} else {
			enabled = red("✗")
		}
		if dryRun == "true" {
			dryRun = yellow("yes")
		} else {
			dryRun = dim("no")
		}

		tbl.AddRow(module, enabled, dryRun, minSev, actionCount, cooldown, rateLimit)
	}
	fmt.Println()
	tbl.Render()
	fmt.Println()
}

func cmdEnforceHistory(args []string) {
	fs := flag.NewFlagSet("enforce history", flag.ExitOnError)
	configPath := fs.String("config", "configs/default.yaml", "Config file path")
	host := fs.String("host", "", "API host")
	port := fs.Int("port", 0, "API port")
	apiKey := fs.String("api-key", "", "API key")
	format := fs.String("format", "table", "Output format: table, json")
	limit := fs.Int("limit", 50, "Max records to show")
	module := fs.String("module", "", "Filter by module name")
	fs.Parse(args)

	*configPath = envConfig(*configPath)
	base := apiBase(*configPath, envHost(*host), envPort(*port))
	key := resolveAPIKey(*apiKey, *configPath)

	url := fmt.Sprintf("%s/api/v1/enforce/history?limit=%d", base, *limit)
	if *module != "" {
		url += "&module=" + *module
	}

	resp, err := doGet(url, key)
	if err != nil {
		errorf("fetching enforcement history: %v", err)
	}
	defer resp.Body.Close()

	var data map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&data)

	if parseFormat(*format) == FormatJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(data)
		return
	}

	records, _ := data["records"].([]interface{})
	if len(records) == 0 {
		fmt.Fprintf(os.Stdout, "\n%s No enforcement actions recorded yet.\n\n", dim("▸"))
		return
	}

	tbl := NewTable(os.Stdout, "TIME", "MODULE", "ACTION", "TARGET", "STATUS", "DURATION", "DETAILS")
	for _, rRaw := range records {
		r, _ := rRaw.(map[string]interface{})
		ts := fmt.Sprintf("%v", r["timestamp"])
		if len(ts) > 19 {
			ts = ts[:19]
		}
		mod := fmt.Sprintf("%v", r["module"])
		action := fmt.Sprintf("%v", r["action"])
		target := fmt.Sprintf("%v", r["target"])
		status := fmt.Sprintf("%v", r["status"])
		dur := fmt.Sprintf("%vms", r["duration_ms"])
		details := fmt.Sprintf("%v", r["details"])
		if len(details) > 50 {
			details = details[:50] + "..."
		}

		switch status {
		case "SUCCESS":
			status = green(status)
		case "FAILED":
			status = red(status)
		case "DRY_RUN":
			status = yellow(status)
		case "COOLDOWN", "SKIPPED":
			status = dim(status)
		}

		tbl.AddRow(ts, mod, action, target, status, dur, details)
	}
	fmt.Println()
	tbl.Render()
	fmt.Println()
}

func cmdEnforceToggle(args []string, enable bool) {
	fs := flag.NewFlagSet("enforce toggle", flag.ExitOnError)
	configPath := fs.String("config", "configs/default.yaml", "Config file path")
	host := fs.String("host", "", "API host")
	port := fs.Int("port", 0, "API port")
	apiKey := fs.String("api-key", "", "API key")
	fs.Parse(args)

	if len(fs.Args()) == 0 {
		errorf("module name required. Usage: 1sec enforce %s <module>",
			map[bool]string{true: "enable", false: "disable"}[enable])
	}

	moduleName := fs.Args()[0]
	*configPath = envConfig(*configPath)
	base := apiBase(*configPath, envHost(*host), envPort(*port))
	key := resolveAPIKey(*apiKey, *configPath)

	action := "enable"
	if !enable {
		action = "disable"
	}

	url := fmt.Sprintf("%s/api/v1/enforce/policies/%s/%s", base, moduleName, action)
	resp, err := doPost(url, key, nil)
	if err != nil {
		errorf("%sing enforcement for %s: %v", action, moduleName, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		if enable {
			fmt.Fprintf(os.Stdout, "%s Enforcement %s for module %s\n", green("✓"), green("enabled"), bold(moduleName))
		} else {
			fmt.Fprintf(os.Stdout, "%s Enforcement %s for module %s\n", green("✓"), red("disabled"), bold(moduleName))
		}
	} else {
		var errData map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&errData)
		errorf("failed: %v", errData["error"])
	}
}

func cmdEnforceDryRun(args []string) {
	fs := flag.NewFlagSet("enforce dry-run", flag.ExitOnError)
	configPath := fs.String("config", "configs/default.yaml", "Config file path")
	host := fs.String("host", "", "API host")
	port := fs.Int("port", 0, "API port")
	apiKey := fs.String("api-key", "", "API key")
	fs.Parse(args)

	if len(fs.Args()) == 0 {
		errorf("specify 'on' or 'off'. Usage: 1sec enforce dry-run [on|off]")
	}

	mode := strings.ToLower(fs.Args()[0])
	if mode != "on" && mode != "off" {
		errorf("invalid mode %q — use 'on' or 'off'", mode)
	}

	*configPath = envConfig(*configPath)
	base := apiBase(*configPath, envHost(*host), envPort(*port))
	key := resolveAPIKey(*apiKey, *configPath)

	url := fmt.Sprintf("%s/api/v1/enforce/dry-run/%s", base, mode)
	resp, err := doPost(url, key, nil)
	if err != nil {
		errorf("setting dry-run mode: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		if mode == "on" {
			fmt.Fprintf(os.Stdout, "%s Global dry-run mode %s — no enforcement actions will be executed\n", green("✓"), yellow("ENABLED"))
		} else {
			fmt.Fprintf(os.Stdout, "%s Global dry-run mode %s — enforcement actions are now LIVE\n", green("✓"), green("DISABLED"))
		}
	} else {
		errorf("failed to set dry-run mode")
	}
}

func cmdEnforceTest(args []string) {
	fs := flag.NewFlagSet("enforce test", flag.ExitOnError)
	configPath := fs.String("config", "configs/default.yaml", "Config file path")
	host := fs.String("host", "", "API host")
	port := fs.Int("port", 0, "API port")
	apiKey := fs.String("api-key", "", "API key")
	severity := fs.String("severity", "HIGH", "Simulated alert severity")
	format := fs.String("format", "table", "Output format: table, json")
	fs.Parse(args)

	if len(fs.Args()) == 0 {
		errorf("module name required. Usage: 1sec enforce test <module> [--severity HIGH]")
	}

	moduleName := fs.Args()[0]
	*configPath = envConfig(*configPath)
	base := apiBase(*configPath, envHost(*host), envPort(*port))
	key := resolveAPIKey(*apiKey, *configPath)

	url := fmt.Sprintf("%s/api/v1/enforce/test/%s?severity=%s", base, moduleName, *severity)
	resp, err := doPost(url, key, nil)
	if err != nil {
		errorf("testing enforcement for %s: %v", moduleName, err)
	}
	defer resp.Body.Close()

	var data map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&data)

	if parseFormat(*format) == FormatJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(data)
		return
	}

	fmt.Fprintf(os.Stdout, "\n%s Enforcement test for module %s (severity=%s)\n\n",
		bold("▸"), bold(moduleName), *severity)

	actions, _ := data["actions"].([]interface{})
	if len(actions) == 0 {
		fmt.Fprintf(os.Stdout, "  %s No actions would be triggered for this severity level.\n\n", yellow("⚠"))
		return
	}

	for i, aRaw := range actions {
		a, _ := aRaw.(map[string]interface{})
		fmt.Fprintf(os.Stdout, "  %d. %s %s\n", i+1, bold(fmt.Sprintf("%v", a["action"])), dim(fmt.Sprintf("(min_severity=%v)", a["min_severity"])))
		if desc, ok := a["description"].(string); ok && desc != "" {
			fmt.Fprintf(os.Stdout, "     %s\n", desc)
		}
		if params, ok := a["params"].(map[string]interface{}); ok && len(params) > 0 {
			for k, v := range params {
				fmt.Fprintf(os.Stdout, "     %s: %v\n", dim(k), v)
			}
		}
	}
	fmt.Println()
}

func cmdEnforcePreset(args []string) {
	fs := flag.NewFlagSet("enforce preset", flag.ExitOnError)
	configPath := fs.String("config", "configs/default.yaml", "Config file path")
	dryRun := fs.Bool("dry-run", false, "Enable dry-run mode with the preset")
	showOnly := fs.Bool("show", false, "Show preset policies without applying")
	format := fs.String("format", "table", "Output format: table, json")
	fs.Parse(args)

	if len(fs.Args()) == 0 {
		fmt.Fprintf(os.Stderr, "%s Available presets:\n\n", bold("1sec enforce preset"))
		fmt.Fprintf(os.Stderr, "  %-12s  %s\n", green("lax"), "Log + webhook only. Safe for initial rollout.")
		fmt.Fprintf(os.Stderr, "  %-12s  %s\n", yellow("balanced"), "Block on HIGH, kill on CRITICAL. Good default.")
		fmt.Fprintf(os.Stderr, "  %-12s  %s\n", red("strict"), "Aggressive enforcement on MEDIUM+. High-security.")
		fmt.Fprintf(os.Stderr, "\nUsage: 1sec enforce preset <lax|balanced|strict> [--dry-run] [--show]\n\n")
		os.Exit(0)
	}

	presetName := strings.ToLower(fs.Args()[0])
	policies := core.GetPresetPolicies(presetName)
	if policies == nil {
		errorf("unknown preset %q — valid presets: lax, balanced, strict", presetName)
	}

	if *showOnly {
		if parseFormat(*format) == FormatJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			enc.Encode(map[string]interface{}{
				"preset":   presetName,
				"policies": policies,
			})
			return
		}

		fmt.Fprintf(os.Stdout, "\n%s preset — %d module policies:\n\n", bold(strings.ToUpper(presetName)), len(policies))
		tbl := NewTable(os.Stdout, "MODULE", "MIN SEVERITY", "ACTIONS", "COOLDOWN", "RATE LIMIT")
		for module, p := range policies {
			actionNames := make([]string, 0, len(p.Actions))
			for _, a := range p.Actions {
				actionNames = append(actionNames, a.Action)
			}
			tbl.AddRow(
				module,
				p.MinSeverity,
				strings.Join(actionNames, ", "),
				fmt.Sprintf("%ds", p.CooldownSeconds),
				fmt.Sprintf("%d/min", p.MaxActionsPerMin),
			)
		}
		tbl.Render()
		fmt.Println()
		return
	}

	// Apply preset to config file
	*configPath = envConfig(*configPath)
	cfg, err := core.LoadConfig(*configPath)
	if err != nil {
		errorf("loading config: %v", err)
	}

	if cfg.Enforcement == nil {
		cfg.Enforcement = &core.EnforcementConfig{}
	}

	cfg.Enforcement.Enabled = true
	cfg.Enforcement.Preset = presetName
	cfg.Enforcement.Policies = policies

	if *dryRun {
		cfg.Enforcement.SetDryRun(true)
	}

	if err := core.SaveConfig(cfg, *configPath); err != nil {
		errorf("saving config: %v", err)
	}

	modeStr := green("LIVE")
	if *dryRun || cfg.Enforcement.GetDryRun() {
		modeStr = yellow("DRY RUN")
	}

	fmt.Fprintf(os.Stdout, "%s Applied %s enforcement preset (%d module policies, mode: %s)\n",
		green("✓"), bold(presetName), len(policies), modeStr)
	fmt.Fprintf(os.Stdout, "%s Config saved to %s\n", dim("▸"), *configPath)

	if presetName == "strict" && !*dryRun {
		fmt.Fprintf(os.Stdout, "\n%s The strict preset enforces aggressively. Consider running with --dry-run first.\n",
			yellow("⚠"))
	}
}

// ---------------------------------------------------------------------------
// Webhook dispatcher subcommands
// ---------------------------------------------------------------------------

func cmdEnforceWebhooks(args []string) {
	if len(args) == 0 {
		// Default to stats
		cmdEnforceWebhooksStats(args)
		return
	}

	switch args[0] {
	case "stats":
		cmdEnforceWebhooksStats(args[1:])
	case "dead-letters":
		cmdEnforceWebhooksDeadLetters(args[1:])
	case "retry":
		cmdEnforceWebhooksRetry(args[1:])
	default:
		fmt.Fprintf(os.Stderr, red("error: ")+"unknown webhooks subcommand %q\n", args[0])
		fmt.Fprintf(os.Stderr, "Usage: 1sec enforce webhooks [stats|dead-letters|retry <id>]\n")
		os.Exit(1)
	}
}

func cmdEnforceWebhooksStats(args []string) {
	fs := flag.NewFlagSet("enforce webhooks stats", flag.ExitOnError)
	configPath := fs.String("config", "configs/default.yaml", "Config file path")
	host := fs.String("host", "", "API host")
	port := fs.Int("port", 0, "API port")
	apiKey := fs.String("api-key", "", "API key")
	format := fs.String("format", "table", "Output format: table, json")
	fs.Parse(args)

	*configPath = envConfig(*configPath)
	base := apiBase(*configPath, envHost(*host), envPort(*port))
	key := resolveAPIKey(*apiKey, *configPath)

	resp, err := doGet(base+"/api/v1/enforce/webhooks/stats", key)
	if err != nil {
		errorf("fetching webhook stats: %v", err)
	}
	defer resp.Body.Close()

	var data map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&data)

	if parseFormat(*format) == FormatJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(data)
		return
	}

	fmt.Fprintf(os.Stdout, "\n%s\n\n", bold("Webhook Dispatcher Stats"))
	fmt.Fprintf(os.Stdout, "  Queue Depth:    %v / %v\n", data["queue_depth"], data["queue_capacity"])
	fmt.Fprintf(os.Stdout, "  Dead Letters:   %v\n", data["dead_letters"])
	fmt.Fprintf(os.Stdout, "  Open Circuits:  %v\n", data["open_circuits"])
	fmt.Fprintf(os.Stdout, "  Workers:        %v\n", data["workers"])
	fmt.Fprintf(os.Stdout, "  Max Retries:    %v\n", data["max_retries"])
	fmt.Println()
}

func cmdEnforceWebhooksDeadLetters(args []string) {
	fs := flag.NewFlagSet("enforce webhooks dead-letters", flag.ExitOnError)
	configPath := fs.String("config", "configs/default.yaml", "Config file path")
	host := fs.String("host", "", "API host")
	port := fs.Int("port", 0, "API port")
	apiKey := fs.String("api-key", "", "API key")
	format := fs.String("format", "table", "Output format: table, json")
	limit := fs.Int("limit", 20, "Max entries to show")
	fs.Parse(args)

	*configPath = envConfig(*configPath)
	base := apiBase(*configPath, envHost(*host), envPort(*port))
	key := resolveAPIKey(*apiKey, *configPath)

	url := fmt.Sprintf("%s/api/v1/enforce/webhooks/dead-letters?limit=%d", base, *limit)
	resp, err := doGet(url, key)
	if err != nil {
		errorf("fetching dead letters: %v", err)
	}
	defer resp.Body.Close()

	var data map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&data)

	if parseFormat(*format) == FormatJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(data)
		return
	}

	entries, _ := data["dead_letters"].([]interface{})
	if len(entries) == 0 {
		fmt.Fprintf(os.Stdout, "\n%s No dead letter entries.\n\n", dim("▸"))
		return
	}

	tbl := NewTable(os.Stdout, "ID", "URL", "ATTEMPTS", "LAST ERROR", "FAILED AT")
	for _, eRaw := range entries {
		e, _ := eRaw.(map[string]interface{})
		delivery, _ := e["delivery"].(map[string]interface{})
		id := fmt.Sprintf("%v", delivery["id"])
		if len(id) > 12 {
			id = id[:12]
		}
		dlURL := fmt.Sprintf("%v", delivery["url"])
		if len(dlURL) > 40 {
			dlURL = dlURL[:40] + "..."
		}
		attempts := fmt.Sprintf("%v", delivery["attempts"])
		lastErr := fmt.Sprintf("%v", e["last_error"])
		if len(lastErr) > 40 {
			lastErr = lastErr[:40] + "..."
		}
		failedAt := fmt.Sprintf("%v", e["failed_at"])
		if len(failedAt) > 19 {
			failedAt = failedAt[:19]
		}
		tbl.AddRow(id, dlURL, attempts, lastErr, failedAt)
	}
	fmt.Println()
	tbl.Render()
	fmt.Println()
}

func cmdEnforceWebhooksRetry(args []string) {
	fs := flag.NewFlagSet("enforce webhooks retry", flag.ExitOnError)
	configPath := fs.String("config", "configs/default.yaml", "Config file path")
	host := fs.String("host", "", "API host")
	port := fs.Int("port", 0, "API port")
	apiKey := fs.String("api-key", "", "API key")
	fs.Parse(args)

	if len(fs.Args()) == 0 {
		errorf("dead letter ID required. Usage: 1sec enforce webhooks retry <id>")
	}

	dlID := fs.Args()[0]
	*configPath = envConfig(*configPath)
	base := apiBase(*configPath, envHost(*host), envPort(*port))
	key := resolveAPIKey(*apiKey, *configPath)

	url := fmt.Sprintf("%s/api/v1/enforce/webhooks/dead-letters/%s/retry", base, dlID)
	resp, err := doPost(url, key, nil)
	if err != nil {
		errorf("retrying dead letter: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		fmt.Fprintf(os.Stdout, "%s Dead letter %s re-enqueued for delivery\n", green("✓"), bold(dlID))
	} else {
		var errData map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&errData)
		errorf("retry failed: %v", errData["error"])
	}
}

// ---------------------------------------------------------------------------
// Approval gate subcommands
// ---------------------------------------------------------------------------

func cmdEnforceApprovals(args []string) {
	if len(args) == 0 {
		cmdEnforceApprovalsPending(args)
		return
	}

	switch args[0] {
	case "pending":
		cmdEnforceApprovalsPending(args[1:])
	case "approve":
		cmdEnforceApprovalsDecide(args[1:], true)
	case "reject":
		cmdEnforceApprovalsDecide(args[1:], false)
	case "history":
		cmdEnforceApprovalsHistory(args[1:])
	default:
		fmt.Fprintf(os.Stderr, red("error: ")+"unknown approvals subcommand %q\n", args[0])
		fmt.Fprintf(os.Stderr, "Usage: 1sec enforce approvals [pending|approve <id>|reject <id>|history]\n")
		os.Exit(1)
	}
}

func cmdEnforceApprovalsPending(args []string) {
	fs := flag.NewFlagSet("enforce approvals pending", flag.ExitOnError)
	configPath := fs.String("config", "configs/default.yaml", "Config file path")
	host := fs.String("host", "", "API host")
	port := fs.Int("port", 0, "API port")
	apiKey := fs.String("api-key", "", "API key")
	format := fs.String("format", "table", "Output format: table, json")
	fs.Parse(args)

	*configPath = envConfig(*configPath)
	base := apiBase(*configPath, envHost(*host), envPort(*port))
	key := resolveAPIKey(*apiKey, *configPath)

	resp, err := doGet(base+"/api/v1/enforce/approvals/pending", key)
	if err != nil {
		errorf("fetching pending approvals: %v", err)
	}
	defer resp.Body.Close()

	var data map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&data)

	if parseFormat(*format) == FormatJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(data)
		return
	}

	pending, _ := data["pending"].([]interface{})
	if len(pending) == 0 {
		fmt.Fprintf(os.Stdout, "\n%s No actions pending approval.\n\n", dim("▸"))
		return
	}

	tbl := NewTable(os.Stdout, "ID", "MODULE", "ACTION", "TARGET", "ALERT", "EXPIRES")
	for _, pRaw := range pending {
		p, _ := pRaw.(map[string]interface{})
		id := fmt.Sprintf("%v", p["id"])
		if len(id) > 12 {
			id = id[:12]
		}
		mod := fmt.Sprintf("%v", p["module"])
		action := fmt.Sprintf("%v", p["action"])
		target := fmt.Sprintf("%v", p["target"])
		alertID := fmt.Sprintf("%v", p["alert_id"])
		if len(alertID) > 12 {
			alertID = alertID[:12]
		}
		expires := fmt.Sprintf("%v", p["expires_at"])
		if len(expires) > 19 {
			expires = expires[:19]
		}
		tbl.AddRow(id, mod, yellow(action), target, alertID, expires)
	}
	fmt.Println()
	fmt.Fprintf(os.Stdout, "%s %d action(s) awaiting human approval:\n\n", yellow("⚠"), len(pending))
	tbl.Render()
	fmt.Fprintf(os.Stdout, "\nApprove: 1sec enforce approvals approve <id>\nReject:  1sec enforce approvals reject <id>\n\n")
}

func cmdEnforceApprovalsDecide(args []string, approve bool) {
	fs := flag.NewFlagSet("enforce approvals decide", flag.ExitOnError)
	configPath := fs.String("config", "configs/default.yaml", "Config file path")
	host := fs.String("host", "", "API host")
	port := fs.Int("port", 0, "API port")
	apiKey := fs.String("api-key", "", "API key")
	decidedBy := fs.String("by", "", "Analyst name/email for audit trail")
	fs.Parse(args)

	action := "approve"
	if !approve {
		action = "reject"
	}

	if len(fs.Args()) == 0 {
		errorf("approval ID required. Usage: 1sec enforce approvals %s <id> [--by analyst@team]", action)
	}

	approvalID := fs.Args()[0]
	*configPath = envConfig(*configPath)
	base := apiBase(*configPath, envHost(*host), envPort(*port))
	key := resolveAPIKey(*apiKey, *configPath)

	var payload []byte
	if *decidedBy != "" {
		payload = []byte(fmt.Sprintf(`{"decided_by":%q}`, *decidedBy))
	}

	url := fmt.Sprintf("%s/api/v1/enforce/approvals/%s/%s", base, approvalID, action)
	resp, err := doPost(url, key, payload)
	if err != nil {
		errorf("%sing approval: %v", action, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		if approve {
			fmt.Fprintf(os.Stdout, "%s Action %s — executing now\n", green("✓ APPROVED"), bold(approvalID))
		} else {
			fmt.Fprintf(os.Stdout, "%s Action %s — blocked\n", red("✗ REJECTED"), bold(approvalID))
		}
	} else {
		var errData map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&errData)
		errorf("failed: %v", errData["error"])
	}
}

func cmdEnforceApprovalsHistory(args []string) {
	fs := flag.NewFlagSet("enforce approvals history", flag.ExitOnError)
	configPath := fs.String("config", "configs/default.yaml", "Config file path")
	host := fs.String("host", "", "API host")
	port := fs.Int("port", 0, "API port")
	apiKey := fs.String("api-key", "", "API key")
	format := fs.String("format", "table", "Output format: table, json")
	limit := fs.Int("limit", 20, "Max entries to show")
	fs.Parse(args)

	*configPath = envConfig(*configPath)
	base := apiBase(*configPath, envHost(*host), envPort(*port))
	key := resolveAPIKey(*apiKey, *configPath)

	url := fmt.Sprintf("%s/api/v1/enforce/approvals/history?limit=%d", base, *limit)
	resp, err := doGet(url, key)
	if err != nil {
		errorf("fetching approval history: %v", err)
	}
	defer resp.Body.Close()

	var data map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&data)

	if parseFormat(*format) == FormatJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(data)
		return
	}

	entries, _ := data["history"].([]interface{})
	if len(entries) == 0 {
		fmt.Fprintf(os.Stdout, "\n%s No approval history yet.\n\n", dim("▸"))
		return
	}

	tbl := NewTable(os.Stdout, "ID", "MODULE", "ACTION", "STATUS", "DECIDED BY", "DECIDED AT")
	for _, eRaw := range entries {
		e, _ := eRaw.(map[string]interface{})
		id := fmt.Sprintf("%v", e["id"])
		if len(id) > 12 {
			id = id[:12]
		}
		mod := fmt.Sprintf("%v", e["module"])
		action := fmt.Sprintf("%v", e["action"])
		status := fmt.Sprintf("%v", e["status"])
		decidedBy := fmt.Sprintf("%v", e["decided_by"])
		decidedAt := fmt.Sprintf("%v", e["decided_at"])
		if len(decidedAt) > 19 {
			decidedAt = decidedAt[:19]
		}

		switch status {
		case "approved":
			status = green(status)
		case "rejected":
			status = red(status)
		case "expired":
			status = yellow(status)
		}

		tbl.AddRow(id, mod, action, status, decidedBy, decidedAt)
	}
	fmt.Println()
	tbl.Render()
	fmt.Println()
}

// ---------------------------------------------------------------------------
// Alert batching subcommand
// ---------------------------------------------------------------------------

func cmdEnforceBatching(args []string) {
	fs := flag.NewFlagSet("enforce batching", flag.ExitOnError)
	configPath := fs.String("config", "configs/default.yaml", "Config file path")
	host := fs.String("host", "", "API host")
	port := fs.Int("port", 0, "API port")
	apiKey := fs.String("api-key", "", "API key")
	format := fs.String("format", "table", "Output format: table, json")
	fs.Parse(args)

	*configPath = envConfig(*configPath)
	base := apiBase(*configPath, envHost(*host), envPort(*port))
	key := resolveAPIKey(*apiKey, *configPath)

	resp, err := doGet(base+"/api/v1/enforce/batching/stats", key)
	if err != nil {
		errorf("fetching batching stats: %v", err)
	}
	defer resp.Body.Close()

	var data map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&data)

	if parseFormat(*format) == FormatJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(data)
		return
	}

	fmt.Fprintf(os.Stdout, "\n%s\n\n", bold("Alert Batcher Stats"))

	enabled, _ := data["enabled"].(bool)
	if enabled {
		fmt.Fprintf(os.Stdout, "  Status:         %s\n", green("ENABLED"))
	} else {
		fmt.Fprintf(os.Stdout, "  Status:         %s\n", red("DISABLED"))
	}
	fmt.Fprintf(os.Stdout, "  Window:         %vs\n", data["window_seconds"])
	fmt.Fprintf(os.Stdout, "  Max Batch Size: %v\n", data["max_batch_size"])
	fmt.Fprintf(os.Stdout, "  Active Batches: %v\n", data["active_batches"])

	batches, _ := data["batches"].([]interface{})
	if len(batches) > 0 {
		fmt.Fprintf(os.Stdout, "\n  %s\n", bold("Active Batches:"))
		for _, bRaw := range batches {
			b, _ := bRaw.(map[string]interface{})
			fmt.Fprintf(os.Stdout, "    %-30s  alerts=%v  highest=%v\n",
				dim(fmt.Sprintf("%v", b["key"])),
				b["alert_count"],
				b["highest_sev"])
		}
	}
	fmt.Println()
}

// ---------------------------------------------------------------------------
// Escalation subcommand
// ---------------------------------------------------------------------------

func cmdEnforceEscalations(args []string) {
	fs := flag.NewFlagSet("enforce escalations", flag.ExitOnError)
	configPath := fs.String("config", "configs/default.yaml", "Config file path")
	host := fs.String("host", "", "API host")
	port := fs.Int("port", 0, "API port")
	apiKey := fs.String("api-key", "", "API key")
	format := fs.String("format", "table", "Output format: table, json")
	fs.Parse(args)

	*configPath = envConfig(*configPath)
	base := apiBase(*configPath, envHost(*host), envPort(*port))
	key := resolveAPIKey(*apiKey, *configPath)

	resp, err := doGet(base+"/api/v1/enforce/escalations/stats", key)
	if err != nil {
		errorf("fetching escalation stats: %v", err)
	}
	defer resp.Body.Close()

	var data map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&data)

	if parseFormat(*format) == FormatJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(data)
		return
	}

	fmt.Fprintf(os.Stdout, "\n%s\n\n", bold("Escalation Manager Stats"))

	enabled, _ := data["enabled"].(bool)
	if enabled {
		fmt.Fprintf(os.Stdout, "  Status:          %s\n", green("ENABLED"))
	} else {
		fmt.Fprintf(os.Stdout, "  Status:          %s\n", red("DISABLED"))
	}
	fmt.Fprintf(os.Stdout, "  Tracked Alerts:  %v\n", data["tracked_alerts"])

	alerts, _ := data["alerts"].([]interface{})
	if len(alerts) > 0 {
		fmt.Fprintf(os.Stdout, "\n  %s\n", bold("Tracked Alerts:"))
		tbl := NewTable(os.Stdout, "ALERT ID", "MODULE", "SEVERITY", "ESCALATIONS")
		for _, aRaw := range alerts {
			a, _ := aRaw.(map[string]interface{})
			id := fmt.Sprintf("%v", a["alert_id"])
			if len(id) > 12 {
				id = id[:12]
			}
			tbl.AddRow(id, fmt.Sprintf("%v", a["module"]), fmt.Sprintf("%v", a["severity"]), fmt.Sprintf("%v", a["escalations"]))
		}
		tbl.Render()
	}
	fmt.Println()
}

// ---------------------------------------------------------------------------
// Action chains subcommands
// ---------------------------------------------------------------------------

func cmdEnforceChains(args []string) {
	if len(args) == 0 {
		cmdEnforceChainsList(args)
		return
	}

	switch args[0] {
	case "list":
		cmdEnforceChainsList(args[1:])
	case "records":
		cmdEnforceChainsRecords(args[1:])
	default:
		fmt.Fprintf(os.Stderr, red("error: ")+"unknown chains subcommand %q\n", args[0])
		fmt.Fprintf(os.Stderr, "Usage: 1sec enforce chains [list|records]\n")
		os.Exit(1)
	}
}

func cmdEnforceChainsList(args []string) {
	fs := flag.NewFlagSet("enforce chains list", flag.ExitOnError)
	configPath := fs.String("config", "configs/default.yaml", "Config file path")
	host := fs.String("host", "", "API host")
	port := fs.Int("port", 0, "API port")
	apiKey := fs.String("api-key", "", "API key")
	format := fs.String("format", "table", "Output format: table, json")
	fs.Parse(args)

	*configPath = envConfig(*configPath)
	base := apiBase(*configPath, envHost(*host), envPort(*port))
	key := resolveAPIKey(*apiKey, *configPath)

	resp, err := doGet(base+"/api/v1/enforce/chains", key)
	if err != nil {
		errorf("fetching action chains: %v", err)
	}
	defer resp.Body.Close()

	var data map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&data)

	if parseFormat(*format) == FormatJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(data)
		return
	}

	chains, _ := data["chains"].(map[string]interface{})
	if len(chains) == 0 {
		fmt.Fprintf(os.Stdout, "\n%s No action chains registered.\n\n", dim("▸"))
		return
	}

	tbl := NewTable(os.Stdout, "NAME", "DESCRIPTION", "STEPS", "ENTRY POINT")
	for name, cRaw := range chains {
		c, _ := cRaw.(map[string]interface{})
		desc := fmt.Sprintf("%v", c["description"])
		if len(desc) > 50 {
			desc = desc[:50] + "..."
		}
		steps, _ := c["steps"].([]interface{})
		entry := fmt.Sprintf("%v", c["entry_point"])
		tbl.AddRow(name, desc, fmt.Sprintf("%d", len(steps)), entry)
	}
	fmt.Println()
	tbl.Render()
	fmt.Println()
}

func cmdEnforceChainsRecords(args []string) {
	fs := flag.NewFlagSet("enforce chains records", flag.ExitOnError)
	configPath := fs.String("config", "configs/default.yaml", "Config file path")
	host := fs.String("host", "", "API host")
	port := fs.Int("port", 0, "API port")
	apiKey := fs.String("api-key", "", "API key")
	format := fs.String("format", "table", "Output format: table, json")
	limit := fs.Int("limit", 20, "Max records to show")
	fs.Parse(args)

	*configPath = envConfig(*configPath)
	base := apiBase(*configPath, envHost(*host), envPort(*port))
	key := resolveAPIKey(*apiKey, *configPath)

	url := fmt.Sprintf("%s/api/v1/enforce/chains/records?limit=%d", base, *limit)
	resp, err := doGet(url, key)
	if err != nil {
		errorf("fetching chain records: %v", err)
	}
	defer resp.Body.Close()

	var data map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&data)

	if parseFormat(*format) == FormatJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(data)
		return
	}

	records, _ := data["records"].([]interface{})
	if len(records) == 0 {
		fmt.Fprintf(os.Stdout, "\n%s No chain execution records yet.\n\n", dim("▸"))
		return
	}

	tbl := NewTable(os.Stdout, "ID", "CHAIN", "ALERT", "STATUS", "STEPS", "STARTED", "DURATION")
	for _, rRaw := range records {
		r, _ := rRaw.(map[string]interface{})
		id := fmt.Sprintf("%v", r["id"])
		if len(id) > 12 {
			id = id[:12]
		}
		chain := fmt.Sprintf("%v", r["chain_name"])
		alertID := fmt.Sprintf("%v", r["alert_id"])
		if len(alertID) > 12 {
			alertID = alertID[:12]
		}
		status := fmt.Sprintf("%v", r["status"])
		steps, _ := r["steps"].([]interface{})
		started := fmt.Sprintf("%v", r["started_at"])
		if len(started) > 19 {
			started = started[:19]
		}
		finished := fmt.Sprintf("%v", r["finished_at"])
		_ = finished // duration calc would need time parsing

		switch status {
		case "completed":
			status = green(status)
		case "partial":
			status = yellow(status)
		case "failed":
			status = red(status)
		}

		tbl.AddRow(id, chain, alertID, status, fmt.Sprintf("%d", len(steps)), started, "—")
	}
	fmt.Println()
	tbl.Render()
	fmt.Println()
}
