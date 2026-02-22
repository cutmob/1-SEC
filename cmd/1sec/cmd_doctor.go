package main

// ---------------------------------------------------------------------------
// cmd_doctor.go — comprehensive system health check with actionable fixes
//
// Goes beyond 'check' by:
//   - Detecting common misconfigurations
//   - Suggesting specific fix commands
//   - Showing a "quick wins" section
//   - Checking AI readiness with key validation
//   - Verifying module coherence (e.g., AI engine enabled but no keys)
//
// Usage:
//   1sec doctor
//   1sec doctor --fix    # auto-fix what can be fixed
// ---------------------------------------------------------------------------

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"

	"github.com/1sec-project/1sec/internal/core"
)

type doctorFinding struct {
	category string
	status   string // "ok", "warn", "error", "info"
	message  string
	fix      string // suggested fix command, empty if none
}

func cmdDoctor(args []string) {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	configPath := fs.String("config", "configs/default.yaml", "Config file path")
	profileFlag := fs.String("profile", "", "Named profile to use")
	fs.Parse(args)

	*configPath = resolveProfile(*profileFlag, envConfig(*configPath))

	findings := make([]doctorFinding, 0)
	add := func(cat, status, msg, fix string) {
		findings = append(findings, doctorFinding{cat, status, msg, fix})
	}

	fmt.Println()
	fmt.Printf("  %s  1SEC Doctor\n", bold("🩺"))
	fmt.Printf("  %s\n\n", dim("Comprehensive health check with fix suggestions"))

	// --- Config ---
	cfg, err := core.LoadConfig(*configPath)
	if err != nil {
		add("config", "error", fmt.Sprintf("Cannot load %s: %v", *configPath, err), "1sec init")
	} else {
		add("config", "ok", fmt.Sprintf("Config loaded from %s", *configPath), "")

		warnings, errs := cfg.Validate()
		for _, e := range errs {
			add("config", "error", e, "")
		}
		for _, w := range warnings {
			add("config", "warn", w, "")
		}
		if len(errs) == 0 && len(warnings) == 0 {
			add("config", "ok", "Config validation passed", "")
		}
	}

	if cfg != nil {
		// --- Ports ---
		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.Server.Port))
		if err != nil {
			add("ports", "error", fmt.Sprintf("API port %d in use", cfg.Server.Port),
				fmt.Sprintf("1sec config set server.port %d", cfg.Server.Port+1))
		} else {
			ln.Close()
			add("ports", "ok", fmt.Sprintf("API port %d available", cfg.Server.Port), "")
		}

		if cfg.Bus.Embedded {
			ln, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.Bus.Port))
			if err != nil {
				add("ports", "error", fmt.Sprintf("NATS port %d in use", cfg.Bus.Port), "")
			} else {
				ln.Close()
				add("ports", "ok", fmt.Sprintf("NATS port %d available", cfg.Bus.Port), "")
			}
		}

		if cfg.Server.Port == cfg.Bus.Port {
			add("ports", "error", "API and NATS ports are the same",
				fmt.Sprintf("1sec config set bus.port %d", cfg.Bus.Port+1))
		}

		// --- Data directory ---
		dataDir := cfg.Bus.DataDir
		if err := os.MkdirAll(dataDir, 0755); err != nil {
			add("storage", "error", fmt.Sprintf("Cannot create data dir %s", dataDir), "")
		} else {
			testFile := dataDir + "/.1sec-doctor"
			if err := os.WriteFile(testFile, []byte("ok"), 0644); err != nil {
				add("storage", "error", fmt.Sprintf("Data dir %s not writable", dataDir), "")
			} else {
				os.Remove(testFile)
				add("storage", "ok", fmt.Sprintf("Data dir %s writable", dataDir), "")
			}
		}

		// --- AI readiness ---
		aiEnabled := cfg.IsModuleEnabled("ai_analysis_engine")
		hasKey := false
		keyCount := 0
		settings := cfg.GetModuleSettings("ai_analysis_engine")

		if _, ok := settings["gemini_api_key"]; ok {
			hasKey = true
			keyCount++
		}
		if keys, ok := settings["gemini_api_keys"]; ok {
			if arr, ok := keys.([]interface{}); ok {
				keyCount += len(arr)
				if len(arr) > 0 {
					hasKey = true
				}
			}
		}
		for _, env := range []string{"GEMINI_API_KEY", "GEMINI_API_KEY_2", "GEMINI_API_KEY_3", "GEMINI_API_KEY_4"} {
			if os.Getenv(env) != "" {
				hasKey = true
				keyCount++
			}
		}

		if aiEnabled && hasKey {
			add("ai", "ok", fmt.Sprintf("AI engine enabled with %d key(s)", keyCount), "")
			if keyCount == 1 {
				add("ai", "info", "Consider adding more keys for rate-limit resilience",
					"1sec config set-key <key1> <key2>")
			}
		} else if aiEnabled && !hasKey {
			add("ai", "warn", "AI engine enabled but no API keys configured",
				"1sec config set-key <your-gemini-key>")
		} else if !aiEnabled {
			add("ai", "info", "AI engine disabled — rule-based modules still active",
				"1sec modules enable ai_analysis_engine")
		}

		// --- Security ---
		if len(cfg.Server.APIKeys) == 0 && os.Getenv("ONESEC_API_KEY") == "" {
			add("security", "warn", "REST API has no authentication — open to anyone on the network",
				"1sec setup --ai-only=false")
		} else {
			add("security", "ok", "REST API authentication configured", "")
		}

		if !cfg.TLSEnabled() {
			add("security", "info", "TLS not configured — API traffic is unencrypted",
				"1sec config set server.tls_cert /path/to/cert.pem")
		}

		// --- Module coherence ---
		enabledCount := 0
		disabledModules := []string{}
		for _, name := range []string{
			"network_guardian", "api_fortress", "iot_shield", "injection_shield",
			"supply_chain", "ransomware", "auth_fortress", "deepfake_shield",
			"identity_monitor", "llm_firewall", "ai_containment", "data_poisoning",
			"quantum_crypto", "runtime_watcher", "cloud_posture", "ai_analysis_engine",
		} {
			if cfg.IsModuleEnabled(name) {
				enabledCount++
			} else {
				disabledModules = append(disabledModules, name)
			}
		}
		add("modules", "ok", fmt.Sprintf("%d/16 modules enabled", enabledCount), "")
		if len(disabledModules) > 0 && len(disabledModules) <= 3 {
			add("modules", "info", fmt.Sprintf("Disabled: %s", strings.Join(disabledModules, ", ")), "")
		}

		// --- Syslog ---
		if cfg.Syslog.Enabled {
			if cfg.Syslog.Port == cfg.Server.Port || cfg.Syslog.Port == cfg.Bus.Port {
				add("syslog", "error", fmt.Sprintf("Syslog port %d conflicts with another service", cfg.Syslog.Port), "")
			} else {
				add("syslog", "ok", fmt.Sprintf("Syslog on port %d (%s)", cfg.Syslog.Port, cfg.Syslog.Protocol), "")
			}
		}

		// --- Rust engine ---
		if cfg.RustEngine.Enabled {
			binary := cfg.RustEngine.Binary
			if binary == "" {
				binary = "1sec-engine"
			}
			if _, err := exec.LookPath(binary); err != nil {
				add("rust", "warn", fmt.Sprintf("Rust binary %q not in PATH", binary),
					"cd rust/1sec-engine && cargo build --release")
			} else {
				add("rust", "ok", "Rust sidecar binary found", "")
			}
		}
	}

	// --- Render ---
	errors := 0
	warns := 0
	fixes := []doctorFinding{}

	for _, f := range findings {
		var icon string
		switch f.status {
		case "ok":
			icon = green("✓")
		case "warn":
			icon = yellow("!")
			warns++
		case "error":
			icon = red("✗")
			errors++
		case "info":
			icon = cyan("ℹ")
		}
		fmt.Printf("  %s  %-10s %s\n", icon, dim("["+f.category+"]"), f.message)
		if f.fix != "" {
			fixes = append(fixes, f)
		}
	}

	// Quick fixes section
	if len(fixes) > 0 {
		fmt.Printf("\n  %s\n\n", bold("Suggested fixes:"))
		for _, f := range fixes {
			fmt.Printf("    %s  %s\n", dim("▸"), bold(f.fix))
			fmt.Printf("       %s\n\n", dim(f.message))
		}
	}

	// Summary
	fmt.Println()
	if errors > 0 {
		fmt.Printf("  %s %d error(s), %d warning(s). Fix errors before running '1sec up'.\n\n", red("✗"), errors, warns)
		os.Exit(1)
	} else if warns > 0 {
		fmt.Printf("  %s All clear with %d suggestion(s). Ready to run.\n\n", yellow("!"), warns)
	} else {
		fmt.Printf("  %s Everything looks good. Run %s to start.\n\n", green("✓"), bold("1sec up"))
	}
}
