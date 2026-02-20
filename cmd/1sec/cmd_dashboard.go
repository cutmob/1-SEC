package main

// ---------------------------------------------------------------------------
// cmd_dashboard.go — live TUI dashboard (Recommendation #3)
//
// A lightweight terminal dashboard that polls the 1SEC API and displays
// real-time module status, alert counts, and recent activity. No external
// TUI library required — uses ANSI escape codes for a clean display.
// ---------------------------------------------------------------------------

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func cmdDashboard(args []string) {
	fs := flag.NewFlagSet("dashboard", flag.ExitOnError)
	configPath := fs.String("config", "configs/default.yaml", "Config file path")
	host := fs.String("host", "", "API host override")
	port := fs.Int("port", 0, "API port override")
	apiKeyFlag := fs.String("api-key", "", "API key for authentication")
	refreshStr := fs.String("refresh", "3s", "Refresh interval")
	profileFlag := fs.String("profile", "", "Named profile to use")
	fs.Parse(args)

	*configPath = resolveProfile(*profileFlag, envConfig(*configPath))
	hostVal := envHost(*host)
	portVal := envPort(*port)

	refresh, err := time.ParseDuration(*refreshStr)
	if err != nil {
		errorf("invalid refresh interval %q: %v", *refreshStr, err)
	}

	base := apiBase(*configPath, hostVal, portVal)
	apiKey := resolveAPIKey(*apiKeyFlag, *configPath)
	timeout := 5 * time.Second

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Hide cursor
	fmt.Print("\033[?25l")
	defer fmt.Print("\033[?25h")

	ticker := time.NewTicker(refresh)
	defer ticker.Stop()

	renderDashboard(base, apiKey, timeout)

	for {
		select {
		case <-sigCh:
			clearScreen()
			fmt.Print("\033[?25h")
			fmt.Fprintf(os.Stderr, "%s Dashboard closed.\n", dim("▸"))
			return
		case <-ticker.C:
			renderDashboard(base, apiKey, timeout)
		}
	}
}

func clearScreen() {
	fmt.Print("\033[2J\033[H")
}

func boolStatus(v interface{}) string {
	if b, ok := v.(bool); ok {
		if b {
			return green("connected")
		}
		return red("disconnected")
	}
	return dim(fmt.Sprintf("%v", v))
}

func renderDashboard(base, apiKey string, timeout time.Duration) {
	clearScreen()

	now := time.Now().Format("15:04:05")

	fmt.Printf("  %s  %s  %s\n", bold("1SEC DASHBOARD"), dim("•"), dim(now))
	fmt.Printf("  %s\n\n", dim("Press Ctrl+C to exit"))

	// Fetch status
	statusBody, statusErr := apiGet(base+"/api/v1/status", apiKey, timeout)
	if statusErr != nil {
		fmt.Printf("  %s Cannot connect to 1SEC at %s\n", red("✗"), base)
		fmt.Printf("  %s %v\n\n", dim("▸"), statusErr)
		fmt.Printf("  %s Is the engine running? Try: 1sec up\n", dim("▸"))
		return
	}

	var status map[string]interface{}
	if err := json.Unmarshal(statusBody, &status); err != nil {
		fmt.Printf("  %s Error parsing status: %v\n", red("✗"), err)
		return
	}

	// Engine section
	engineStatus := fmt.Sprintf("%v", status["status"])
	statusColor := green
	if engineStatus != "running" {
		statusColor = yellow
	}

	fmt.Printf("  %s\n", bold("ENGINE"))
	fmt.Printf("  %-20s %s\n", "Status:", statusColor(engineStatus))
	fmt.Printf("  %-20s %v\n", "Version:", status["version"])
	fmt.Printf("  %-20s %v\n", "Bus:", boolStatus(status["bus_connected"]))
	if re, ok := status["rust_engine"].(string); ok {
		reColor := dim
		if re == "running" {
			reColor = green
		}
		fmt.Printf("  %-20s %s\n", "Rust Engine:", reColor(re))
	}
	fmt.Println()

	// Modules section
	if modules, ok := status["modules"].([]interface{}); ok && len(modules) > 0 {
		enabledCount := 0
		for _, m := range modules {
			mod := m.(map[string]interface{})
			if enabled, ok := mod["enabled"].(bool); ok && enabled {
				enabledCount++
			}
		}

		fmt.Printf("  %s  %s\n", bold("MODULES"), dim(fmt.Sprintf("%d/%d active", enabledCount, len(modules))))

		cols := 3
		for i, m := range modules {
			mod := m.(map[string]interface{})
			name := fmt.Sprintf("%v", mod["name"])
			marker := green("●")
			if enabled, ok := mod["enabled"].(bool); ok && !enabled {
				marker = red("○")
				name = dim(name)
			}
			if len(name) > 22 {
				name = name[:19] + "..."
			}
			fmt.Printf("  %s %-22s", marker, name)
			if (i+1)%cols == 0 {
				fmt.Println()
			}
		}
		if len(modules)%cols != 0 {
			fmt.Println()
		}
		fmt.Println()
	}

	// Alerts section
	alertsBody, alertsErr := apiGet(base+"/api/v1/alerts?limit=10", apiKey, timeout)
	if alertsErr == nil {
		var alertResp map[string]interface{}
		if json.Unmarshal(alertsBody, &alertResp) == nil {
			alerts, _ := alertResp["alerts"].([]interface{})
			total := 0
			if t, ok := alertResp["total"].(float64); ok {
				total = int(t)
			}

			sevCounts := map[string]int{}
			for _, a := range alerts {
				alert := a.(map[string]interface{})
				sev := fmt.Sprintf("%v", alert["severity"])
				sevCounts[sev]++
			}

			fmt.Printf("  %s  %s\n", bold("ALERTS"), dim(fmt.Sprintf("%d total", total)))

			if total > 0 {
				parts := make([]string, 0)
				if c := sevCounts["CRITICAL"]; c > 0 {
					parts = append(parts, red(fmt.Sprintf("CRIT:%d", c)))
				}
				if c := sevCounts["HIGH"]; c > 0 {
					parts = append(parts, red(fmt.Sprintf("HIGH:%d", c)))
				}
				if c := sevCounts["MEDIUM"]; c > 0 {
					parts = append(parts, yellow(fmt.Sprintf("MED:%d", c)))
				}
				if c := sevCounts["LOW"]; c > 0 {
					parts = append(parts, cyan(fmt.Sprintf("LOW:%d", c)))
				}
				if c := sevCounts["INFO"]; c > 0 {
					parts = append(parts, dim(fmt.Sprintf("INFO:%d", c)))
				}
				fmt.Printf("  %s\n\n", strings.Join(parts, "  "))

				fmt.Printf("  %s\n", dim("Recent:"))
				shown := 5
				if len(alerts) < shown {
					shown = len(alerts)
				}
				for i := 0; i < shown; i++ {
					alert := alerts[i].(map[string]interface{})
					sev := fmt.Sprintf("%v", alert["severity"])
					sevColor := dim
					switch sev {
					case "CRITICAL", "HIGH":
						sevColor = red
					case "MEDIUM":
						sevColor = yellow
					case "LOW":
						sevColor = cyan
					}
					title := fmt.Sprintf("%v", alert["title"])
					if len(title) > 50 {
						title = title[:47] + "..."
					}
					fmt.Printf("  %s [%-8s] %s\n", sevColor("●"), sev, title)
				}
			} else {
				fmt.Printf("  %s\n", green("No alerts — all clear"))
			}
		}
	}

	// Enforcement section
	enforceBody, enforceErr := apiGet(base+"/api/v1/enforce/status", apiKey, timeout)
	if enforceErr == nil {
		var enforceResp map[string]interface{}
		if json.Unmarshal(enforceBody, &enforceResp) == nil {
			enabled, _ := enforceResp["enabled"].(bool)
			dryRun, _ := enforceResp["dry_run"].(bool)

			fmt.Println()
			fmt.Printf("  %s\n", bold("ENFORCEMENT"))

			if enabled {
				if dryRun {
					fmt.Printf("  %-20s %s\n", "Status:", yellow("DRY RUN"))
				} else {
					fmt.Printf("  %-20s %s\n", "Status:", green("LIVE"))
				}
			} else {
				fmt.Printf("  %-20s %s\n", "Status:", dim("disabled"))
			}

			if stats, ok := enforceResp["stats"].(map[string]interface{}); ok {
				if p, ok := stats["total_policies"].(float64); ok {
					fmt.Printf("  %-20s %d\n", "Policies:", int(p))
				}
				if r, ok := stats["total_records"].(float64); ok && r > 0 {
					fmt.Printf("  %-20s %d\n", "Actions:", int(r))
				}
				if byStatus, ok := stats["by_status"].(map[string]interface{}); ok && len(byStatus) > 0 {
					parts := make([]string, 0)
					for k, v := range byStatus {
						count := int(v.(float64))
						switch k {
						case "SUCCESS":
							parts = append(parts, green(fmt.Sprintf("OK:%d", count)))
						case "FAILED":
							parts = append(parts, red(fmt.Sprintf("FAIL:%d", count)))
						case "DRY_RUN":
							parts = append(parts, yellow(fmt.Sprintf("DRY:%d", count)))
						case "COOLDOWN":
							parts = append(parts, dim(fmt.Sprintf("CD:%d", count)))
						case "SKIPPED":
							parts = append(parts, dim(fmt.Sprintf("SKIP:%d", count)))
						}
					}
					if len(parts) > 0 {
						fmt.Printf("  %-20s %s\n", "Breakdown:", strings.Join(parts, "  "))
					}
				}
			}
		}
	}

	fmt.Printf("\n  %s\n", dim("─────────────────────────────────────────────"))
	fmt.Printf("  %s %s  %s %s\n",
		dim("API:"), base,
		dim("Refresh:"), dim("auto"))
}
