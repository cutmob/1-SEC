package main

// ---------------------------------------------------------------------------
// cmd_correlator.go — inspect the threat correlator state
// ---------------------------------------------------------------------------

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"
)

func cmdCorrelator(args []string) {
	fs := flag.NewFlagSet("correlator", flag.ExitOnError)
	configPath := fs.String("config", "configs/default.yaml", "Config file path")
	host := fs.String("host", "", "API host override")
	port := fs.Int("port", 0, "API port override")
	apiKeyFlag := fs.String("api-key", "", "API key for authentication")
	format := fs.String("format", "table", "Output format: table, json")
	jsonOut := fs.Bool("json", false, "Output raw JSON")
	timeoutStr := fs.String("timeout", "5s", "Request timeout")
	profileFlag := fs.String("profile", "", "Named profile to use")
	fs.Parse(args)

	*configPath = resolveProfile(*profileFlag, envConfig(*configPath))
	hostVal := envHost(*host)
	portVal := envPort(*port)

	if *jsonOut {
		*format = "json"
	}
	outFmt := parseFormat(*format)

	timeout, err := time.ParseDuration(*timeoutStr)
	if err != nil {
		errorf("invalid timeout %q: %v", *timeoutStr, err)
	}

	base := apiBase(*configPath, hostVal, portVal)
	apiKey := resolveAPIKey(*apiKeyFlag, *configPath)
	body, err := apiGet(base+"/api/v1/correlator", apiKey, timeout)
	if err != nil {
		errorf("%v", err)
	}

	if outFmt == FormatJSON {
		fmt.Println(string(body))
		return
	}

	var status map[string]interface{}
	if err := json.Unmarshal(body, &status); err != nil {
		errorf("parsing response: %v", err)
	}

	fmt.Printf("%s Threat Correlator\n\n", bold("🔗"))
	fmt.Printf("  %-20s %v\n", "Active Sources:", status["active_sources"])
	fmt.Printf("  %-20s %v min\n", "Window:", status["window_minutes"])
	fmt.Printf("  %-20s %v\n", "Chain Definitions:", status["chain_count"])

	// Show attack chain definitions
	if chains, ok := status["chains"].([]interface{}); ok && len(chains) > 0 {
		fmt.Printf("\n  %s\n", bold("Attack Chains:"))
		for _, c := range chains {
			chain := c.(map[string]interface{})
			sev := fmt.Sprintf("%v", chain["severity"])
			sevColor := dim
			switch sev {
			case "CRITICAL", "HIGH":
				sevColor = red
			case "MEDIUM":
				sevColor = yellow
			}
			fmt.Printf("    %s [%s] %s\n", sevColor("●"), sev, chain["name"])
			if desc, ok := chain["description"]; ok {
				fmt.Printf("      %s\n", dim(fmt.Sprintf("%v", desc)))
			}
		}
	}

	// Show active source windows
	if sources, ok := status["sources"].([]interface{}); ok && len(sources) > 0 {
		fmt.Printf("\n  %s\n", bold("Active Source Windows:"))
		tbl := NewTable(os.Stdout, "IP", "ALERTS", "MODULES", "LAST SEEN")
		for _, s := range sources {
			src := s.(map[string]interface{})
			modules := src["modules"].(map[string]interface{})
			moduleNames := make([]string, 0)
			for k := range modules {
				moduleNames = append(moduleNames, k)
			}
			tbl.AddRow(
				fmt.Sprintf("%v", src["ip"]),
				fmt.Sprintf("%v", src["alert_count"]),
				fmt.Sprintf("%d (%s)", len(moduleNames), truncateList(moduleNames, 3)),
				fmt.Sprintf("%v", src["last_seen"]),
			)
		}
		tbl.Render()
	} else {
		fmt.Printf("\n  %s No active correlation windows.\n", green("✓"))
	}
	fmt.Println()
}

func truncateList(items []string, max int) string {
	if len(items) <= max {
		return joinStrings(items, ", ")
	}
	return joinStrings(items[:max], ", ") + fmt.Sprintf(" +%d", len(items)-max)
}

func joinStrings(items []string, sep string) string {
	result := ""
	for i, item := range items {
		if i > 0 {
			result += sep
		}
		result += item
	}
	return result
}
