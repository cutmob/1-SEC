package main

// ---------------------------------------------------------------------------
// cmd_alerts.go — fetch/manage alerts from a running instance
// ---------------------------------------------------------------------------

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

func cmdAlerts(args []string) {
	if len(args) > 0 {
		switch args[0] {
		case "ack", "acknowledge":
			cmdAlertsUpdateStatus(args[1:], "ACKNOWLEDGED")
			return
		case "resolve":
			cmdAlertsUpdateStatus(args[1:], "RESOLVED")
			return
		case "false-positive":
			cmdAlertsUpdateStatus(args[1:], "FALSE_POSITIVE")
			return
		case "get":
			cmdAlertsGet(args[1:])
			return
		case "clear":
			cmdAlertsClear(args[1:])
			return
		}
	}

	fs := flag.NewFlagSet("alerts", flag.ExitOnError)
	configPath := fs.String("config", "configs/default.yaml", "Config file path")
	host := fs.String("host", "", "API host override")
	port := fs.Int("port", 0, "API port override")
	apiKeyFlag := fs.String("api-key", "", "API key for authentication")
	severity := fs.String("severity", "", "Minimum severity: INFO, LOW, MEDIUM, HIGH, CRITICAL")
	module := fs.String("module", "", "Filter by source module")
	statusFilter := fs.String("status", "", "Filter by status: OPEN, ACKNOWLEDGED, RESOLVED, FALSE_POSITIVE")
	limit := fs.Int("limit", 20, "Maximum alerts to fetch")
	format := fs.String("format", "table", "Output format: table, json, csv, sarif")
	jsonOut := fs.Bool("json", false, "Output raw JSON (shorthand for --format json)")
	output := fs.String("output", "", "Write output to file")
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
	url := fmt.Sprintf("%s/api/v1/alerts?limit=%d", base, *limit)
	if *severity != "" {
		url += "&min_severity=" + strings.ToUpper(*severity)
	}

	body, err := apiGet(url, apiKey, timeout)
	if err != nil {
		errorf("%v", err)
	}

	w, cleanup := outputWriter(*output)
	defer cleanup()

	var resp map[string]interface{}
	if err := json.Unmarshal(body, &resp); err != nil {
		errorf("parsing response: %v", err)
	}

	alerts, _ := resp["alerts"].([]interface{})
	if *module != "" || *statusFilter != "" {
		filtered := make([]interface{}, 0)
		for _, a := range alerts {
			alert := a.(map[string]interface{})
			if *module != "" && fmt.Sprintf("%v", alert["module"]) != *module {
				continue
			}
			if *statusFilter != "" && !strings.EqualFold(fmt.Sprintf("%v", alert["status"]), *statusFilter) {
				continue
			}
			filtered = append(filtered, a)
		}
		alerts = filtered
		resp["alerts"] = alerts
		resp["total"] = len(alerts)
	}

	switch outFmt {
	case FormatJSON:
		data, _ := json.MarshalIndent(resp, "", "  ")
		fmt.Fprintln(w, string(data))
		return
	case FormatSARIF:
		writeSARIF(w, alerts, version)
		return
	case FormatCSV:
		headers := []string{"id", "severity", "status", "module", "type", "title", "timestamp"}
		rows := make([][]string, 0, len(alerts))
		for _, a := range alerts {
			alert := a.(map[string]interface{})
			rows = append(rows, []string{
				fmt.Sprintf("%v", alert["id"]),
				fmt.Sprintf("%v", alert["severity"]),
				fmt.Sprintf("%v", alert["status"]),
				fmt.Sprintf("%v", alert["module"]),
				fmt.Sprintf("%v", alert["type"]),
				fmt.Sprintf("%v", alert["title"]),
				fmt.Sprintf("%v", alert["timestamp"]),
			})
		}
		writeCSV(w, headers, rows)
		return
	}

	// Table (default)
	if len(alerts) == 0 {
		fmt.Fprintf(w, "%s No alerts found.\n", dim("▸"))
		return
	}

	fmt.Fprintf(w, "%s Alerts (%d)\n\n", bold("🔔"), len(alerts))

	tbl := NewTable(w, "SEVERITY", "STATUS", "MODULE", "TYPE", "TITLE", "ID")
	for _, a := range alerts {
		alert := a.(map[string]interface{})
		tbl.AddRow(
			fmt.Sprintf("%v", alert["severity"]),
			fmt.Sprintf("%v", alert["status"]),
			fmt.Sprintf("%v", alert["module"]),
			fmt.Sprintf("%v", alert["type"]),
			fmt.Sprintf("%v", alert["title"]),
			fmt.Sprintf("%v", alert["id"]),
		)
	}
	tbl.Render()
	fmt.Fprintln(w)
}

func cmdAlertsUpdateStatus(args []string, status string) {
	fs := flag.NewFlagSet("alerts-status", flag.ExitOnError)
	configPath := fs.String("config", "configs/default.yaml", "Config file path")
	host := fs.String("host", "", "API host override")
	port := fs.Int("port", 0, "API port override")
	apiKeyFlag := fs.String("api-key", "", "API key for authentication")
	jsonOut := fs.Bool("json", false, "Output raw JSON")
	timeoutStr := fs.String("timeout", "5s", "Request timeout")
	profileFlag := fs.String("profile", "", "Named profile to use")
	fs.Parse(args)

	*configPath = resolveProfile(*profileFlag, envConfig(*configPath))

	remaining := fs.Args()
	if len(remaining) == 0 {
		errorf("alert ID required — usage: 1sec alerts %s <alert-id>", strings.ToLower(status))
	}
	alertID := remaining[0]

	timeout, err := time.ParseDuration(*timeoutStr)
	if err != nil {
		errorf("invalid timeout %q: %v", *timeoutStr, err)
	}

	base := apiBase(*configPath, envHost(*host), envPort(*port))
	apiKey := resolveAPIKey(*apiKeyFlag, *configPath)
	payload, _ := json.Marshal(map[string]string{"status": status})
	body, err := apiPatch(fmt.Sprintf("%s/api/v1/alerts/%s", base, alertID), payload, apiKey, timeout)
	if err != nil {
		errorf("%v", err)
	}

	if *jsonOut {
		fmt.Println(string(body))
		return
	}

	fmt.Fprintf(os.Stdout, "%s Alert %s marked as %s\n", green("✓"), alertID, status)
}

func cmdAlertsGet(args []string) {
	fs := flag.NewFlagSet("alerts-get", flag.ExitOnError)
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

	if *jsonOut {
		*format = "json"
	}

	remaining := fs.Args()
	if len(remaining) == 0 {
		errorf("alert ID required — usage: 1sec alerts get <alert-id>")
	}
	alertID := remaining[0]

	timeout, err := time.ParseDuration(*timeoutStr)
	if err != nil {
		errorf("invalid timeout %q: %v", *timeoutStr, err)
	}

	base := apiBase(*configPath, envHost(*host), envPort(*port))
	apiKey := resolveAPIKey(*apiKeyFlag, *configPath)
	body, err := apiGet(fmt.Sprintf("%s/api/v1/alerts/%s", base, alertID), apiKey, timeout)
	if err != nil {
		errorf("%v", err)
	}

	if parseFormat(*format) == FormatJSON {
		fmt.Println(string(body))
		return
	}

	var alert map[string]interface{}
	if err := json.Unmarshal(body, &alert); err != nil {
		errorf("parsing response: %v", err)
	}

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

	fmt.Printf("%s Alert Detail\n\n", bold("🔔"))
	fmt.Printf("  %-16s %s\n", "ID:", alert["id"])
	fmt.Printf("  %-16s %s\n", "Title:", alert["title"])
	fmt.Printf("  %-16s %s\n", "Severity:", sevColor(sev))
	fmt.Printf("  %-16s %v\n", "Status:", alert["status"])
	fmt.Printf("  %-16s %v\n", "Module:", alert["module"])
	fmt.Printf("  %-16s %v\n", "Type:", alert["type"])
	fmt.Printf("  %-16s %v\n", "Timestamp:", alert["timestamp"])
	if desc, ok := alert["description"]; ok && desc != "" && desc != nil {
		fmt.Printf("  %-16s %v\n", "Description:", desc)
	}
	if mits, ok := alert["mitigations"].([]interface{}); ok && len(mits) > 0 {
		fmt.Printf("  %-16s\n", "Mitigations:")
		for _, m := range mits {
			fmt.Printf("    - %v\n", m)
		}
	}
	fmt.Println()
}

func cmdAlertsClear(args []string) {
	fs := flag.NewFlagSet("alerts-clear", flag.ExitOnError)
	configPath := fs.String("config", "configs/default.yaml", "Config file path")
	host := fs.String("host", "", "API host override")
	port := fs.Int("port", 0, "API port override")
	apiKeyFlag := fs.String("api-key", "", "API key for authentication")
	timeoutStr := fs.String("timeout", "5s", "Request timeout")
	profileFlag := fs.String("profile", "", "Named profile to use")
	fs.Parse(args)

	*configPath = resolveProfile(*profileFlag, envConfig(*configPath))

	timeout, err := time.ParseDuration(*timeoutStr)
	if err != nil {
		errorf("invalid timeout %q: %v", *timeoutStr, err)
	}

	base := apiBase(*configPath, envHost(*host), envPort(*port))
	apiKey := resolveAPIKey(*apiKeyFlag, *configPath)
	body, err := apiPost(base+"/api/v1/alerts/clear", []byte("{}"), apiKey, timeout)
	if err != nil {
		errorf("%v", err)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(body, &resp); err != nil {
		fmt.Fprintf(os.Stdout, "%s Alerts cleared.\n", green("✓"))
		return
	}

	fmt.Fprintf(os.Stdout, "%s Cleared %v alert(s).\n", green("✓"), resp["cleared"])
}
