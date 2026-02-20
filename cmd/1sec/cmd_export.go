package main

// ---------------------------------------------------------------------------
// cmd_export.go — bulk export alerts/events (Recommendation #5)
//
// Supports JSON, CSV, and SARIF output formats with date range filtering.
// ---------------------------------------------------------------------------

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

func cmdExport(args []string) {
	fs := flag.NewFlagSet("export", flag.ExitOnError)
	configPath := fs.String("config", "configs/default.yaml", "Config file path")
	host := fs.String("host", "", "API host override")
	port := fs.Int("port", 0, "API port override")
	apiKeyFlag := fs.String("api-key", "", "API key for authentication")
	exportType := fs.String("type", "alerts", "What to export: alerts, events")
	format := fs.String("format", "json", "Output format: json, csv, sarif")
	output := fs.String("output", "", "Write output to file (default: stdout)")
	severity := fs.String("severity", "", "Minimum severity filter")
	module := fs.String("module", "", "Filter by module")
	limit := fs.Int("limit", 1000, "Maximum records to export")
	timeoutStr := fs.String("timeout", "30s", "Request timeout")
	profileFlag := fs.String("profile", "", "Named profile to use")
	fs.Parse(args)

	*configPath = resolveProfile(*profileFlag, envConfig(*configPath))
	hostVal := envHost(*host)
	portVal := envPort(*port)
	outFmt := parseFormat(*format)

	timeout, err := time.ParseDuration(*timeoutStr)
	if err != nil {
		errorf("invalid timeout %q: %v", *timeoutStr, err)
	}

	base := apiBase(*configPath, hostVal, portVal)
	apiKey := resolveAPIKey(*apiKeyFlag, *configPath)

	w, cleanup := outputWriter(*output)
	defer cleanup()

	switch strings.ToLower(*exportType) {
	case "alerts":
		exportAlerts(w, base, apiKey, timeout, outFmt, *severity, *module, *limit)
	case "events":
		exportEvents(w, base, apiKey, timeout, outFmt, *limit)
	default:
		errorf("unknown export type %q — supported: alerts, events", *exportType)
	}

	if *output != "" {
		fmt.Fprintf(os.Stderr, "%s Exported to %s (%s format)\n", green("✓"), *output, formatName(outFmt))
	}
}

func exportAlerts(w *os.File, base, apiKey string, timeout time.Duration, outFmt OutputFormat, severity, module string, limit int) {
	url := fmt.Sprintf("%s/api/v1/alerts?limit=%d", base, limit)
	if severity != "" {
		url += "&min_severity=" + strings.ToUpper(severity)
	}

	body, err := apiGet(url, apiKey, timeout)
	if err != nil {
		errorf("%v", err)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(body, &resp); err != nil {
		errorf("parsing response: %v", err)
	}

	alerts, _ := resp["alerts"].([]interface{})

	// Client-side module filter
	if module != "" {
		filtered := make([]interface{}, 0)
		for _, a := range alerts {
			alert := a.(map[string]interface{})
			if fmt.Sprintf("%v", alert["module"]) == module {
				filtered = append(filtered, a)
			}
		}
		alerts = filtered
	}

	switch outFmt {
	case FormatSARIF:
		writeSARIF(w, alerts, version)
	case FormatCSV:
		headers := []string{"id", "severity", "status", "module", "type", "title", "description", "timestamp"}
		rows := make([][]string, 0, len(alerts))
		for _, a := range alerts {
			alert := a.(map[string]interface{})
			desc := ""
			if d, ok := alert["description"]; ok && d != nil {
				desc = fmt.Sprintf("%v", d)
			}
			rows = append(rows, []string{
				fmt.Sprintf("%v", alert["id"]),
				fmt.Sprintf("%v", alert["severity"]),
				fmt.Sprintf("%v", alert["status"]),
				fmt.Sprintf("%v", alert["module"]),
				fmt.Sprintf("%v", alert["type"]),
				fmt.Sprintf("%v", alert["title"]),
				desc,
				fmt.Sprintf("%v", alert["timestamp"]),
			})
		}
		writeCSV(w, headers, rows)
	default:
		data, _ := json.MarshalIndent(map[string]interface{}{
			"alerts":    alerts,
			"total":     len(alerts),
			"exported":  time.Now().UTC().Format(time.RFC3339),
			"format":    "1sec-export-v1",
		}, "", "  ")
		fmt.Fprintln(w, string(data))
	}
}

func exportEvents(w *os.File, base, apiKey string, timeout time.Duration, outFmt OutputFormat, limit int) {
	url := fmt.Sprintf("%s/api/v1/events?limit=%d", base, limit)

	body, err := apiGet(url, apiKey, timeout)
	if err != nil {
		errorf("%v", err)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(body, &resp); err != nil {
		// If events endpoint returns raw array or different shape
		if outFmt == FormatJSON {
			fmt.Fprintln(w, string(body))
			return
		}
		errorf("parsing response: %v", err)
	}

	events, _ := resp["events"].([]interface{})

	switch outFmt {
	case FormatCSV:
		headers := []string{"id", "type", "source", "module", "severity", "summary", "timestamp"}
		rows := make([][]string, 0, len(events))
		for _, e := range events {
			event := e.(map[string]interface{})
			rows = append(rows, []string{
				fmt.Sprintf("%v", event["id"]),
				fmt.Sprintf("%v", event["type"]),
				fmt.Sprintf("%v", event["source"]),
				fmt.Sprintf("%v", event["module"]),
				fmt.Sprintf("%v", event["severity"]),
				fmt.Sprintf("%v", event["summary"]),
				fmt.Sprintf("%v", event["timestamp"]),
			})
		}
		writeCSV(w, headers, rows)
	default:
		data, _ := json.MarshalIndent(map[string]interface{}{
			"events":   events,
			"total":    len(events),
			"exported": time.Now().UTC().Format(time.RFC3339),
			"format":   "1sec-export-v1",
		}, "", "  ")
		fmt.Fprintln(w, string(data))
	}
}
