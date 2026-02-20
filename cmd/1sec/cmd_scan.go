package main

// ---------------------------------------------------------------------------
// cmd_scan.go — submit a payload for on-demand analysis
// ---------------------------------------------------------------------------

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/1sec-project/1sec/internal/core"
)

func cmdScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	configPath := fs.String("config", "configs/default.yaml", "Config file path")
	host := fs.String("host", "", "API host override")
	port := fs.Int("port", 0, "API port override")
	apiKeyFlag := fs.String("api-key", "", "API key for authentication")
	module := fs.String("module", "external", "Module to attribute the event to")
	eventType := fs.String("type", "scan", "Event type")
	severity := fs.String("severity", "MEDIUM", "Event severity")
	inputFile := fs.String("input", "-", "Read payload from file (- for stdin)")
	wait := fs.Bool("wait", false, "Wait for analysis results after submission")
	waitTimeoutStr := fs.String("wait-timeout", "30s", "How long to wait for results")
	format := fs.String("format", "table", "Output format: table, json")
	jsonOut := fs.Bool("json", false, "Output raw JSON response")
	timeoutStr := fs.String("timeout", "10s", "Request timeout")
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

	waitTimeout, err := time.ParseDuration(*waitTimeoutStr)
	if err != nil {
		errorf("invalid wait-timeout %q: %v", *waitTimeoutStr, err)
	}

	var reader io.Reader
	if *inputFile == "-" || *inputFile == "" {
		fi, err := os.Stdin.Stat()
		if err != nil {
			errorf("checking stdin: %v", err)
		}
		if (fi.Mode() & os.ModeCharDevice) != 0 {
			errorf("no input provided — pipe data via stdin or use --input <file>")
		}
		reader = os.Stdin
	} else {
		f, err := os.Open(*inputFile)
		if err != nil {
			errorf("opening input file %q: %v", *inputFile, err)
		}
		defer f.Close()
		reader = f
	}

	payload, err := io.ReadAll(reader)
	if err != nil {
		errorf("reading input: %v", err)
	}
	if len(payload) == 0 {
		errorf("empty payload — nothing to scan")
	}

	var sev core.Severity
	switch strings.ToUpper(*severity) {
	case "INFO":
		sev = core.SeverityInfo
	case "LOW":
		sev = core.SeverityLow
	case "MEDIUM":
		sev = core.SeverityMedium
	case "HIGH":
		sev = core.SeverityHigh
	case "CRITICAL":
		sev = core.SeverityCritical
	default:
		sev = core.SeverityMedium
	}

	event := core.SecurityEvent{
		ID:        "scan-" + time.Now().Format("20060102-150405.000"),
		Timestamp: time.Now().UTC(),
		Source:    "cli-scan",
		Module:    *module,
		Type:      *eventType,
		Severity:  sev,
		Summary:   fmt.Sprintf("CLI scan submission (%d bytes)", len(payload)),
		RawData:   payload,
		Details:   map[string]interface{}{"payload_size": len(payload)},
	}

	var parsed map[string]interface{}
	if json.Unmarshal(payload, &parsed) == nil {
		for k, v := range parsed {
			event.Details[k] = v
		}
	}

	eventJSON, err := json.Marshal(event)
	if err != nil {
		errorf("marshaling event: %v", err)
	}

	base := apiBase(*configPath, hostVal, portVal)
	apiKey := resolveAPIKey(*apiKeyFlag, *configPath)
	body, err := apiPost(base+"/api/v1/events", eventJSON, apiKey, timeout)
	if err != nil {
		errorf("%v", err)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(body, &resp); err != nil {
		fmt.Println(string(body))
		return
	}

	eventID := fmt.Sprintf("%v", resp["event_id"])

	if !*wait {
		if outFmt == FormatJSON {
			fmt.Println(string(body))
			return
		}
		fmt.Fprintf(os.Stdout, "%s Event submitted — id=%s status=%s\n",
			green("✓"), eventID, resp["status"])
		return
	}

	// --wait mode: poll for alerts related to this event
	fmt.Fprintf(os.Stderr, "%s Event submitted (id=%s), waiting for analysis...\n", dim("▸"), eventID)

	deadline := time.Now().Add(waitTimeout)
	pollInterval := 500 * time.Millisecond
	prevAlertCount := 0

	initialBody, err := apiGet(base+"/api/v1/alerts?limit=1", apiKey, timeout)
	if err == nil {
		var initialResp map[string]interface{}
		if json.Unmarshal(initialBody, &initialResp) == nil {
			if total, ok := initialResp["total"].(float64); ok {
				prevAlertCount = int(total)
			}
		}
	}

	for time.Now().Before(deadline) {
		time.Sleep(pollInterval)

		alertBody, err := apiGet(fmt.Sprintf("%s/api/v1/alerts?limit=50", base), apiKey, timeout)
		if err != nil {
			continue
		}

		var alertResp map[string]interface{}
		if json.Unmarshal(alertBody, &alertResp) != nil {
			continue
		}

		alerts, _ := alertResp["alerts"].([]interface{})
		if len(alerts) > prevAlertCount {
			newAlerts := make([]interface{}, 0)
			for _, a := range alerts {
				alert := a.(map[string]interface{})
				if eventIDs, ok := alert["event_ids"].([]interface{}); ok {
					for _, eid := range eventIDs {
						if fmt.Sprintf("%v", eid) == eventID {
							newAlerts = append(newAlerts, a)
						}
					}
				}
			}

			if len(newAlerts) > 0 {
				if outFmt == FormatJSON {
					data, _ := json.MarshalIndent(map[string]interface{}{
						"event_id": eventID,
						"alerts":   newAlerts,
						"total":    len(newAlerts),
					}, "", "  ")
					fmt.Println(string(data))
					return
				}

				fmt.Fprintf(os.Stdout, "\n%s Analysis complete — %d alert(s) generated:\n\n", green("✓"), len(newAlerts))
				for _, a := range newAlerts {
					alert := a.(map[string]interface{})
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
					fmt.Fprintf(os.Stdout, "  %s [%s] %s\n", sevColor("●"), sevColor(sev), alert["title"])
					if desc, ok := alert["description"]; ok && desc != "" {
						fmt.Fprintf(os.Stdout, "    %s\n", desc)
					}
				}
				fmt.Println()
				return
			}
		}

		if pollInterval < 2*time.Second {
			pollInterval += 250 * time.Millisecond
		}
	}

	fmt.Fprintf(os.Stdout, "%s No alerts generated within %s. The payload may be clean.\n",
		dim("▸"), waitTimeout)
}
