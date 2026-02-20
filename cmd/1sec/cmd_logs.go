package main

// ---------------------------------------------------------------------------
// cmd_logs.go — fetch recent logs, with --follow for real-time tailing
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

func cmdLogs(args []string) {
	fs := flag.NewFlagSet("logs", flag.ExitOnError)
	configPath := fs.String("config", "configs/default.yaml", "Config file path")
	host := fs.String("host", "", "API host override")
	port := fs.Int("port", 0, "API port override")
	apiKeyFlag := fs.String("api-key", "", "API key for authentication")
	lines := fs.Int("lines", 50, "Number of log lines to fetch")
	follow := fs.Bool("follow", false, "Continuously poll for new log entries (like tail -f)")
	fs.BoolVar(follow, "f", false, "Continuously poll for new log entries (like tail -f)")
	pollStr := fs.String("poll-interval", "2s", "Poll interval for --follow mode")
	format := fs.String("format", "table", "Output format: table, json")
	jsonOut := fs.Bool("json", false, "Output raw JSON")
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

	pollInterval, err := time.ParseDuration(*pollStr)
	if err != nil {
		errorf("invalid poll-interval %q: %v", *pollStr, err)
	}

	base := apiBase(*configPath, hostVal, portVal)
	apiKey := resolveAPIKey(*apiKeyFlag, *configPath)

	if *follow {
		cmdLogsFollow(base, apiKey, *lines, pollInterval, timeout)
		return
	}

	url := fmt.Sprintf("%s/api/v1/logs?limit=%d", base, *lines)
	body, err := apiGet(url, apiKey, timeout)
	if err != nil {
		errorf("%v", err)
	}

	w, cleanup := outputWriter(*output)
	defer cleanup()

	if outFmt == FormatJSON {
		fmt.Fprintln(w, string(body))
		return
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(body, &resp); err != nil {
		errorf("parsing response: %v", err)
	}

	logs, _ := resp["logs"].([]interface{})
	if len(logs) == 0 {
		fmt.Fprintf(w, "%s No log entries found.\n", dim("▸"))
		return
	}

	fmt.Fprintf(w, "%s Logs (%d entries)\n\n", bold("📋"), len(logs))
	for _, l := range logs {
		entry := l.(map[string]interface{})
		raw := fmt.Sprintf("%v", entry["raw"])
		raw = strings.TrimSpace(raw)
		if raw != "" {
			fmt.Fprintln(w, raw)
		} else {
			fmt.Fprintf(w, "%s %s\n", dim(fmt.Sprintf("%v", entry["timestamp"])), entry["message"])
		}
	}
	fmt.Fprintln(w)
}

// cmdLogsFollow continuously polls the logs API and prints new entries.
func cmdLogsFollow(base, apiKey string, initialLines int, pollInterval, timeout time.Duration) {
	fmt.Fprintf(os.Stderr, "%s Tailing logs (Ctrl+C to stop)...\n\n", dim("▸"))

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Track the last seen log entry to avoid duplicates
	lastSeen := ""
	firstFetch := true

	for {
		select {
		case <-sigCh:
			fmt.Fprintf(os.Stderr, "\n%s Log tailing stopped.\n", dim("▸"))
			return
		default:
		}

		limit := initialLines
		if !firstFetch {
			limit = 20 // smaller fetches after initial
		}

		url := fmt.Sprintf("%s/api/v1/logs?limit=%d", base, limit)
		body, err := apiGet(url, apiKey, timeout)
		if err != nil {
			// Silently retry on transient errors
			time.Sleep(pollInterval)
			continue
		}

		var resp map[string]interface{}
		if json.Unmarshal(body, &resp) != nil {
			time.Sleep(pollInterval)
			continue
		}

		logs, _ := resp["logs"].([]interface{})

		// Find new entries (after lastSeen)
		newEntries := make([]interface{}, 0)
		foundLast := false
		for _, l := range logs {
			entry := l.(map[string]interface{})
			key := fmt.Sprintf("%v|%v", entry["timestamp"], entry["message"])
			if key == lastSeen {
				foundLast = true
				continue
			}
			if foundLast || firstFetch {
				newEntries = append(newEntries, l)
			}
		}

		// If we didn't find lastSeen, print everything (gap in logs)
		if !firstFetch && !foundLast && len(logs) > 0 {
			newEntries = logs
		}

		for _, l := range newEntries {
			entry := l.(map[string]interface{})
			raw := strings.TrimSpace(fmt.Sprintf("%v", entry["raw"]))
			if raw != "" {
				fmt.Println(raw)
			} else {
				fmt.Printf("%s %s\n", dim(fmt.Sprintf("%v", entry["timestamp"])), entry["message"])
			}
			lastSeen = fmt.Sprintf("%v|%v", entry["timestamp"], entry["message"])
		}

		firstFetch = false
		time.Sleep(pollInterval)
	}
}
