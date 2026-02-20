package main

// ---------------------------------------------------------------------------
// cmd_events.go — submit events to a running instance
// ---------------------------------------------------------------------------

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"
)

func cmdEvents(args []string) {
	fs := flag.NewFlagSet("events", flag.ExitOnError)
	configPath := fs.String("config", "configs/default.yaml", "Config file path")
	host := fs.String("host", "", "API host override")
	port := fs.Int("port", 0, "API port override")
	apiKeyFlag := fs.String("api-key", "", "API key for authentication")
	inputFile := fs.String("input", "-", "Read event JSON from file (- for stdin)")
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

	var reader io.Reader
	if *inputFile == "-" || *inputFile == "" {
		fi, err := os.Stdin.Stat()
		if err != nil {
			errorf("checking stdin: %v", err)
		}
		if (fi.Mode() & os.ModeCharDevice) != 0 {
			errorf("no input provided — pipe event JSON via stdin or use --input <file>")
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
		errorf("empty input — provide event JSON")
	}

	var event map[string]interface{}
	if err := json.Unmarshal(payload, &event); err != nil {
		errorf("invalid JSON: %v", err)
	}

	if _, ok := event["id"]; !ok {
		event["id"] = "cli-" + time.Now().Format("20060102-150405.000")
	}
	if _, ok := event["timestamp"]; !ok {
		event["timestamp"] = time.Now().UTC()
	}
	if _, ok := event["source"]; !ok {
		event["source"] = "cli-events"
	}

	eventJSON, _ := json.Marshal(event)

	base := apiBase(*configPath, hostVal, portVal)
	apiKey := resolveAPIKey(*apiKeyFlag, *configPath)
	body, err := apiPost(base+"/api/v1/events", eventJSON, apiKey, timeout)
	if err != nil {
		errorf("%v", err)
	}

	if outFmt == FormatJSON {
		fmt.Println(string(body))
		return
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(body, &resp); err != nil {
		fmt.Println(string(body))
		return
	}

	fmt.Fprintf(os.Stdout, "%s Event submitted — id=%s status=%s\n",
		green("✓"), resp["event_id"], resp["status"])
}
