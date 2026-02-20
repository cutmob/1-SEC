package main

// ---------------------------------------------------------------------------
// cmd_rust.go — inspect Rust sidecar status
// ---------------------------------------------------------------------------

import (
	"encoding/json"
	"flag"
	"fmt"
	"time"
)

func cmdRust(args []string) {
	fs := flag.NewFlagSet("rust", flag.ExitOnError)
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
	body, err := apiGet(base+"/api/v1/rust", apiKey, timeout)
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

	fmt.Printf("%s Rust Engine Sidecar\n\n", bold("⚙"))

	engineStatus := fmt.Sprintf("%v", status["status"])
	statusColor := dim
	switch engineStatus {
	case "running":
		statusColor = green
	case "stopped":
		statusColor = red
	case "disabled":
		statusColor = dim
	}

	fmt.Printf("  %-20s %s\n", "Status:", statusColor(engineStatus))
	fmt.Printf("  %-20s %v\n", "Enabled:", status["enabled"])

	if engineStatus == "running" {
		if v, ok := status["binary"]; ok {
			fmt.Printf("  %-20s %v\n", "Binary:", v)
		}
		if v, ok := status["workers"]; ok {
			workers := fmt.Sprintf("%v", v)
			if workers == "0" {
				workers = "auto (CPU cores)"
			}
			fmt.Printf("  %-20s %s\n", "Workers:", workers)
		}
		if v, ok := status["buffer_size"]; ok {
			fmt.Printf("  %-20s %v\n", "Buffer Size:", v)
		}
		if v, ok := status["aho_corasick"]; ok {
			fmt.Printf("  %-20s %v\n", "Aho-Corasick:", v)
		}
		if v, ok := status["capture_enabled"]; ok {
			captureEnabled := fmt.Sprintf("%v", v)
			fmt.Printf("  %-20s %s\n", "Packet Capture:", captureEnabled)
			if captureEnabled == "true" {
				if iface, ok := status["capture_interface"]; ok {
					fmt.Printf("  %-20s %v\n", "Interface:", iface)
				}
			}
		}
	}

	if engineStatus == "disabled" {
		fmt.Printf("\n  %s Enable with: rust_engine.enabled: true in config\n", dim("▸"))
		fmt.Printf("  %s Build with: cd rust/1sec-engine && cargo build --release\n", dim("▸"))
	}

	fmt.Println()
}
