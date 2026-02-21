package main

// ---------------------------------------------------------------------------
// cmd_status.go — fetch status from a running instance
// ---------------------------------------------------------------------------

import (
	"encoding/json"
	"flag"
	"fmt"
	"time"
)

func cmdStatus(args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	configPath := fs.String("config", "configs/default.yaml", "Config file path")
	host := fs.String("host", "", "API host override")
	port := fs.Int("port", 0, "API port override")
	apiKeyFlag := fs.String("api-key", "", "API key for authentication")
	format := fs.String("format", "table", "Output format: table, json, csv")
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
	body, err := apiGet(base+"/api/v1/status", apiKey, timeout)
	if err != nil {
		errorf("%v", err)
	}

	w, cleanup := outputWriter(*output)
	defer cleanup()

	if outFmt == FormatJSON {
		fmt.Fprintln(w, string(body))
		return
	}

	var status map[string]interface{}
	if err := json.Unmarshal(body, &status); err != nil {
		errorf("parsing response: %v", err)
	}

	if outFmt == FormatCSV {
		headers := []string{"field", "value"}
		rows := [][]string{
			{"version", fmt.Sprintf("%v", status["version"])},
			{"status", fmt.Sprintf("%v", status["status"])},
			{"bus_connected", fmt.Sprintf("%v", status["bus_connected"])},
			{"modules_total", fmt.Sprintf("%v", status["modules_total"])},
			{"alerts_total", fmt.Sprintf("%v", status["alerts_total"])},
			{"timestamp", fmt.Sprintf("%v", status["timestamp"])},
		}
		if re, ok := status["rust_engine"].(string); ok {
			rows = append(rows, []string{"rust_engine", re})
		}
		writeCSV(w, headers, rows)
		return
	}

	// Table (default)
	fmt.Fprintf(w, "%s 1SEC Status\n\n", bold("●"))
	fmt.Fprintf(w, "  %-18s %s\n", "Version:", green(fmt.Sprintf("%v", status["version"])))
	fmt.Fprintf(w, "  %-18s %s\n", "Status:", green(fmt.Sprintf("%v", status["status"])))
	fmt.Fprintf(w, "  %-18s %v\n", "Bus Connected:", status["bus_connected"])
	fmt.Fprintf(w, "  %-18s %v\n", "Modules Active:", status["modules_total"])
	fmt.Fprintf(w, "  %-18s %v\n", "Total Alerts:", status["alerts_total"])
	if re, ok := status["rust_engine"].(string); ok {
		var reDisplay string
		switch re {
		case "running":
			reDisplay = green("running")
		case "disabled":
			reDisplay = dim("disabled")
		default:
			reDisplay = yellow(re)
		}
		fmt.Fprintf(w, "  %-18s %s\n", "Rust Engine:", reDisplay)
	}
	if cloud, ok := status["cloud"].(string); ok {
		var cloudDisplay string
		switch cloud {
		case "reporting":
			cloudDisplay = green("reporting")
		case "disabled":
			cloudDisplay = dim("disabled")
		default:
			cloudDisplay = yellow(cloud)
		}
		fmt.Fprintf(w, "  %-18s %s\n", "Cloud Dashboard:", cloudDisplay)
	}

	// Enforcement status
	if enforce, ok := status["enforcement"].(map[string]interface{}); ok {
		enabled, _ := enforce["enabled"].(bool)
		dryRun, _ := enforce["dry_run"].(bool)
		preset, _ := enforce["preset"].(string)
		if enabled {
			mode := green("live")
			if dryRun {
				mode = yellow("dry-run")
			}
			presetStr := ""
			if preset != "" {
				presetStr = fmt.Sprintf(" (%s)", preset)
			}
			fmt.Fprintf(w, "  %-18s %s%s\n", "Enforcement:", mode, dim(presetStr))
		} else {
			fmt.Fprintf(w, "  %-18s %s\n", "Enforcement:", dim("disabled"))
		}
	}

	fmt.Fprintf(w, "  %-18s %v\n", "Timestamp:", status["timestamp"])

	if modules, ok := status["modules"].([]interface{}); ok && len(modules) > 0 {
		fmt.Fprintf(w, "\n  %s\n", bold("Modules:"))
		for _, m := range modules {
			mod := m.(map[string]interface{})
			marker := green("●")
			if enabled, ok := mod["enabled"].(bool); ok && !enabled {
				marker = red("○")
			}
			fmt.Fprintf(w, "    %s %-24s %s\n", marker, mod["name"], dim(fmt.Sprintf("%v", mod["description"])))
		}
	}
	fmt.Fprintln(w)
}
