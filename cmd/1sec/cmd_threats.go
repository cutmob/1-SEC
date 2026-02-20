package main

// ---------------------------------------------------------------------------
// cmd_threats.go — query dynamic IP threat scoring
// ---------------------------------------------------------------------------

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"
)

func cmdThreats(args []string) {
	fs := flag.NewFlagSet("threats", flag.ExitOnError)
	configPath := fs.String("config", "configs/default.yaml", "Config file path")
	host := fs.String("host", "", "API host override")
	port := fs.Int("port", 0, "API port override")
	apiKeyFlag := fs.String("api-key", "", "API key for authentication")
	format := fs.String("format", "table", "Output format: table, json, csv")
	jsonOut := fs.Bool("json", false, "Output raw JSON")
	blockedOnly := fs.Bool("blocked", false, "Show only blocked IPs")
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
	body, err := apiGet(base+"/api/v1/threats", apiKey, timeout)
	if err != nil {
		errorf("%v", err)
	}

	if outFmt == FormatJSON {
		fmt.Println(string(body))
		return
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(body, &resp); err != nil {
		errorf("parsing response: %v", err)
	}

	threats, _ := resp["threats"].([]interface{})
	blockedCount := 0
	if bc, ok := resp["blocked_count"].(float64); ok {
		blockedCount = int(bc)
	}

	if outFmt == FormatCSV {
		headers := []string{"ip", "points", "modules", "blocked", "first_seen", "last_seen"}
		rows := make([][]string, 0, len(threats))
		for _, t := range threats {
			threat := t.(map[string]interface{})
			blocked := fmt.Sprintf("%v", threat["blocked"])
			if *blockedOnly && blocked != "true" {
				continue
			}
			modules := threat["modules"].(map[string]interface{})
			rows = append(rows, []string{
				fmt.Sprintf("%v", threat["ip"]),
				fmt.Sprintf("%v", threat["points"]),
				fmt.Sprintf("%d", len(modules)),
				blocked,
				fmt.Sprintf("%v", threat["first_seen"]),
				fmt.Sprintf("%v", threat["last_seen"]),
			})
		}
		writeCSV(os.Stdout, headers, rows)
		return
	}

	// Table output
	fmt.Printf("%s IP Threat Scores (%d tracked, %s blocked)\n\n",
		bold("🎯"), len(threats), red(fmt.Sprintf("%d", blockedCount)))

	if len(threats) == 0 {
		fmt.Printf("  %s No IPs currently tracked.\n\n", green("✓"))
		return
	}

	tbl := NewTable(os.Stdout, "IP", "POINTS", "MODULES", "BLOCKED", "LAST SEEN")
	for _, t := range threats {
		threat := t.(map[string]interface{})
		blocked := fmt.Sprintf("%v", threat["blocked"])
		if *blockedOnly && blocked != "true" {
			continue
		}
		modules := threat["modules"].(map[string]interface{})
		moduleNames := make([]string, 0)
		for k := range modules {
			moduleNames = append(moduleNames, k)
		}

		blockedStr := dim("no")
		if blocked == "true" {
			blockedStr = red("YES")
		}

		points := fmt.Sprintf("%v", threat["points"])
		pointsColor := dim
		if p, ok := threat["points"].(float64); ok {
			if p >= 50 {
				pointsColor = red
			} else if p >= 25 {
				pointsColor = yellow
			}
		}

		tbl.AddRow(
			fmt.Sprintf("%v", threat["ip"]),
			pointsColor(points),
			fmt.Sprintf("%d (%s)", len(moduleNames), joinStrings(moduleNames, ", ")),
			blockedStr,
			fmt.Sprintf("%v", threat["last_seen"]),
		)
	}
	tbl.Render()
	fmt.Println()
}
