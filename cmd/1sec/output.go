package main

// ---------------------------------------------------------------------------
// output.go — format flag, table rendering, SARIF, CSV, output helpers
// ---------------------------------------------------------------------------

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

// OutputFormat enumerates supported output formats.
type OutputFormat int

const (
	FormatTable OutputFormat = iota
	FormatJSON
	FormatCSV
	FormatSARIF
)

// parseFormat converts a --format string to an OutputFormat.
func parseFormat(s string) OutputFormat {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "json":
		return FormatJSON
	case "csv":
		return FormatCSV
	case "sarif":
		return FormatSARIF
	default:
		return FormatTable
	}
}

// formatName returns the canonical name for a format.
func formatName(f OutputFormat) string {
	switch f {
	case FormatJSON:
		return "json"
	case FormatCSV:
		return "csv"
	case FormatSARIF:
		return "sarif"
	default:
		return "table"
	}
}

// ---------------------------------------------------------------------------
// Table renderer — auto-sized columns with box-drawing borders
// ---------------------------------------------------------------------------

// Table renders aligned, bordered tables to a writer.
type Table struct {
	headers []string
	rows    [][]string
	w       io.Writer
}

// NewTable creates a table with the given column headers.
func NewTable(w io.Writer, headers ...string) *Table {
	return &Table{headers: headers, w: w}
}

// AddRow appends a row. Values are matched positionally to headers.
func (t *Table) AddRow(values ...string) {
	// Pad or truncate to match header count
	row := make([]string, len(t.headers))
	for i := range row {
		if i < len(values) {
			row[i] = values[i]
		}
	}
	t.rows = append(t.rows, row)
}

// Render writes the table with box-drawing borders.
func (t *Table) Render() {
	if len(t.headers) == 0 {
		return
	}

	// Calculate column widths
	widths := make([]int, len(t.headers))
	for i, h := range t.headers {
		widths[i] = len(h)
	}
	for _, row := range t.rows {
		for i, cell := range row {
			if len(cell) > widths[i] {
				widths[i] = len(cell)
			}
		}
	}

	// Build format strings
	border := "┌"
	for i, w := range widths {
		border += strings.Repeat("─", w+2)
		if i < len(widths)-1 {
			border += "┬"
		}
	}
	border += "┐"

	mid := "├"
	for i, w := range widths {
		mid += strings.Repeat("─", w+2)
		if i < len(widths)-1 {
			mid += "┼"
		}
	}
	mid += "┤"

	bottom := "└"
	for i, w := range widths {
		bottom += strings.Repeat("─", w+2)
		if i < len(widths)-1 {
			bottom += "┴"
		}
	}
	bottom += "┘"

	printRow := func(cells []string) {
		fmt.Fprint(t.w, "│")
		for i, cell := range cells {
			fmt.Fprintf(t.w, " %-*s │", widths[i], cell)
		}
		fmt.Fprintln(t.w)
	}

	fmt.Fprintln(t.w, border)
	printRow(t.headers)
	fmt.Fprintln(t.w, mid)
	for _, row := range t.rows {
		printRow(row)
	}
	fmt.Fprintln(t.w, bottom)
}

// ---------------------------------------------------------------------------
// CSV writer helper
// ---------------------------------------------------------------------------

func writeCSV(w io.Writer, headers []string, rows [][]string) {
	cw := csv.NewWriter(w)
	cw.Write(headers)
	for _, row := range rows {
		cw.Write(row)
	}
	cw.Flush()
}

// ---------------------------------------------------------------------------
// SARIF output helper (minimal SARIF 2.1.0 for GitHub Security tab)
// ---------------------------------------------------------------------------

type sarifReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type sarifResult struct {
	RuleID  string       `json:"ruleId"`
	Level   string       `json:"level"`
	Message sarifMessage `json:"message"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

func sarifLevel(severity string) string {
	switch strings.ToUpper(severity) {
	case "CRITICAL", "HIGH":
		return "error"
	case "MEDIUM":
		return "warning"
	default:
		return "note"
	}
}

func writeSARIF(w io.Writer, alerts []interface{}, ver string) {
	results := make([]sarifResult, 0, len(alerts))
	for _, a := range alerts {
		alert := a.(map[string]interface{})
		results = append(results, sarifResult{
			RuleID: fmt.Sprintf("%v/%v", alert["module"], alert["type"]),
			Level:  sarifLevel(fmt.Sprintf("%v", alert["severity"])),
			Message: sarifMessage{
				Text: fmt.Sprintf("%v", alert["title"]),
			},
		})
	}

	report := sarifReport{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{Name: "1sec", Version: ver}},
			Results: results,
		}},
	}

	data, _ := json.MarshalIndent(report, "", "  ")
	fmt.Fprintln(w, string(data))
}

// ---------------------------------------------------------------------------
// outputWriter — writes to file if --output is set, otherwise stdout
// ---------------------------------------------------------------------------

func outputWriter(path string) (*os.File, func()) {
	if path == "" || path == "-" {
		return os.Stdout, func() {}
	}
	f, err := os.Create(path)
	if err != nil {
		errorf("opening output file %q: %v", path, err)
	}
	return f, func() { f.Close() }
}
