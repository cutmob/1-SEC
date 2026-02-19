package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/1sec-project/1sec/internal/api"
	"github.com/1sec-project/1sec/internal/core"
	"github.com/1sec-project/1sec/internal/ingest"

	"github.com/1sec-project/1sec/internal/modules/aicontainment"
	"github.com/1sec-project/1sec/internal/modules/aiengine"
	"github.com/1sec-project/1sec/internal/modules/apifortress"
	"github.com/1sec-project/1sec/internal/modules/auth"
	"github.com/1sec-project/1sec/internal/modules/cloudposture"
	"github.com/1sec-project/1sec/internal/modules/datapoisoning"
	"github.com/1sec-project/1sec/internal/modules/deepfake"
	"github.com/1sec-project/1sec/internal/modules/identity"
	"github.com/1sec-project/1sec/internal/modules/injection"
	"github.com/1sec-project/1sec/internal/modules/iot"
	"github.com/1sec-project/1sec/internal/modules/llmfirewall"
	"github.com/1sec-project/1sec/internal/modules/network"
	"github.com/1sec-project/1sec/internal/modules/quantumcrypto"
	"github.com/1sec-project/1sec/internal/modules/ransomware"
	"github.com/1sec-project/1sec/internal/modules/runtime"
	"github.com/1sec-project/1sec/internal/modules/supplychain"

	"gopkg.in/yaml.v3"
)

var (
	version   = "1.0.0"
	commit    = "dev"
	buildDate = "unknown"
)

// ---------------------------------------------------------------------------
// TTY / color helpers
// ---------------------------------------------------------------------------

func isTTY(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

func colorEnabled() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	if os.Getenv("TERM") == "dumb" {
		return false
	}
	return isTTY(os.Stderr)
}

func ansi(code, s string) string {
	if !colorEnabled() {
		return s
	}
	return code + s + "\033[0m"
}

func red(s string) string    { return ansi("\033[91m", s) }
func yellow(s string) string { return ansi("\033[93m", s) }
func green(s string) string  { return ansi("\033[32m", s) }
func cyan(s string) string   { return ansi("\033[36m", s) }
func dim(s string) string    { return ansi("\033[90m", s) }
func bold(s string) string   { return ansi("\033[1m", s) }

func bannerText() string {
	if !colorEnabled() {
		return `
    ╔══════════════════════════════════════════════════════════╗
    ║                                                          ║
    ║     ██╗       ███████╗ ███████╗  ██████╗               ║
    ║    ███║       ██╔════╝ ██╔════╝ ██╔════╝               ║
    ║    ╚██║ █████╗███████╗ █████╗   ██║                    ║
    ║     ██║ ╚════╝╚════██║ ██╔══╝   ██║                    ║
    ║     ██║       ███████║ ███████╗ ╚██████╗               ║
    ║     ╚═╝       ╚══════╝ ╚══════╝  ╚═════╝               ║
    ║                                                          ║
    ║        ALL-IN-ONE CYBER DEFENSE PLATFORM                ║
    ║                                    Go + Rust             ║
    ║                                                          ║
    ╚══════════════════════════════════════════════════════════╝
`
	}
	return "\033[36m" + `
    ╔══════════════════════════════════════════════════════════╗
    ║                                                          ║
    ║` + "\033[97m" + `     ██╗       ███████╗ ███████╗  ██████╗` + "\033[36m" + `              ║
    ║` + "\033[97m" + `    ███║       ██╔════╝ ██╔════╝ ██╔════╝` + "\033[36m" + `              ║
    ║` + "\033[91m" + `    ╚██║ █████╗███████╗ █████╗   ██║     ` + "\033[36m" + `              ║
    ║` + "\033[91m" + `     ██║ ╚════╝╚════██║ ██╔══╝   ██║     ` + "\033[36m" + `              ║
    ║` + "\033[93m" + `     ██║       ███████║ ███████╗ ╚██████╗` + "\033[36m" + `              ║
    ║` + "\033[93m" + `     ╚═╝       ╚══════╝ ╚══════╝  ╚═════╝` + "\033[36m" + `             ║
    ║                                                          ║
    ║` + "\033[97m" + `        ALL-IN-ONE CYBER DEFENSE PLATFORM` + "\033[36m" + `               ║
    ║` + "\033[90m" + `                                    Go + Rust` + "\033[36m" + `            ║
    ║                                                          ║
    ╚══════════════════════════════════════════════════════════╝` + "\033[0m" + `
`
}

// ---------------------------------------------------------------------------
// Error / warn helpers (always to stderr)
// ---------------------------------------------------------------------------

func errorf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, red("error: ")+format+"\n", args...)
	os.Exit(1)
}

func warnf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, yellow("warn: ")+format+"\n", args...)
}

// ---------------------------------------------------------------------------
// Output helper — writes to file if --output is set, otherwise stdout
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

// ---------------------------------------------------------------------------
// main dispatch
// ---------------------------------------------------------------------------

func main() {
	if len(os.Args) >= 2 {
		switch os.Args[1] {
		case "--version", "-V":
			printVersion(os.Stdout)
			os.Exit(0)
		case "--help", "-h", "help":
			if len(os.Args) >= 3 {
				cmdHelp(os.Args[2])
			} else {
				printUsage(os.Stdout)
			}
			os.Exit(0)
		}
	}

	if len(os.Args) < 2 {
		printUsage(os.Stdout)
		os.Exit(0)
	}

	subcmd := os.Args[1]
	args := os.Args[2:]

	// Handle -h / --help appended to any subcommand
	for _, a := range args {
		if a == "-h" || a == "--help" {
			cmdHelp(subcmd)
			os.Exit(0)
		}
	}

	switch subcmd {
	case "up":
		cmdUp(args)
	case "status":
		cmdStatus(args)
	case "alerts":
		cmdAlerts(args)
	case "scan":
		cmdScan(args)
	case "modules":
		cmdModules(args)
	case "config":
		cmdConfig(args)
	case "check":
		cmdCheck(args)
	case "stop":
		cmdStop(args)
	case "docker":
		cmdDocker(args)
	case "version":
		printVersion(os.Stdout)
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, red("error: ")+"unknown command %q\n\n", subcmd)
		if s := suggest(subcmd); s != "" {
			fmt.Fprintf(os.Stderr, "       Did you mean %s?\n\n", bold(s))
		}
		printUsage(os.Stderr)
		os.Exit(1)
	}
}

func suggest(input string) string {
	cmds := []string{"up", "status", "alerts", "scan", "modules", "config", "check", "stop", "docker", "version", "help"}
	input = strings.ToLower(input)
	for _, c := range cmds {
		if strings.HasPrefix(c, input) || strings.HasPrefix(input, c) {
			return c
		}
	}
	// Levenshtein-ish: single char difference
	for _, c := range cmds {
		if len(c) == len(input) {
			diff := 0
			for i := range c {
				if c[i] != input[i] {
					diff++
				}
			}
			if diff <= 1 {
				return c
			}
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// printVersion — includes build metadata (commit, date, Go version)
// ---------------------------------------------------------------------------

func printVersion(w io.Writer) {
	fmt.Fprintf(w, "1sec v%s", version)
	if commit != "dev" {
		fmt.Fprintf(w, " (%s)", commit[:min(7, len(commit))])
	}
	if buildDate != "unknown" {
		fmt.Fprintf(w, " built %s", buildDate)
	}
	// Go version from runtime
	if bi, ok := debug.ReadBuildInfo(); ok {
		fmt.Fprintf(w, " %s", bi.GoVersion)
	}
	fmt.Fprintln(w)
}

// ---------------------------------------------------------------------------
// printUsage
// ---------------------------------------------------------------------------

func printUsage(w io.Writer) {
	fmt.Fprint(w, bannerText())
	fmt.Fprintf(w, "  %s\n\n", dim("v"+version))
	fmt.Fprintf(w, "%s\n\n", bold("USAGE"))
	fmt.Fprintf(w, "  1sec <command> [flags]\n\n")
	fmt.Fprintf(w, "%s\n\n", bold("COMMANDS"))
	fmt.Fprintf(w, "  %-12s  %s\n", bold("up"), "Start the 1SEC engine with all enabled modules")
	fmt.Fprintf(w, "  %-12s  %s\n", bold("status"), "Show status of a running 1SEC instance")
	fmt.Fprintf(w, "  %-12s  %s\n", bold("alerts"), "Fetch recent alerts from a running instance")
	fmt.Fprintf(w, "  %-12s  %s\n", bold("scan"), "Submit a payload for on-demand analysis")
	fmt.Fprintf(w, "  %-12s  %s\n", bold("modules"), "List all available defense modules")
	fmt.Fprintf(w, "  %-12s  %s\n", bold("config"), "Show or validate the resolved configuration")
	fmt.Fprintf(w, "  %-12s  %s\n", bold("check"), "Run pre-flight diagnostics")
	fmt.Fprintf(w, "  %-12s  %s\n", bold("stop"), "Gracefully stop a running instance")
	fmt.Fprintf(w, "  %-12s  %s\n", bold("docker"), "Manage the 1SEC Docker deployment")
	fmt.Fprintf(w, "  %-12s  %s\n", bold("version"), "Print version and build info")
	fmt.Fprintf(w, "  %-12s  %s\n", bold("help"), "Show help for a command")
	fmt.Fprintf(w, "\n%s\n\n", bold("GLOBAL FLAGS"))
	fmt.Fprintf(w, "  %-20s  %s\n", "--config <path>", "Config file path (default: configs/default.yaml)")
	fmt.Fprintf(w, "  %-20s  %s\n", "--version, -V", "Print version and exit")
	fmt.Fprintf(w, "  %-20s  %s\n", "--help, -h", "Show help")
	fmt.Fprintf(w, "\n%s\n\n", bold("EXAMPLES"))
	fmt.Fprintf(w, "  %s\n", dim("# Start with defaults"))
	fmt.Fprintf(w, "  1sec up\n\n")
	fmt.Fprintf(w, "  %s\n", dim("# Start only specific modules"))
	fmt.Fprintf(w, "  1sec up --modules injection_shield,auth_fortress,network_guardian\n\n")
	fmt.Fprintf(w, "  %s\n", dim("# Check a running instance"))
	fmt.Fprintf(w, "  1sec status --json\n\n")
	fmt.Fprintf(w, "  %s\n", dim("# Fetch critical alerts, save to file"))
	fmt.Fprintf(w, "  1sec alerts --severity CRITICAL --json --output alerts.json\n\n")
	fmt.Fprintf(w, "  %s\n", dim("# Scan a payload"))
	fmt.Fprintf(w, "  echo '{\"input\": \"1 OR 1=1\"}' | 1sec scan --module injection_shield\n\n")
	fmt.Fprintf(w, "  %s\n", dim("# Pre-flight check"))
	fmt.Fprintf(w, "  1sec check\n\n")
	fmt.Fprintf(w, "Run %s for detailed help on any command.\n\n", bold("1sec help <command>"))
}

// ---------------------------------------------------------------------------
// cmdHelp — per-command help
// ---------------------------------------------------------------------------

func cmdHelp(subcmd string) {
	switch subcmd {
	case "up":
		fmt.Printf("%s\n\n", bold("1sec up"))
		fmt.Printf("Start the 1SEC engine with all enabled modules.\n\n")
		fmt.Printf("%s\n\n", bold("FLAGS"))
		fmt.Printf("  %-28s  %s\n", "--config <path>", "Config file (default: configs/default.yaml)")
		fmt.Printf("  %-28s  %s\n", "--modules <list>", "Comma-separated list of modules to enable (disables all others)")
		fmt.Printf("  %-28s  %s\n", "--log-level <level>", "Log level: debug, info, warn, error (default: from config)")
		fmt.Printf("  %-28s  %s\n", "--dry-run", "Validate config and modules, then exit without starting")
		fmt.Printf("  %-28s  %s\n", "-q, --quiet", "Suppress banner and non-essential output")
		fmt.Printf("  %-28s  %s\n", "--no-color", "Disable color output")
		fmt.Printf("\n%s\n\n", bold("EXAMPLES"))
		fmt.Printf("  1sec up\n")
		fmt.Printf("  1sec up --config /etc/1sec/prod.yaml\n")
		fmt.Printf("  1sec up --modules injection_shield,auth_fortress\n")
		fmt.Printf("  1sec up --log-level debug\n")
		fmt.Printf("  1sec up --dry-run\n")
	case "status":
		fmt.Printf("%s\n\n", bold("1sec status"))
		fmt.Printf("Fetch and display the status of a running 1SEC instance.\n\n")
		fmt.Printf("%s\n\n", bold("FLAGS"))
		fmt.Printf("  %-28s  %s\n", "--config <path>", "Config file to derive API address")
		fmt.Printf("  %-28s  %s\n", "--host <host>", "API host (overrides config)")
		fmt.Printf("  %-28s  %s\n", "--port <port>", "API port (overrides config)")
		fmt.Printf("  %-28s  %s\n", "--json", "Output raw JSON")
		fmt.Printf("  %-28s  %s\n", "--output <file>", "Write output to file instead of stdout")
		fmt.Printf("  %-28s  %s\n", "--timeout <duration>", "Request timeout (default: 5s)")
	case "alerts":
		fmt.Printf("%s\n\n", bold("1sec alerts"))
		fmt.Printf("Fetch recent alerts from a running 1SEC instance.\n\n")
		fmt.Printf("%s\n\n", bold("FLAGS"))
		fmt.Printf("  %-28s  %s\n", "--config <path>", "Config file to derive API address")
		fmt.Printf("  %-28s  %s\n", "--host <host>", "API host (overrides config)")
		fmt.Printf("  %-28s  %s\n", "--port <port>", "API port (overrides config)")
		fmt.Printf("  %-28s  %s\n", "--severity <level>", "Minimum severity: INFO, LOW, MEDIUM, HIGH, CRITICAL")
		fmt.Printf("  %-28s  %s\n", "--module <name>", "Filter alerts by source module")
		fmt.Printf("  %-28s  %s\n", "--limit <n>", "Maximum number of alerts (default: 20)")
		fmt.Printf("  %-28s  %s\n", "--json", "Output raw JSON")
		fmt.Printf("  %-28s  %s\n", "--output <file>", "Write output to file instead of stdout")
		fmt.Printf("  %-28s  %s\n", "--timeout <duration>", "Request timeout (default: 5s)")
		fmt.Printf("\n%s\n\n", bold("EXAMPLES"))
		fmt.Printf("  1sec alerts\n")
		fmt.Printf("  1sec alerts --severity HIGH --module injection_shield\n")
		fmt.Printf("  1sec alerts --severity CRITICAL --json --output alerts.json\n")
		fmt.Printf("  1sec alerts --limit 50\n")
	case "scan":
		fmt.Printf("%s\n\n", bold("1sec scan"))
		fmt.Printf("Submit a payload for on-demand analysis by a running 1SEC instance.\n")
		fmt.Printf("Reads from stdin or a file, sends it as a SecurityEvent to the event bus.\n\n")
		fmt.Printf("%s\n\n", bold("FLAGS"))
		fmt.Printf("  %-28s  %s\n", "--config <path>", "Config file to derive API address")
		fmt.Printf("  %-28s  %s\n", "--host <host>", "API host (overrides config)")
		fmt.Printf("  %-28s  %s\n", "--port <port>", "API port (overrides config)")
		fmt.Printf("  %-28s  %s\n", "--module <name>", "Module to attribute the event to (default: external)")
		fmt.Printf("  %-28s  %s\n", "--type <type>", "Event type (default: scan)")
		fmt.Printf("  %-28s  %s\n", "--severity <level>", "Event severity (default: MEDIUM)")
		fmt.Printf("  %-28s  %s\n", "--input <file>", "Read payload from file instead of stdin (use - for stdin)")
		fmt.Printf("  %-28s  %s\n", "--json", "Output raw JSON response")
		fmt.Printf("  %-28s  %s\n", "--timeout <duration>", "Request timeout (default: 10s)")
		fmt.Printf("\n%s\n\n", bold("EXAMPLES"))
		fmt.Printf("  echo '{\"query\": \"1 OR 1=1\"}' | 1sec scan --module injection_shield\n")
		fmt.Printf("  1sec scan --input payload.json --module llm_firewall --type prompt_check\n")
		fmt.Printf("  curl -s https://example.com/api | 1sec scan --module api_fortress\n")
	case "modules":
		fmt.Printf("%s\n\n", bold("1sec modules"))
		fmt.Printf("List all 16 available defense modules.\n\n")
		fmt.Printf("%s\n\n", bold("FLAGS"))
		fmt.Printf("  %-28s  %s\n", "--json", "Output as JSON")
		fmt.Printf("  %-28s  %s\n", "--tier <n>", "Filter by tier number (1-6)")
	case "config":
		fmt.Printf("%s\n\n", bold("1sec config"))
		fmt.Printf("Show the fully resolved configuration (with defaults applied).\n\n")
		fmt.Printf("%s\n\n", bold("FLAGS"))
		fmt.Printf("  %-28s  %s\n", "--config <path>", "Config file to load")
		fmt.Printf("  %-28s  %s\n", "--validate", "Validate config and exit (exit 0 = valid)")
		fmt.Printf("  %-28s  %s\n", "--json", "Output as JSON")
		fmt.Printf("  %-28s  %s\n", "--output <file>", "Write output to file")
	case "check":
		fmt.Printf("%s\n\n", bold("1sec check"))
		fmt.Printf("Run pre-flight diagnostics to verify the system is ready.\n\n")
		fmt.Printf("Checks:\n")
		fmt.Printf("  - Config file is valid and loadable\n")
		fmt.Printf("  - API port is available (not already in use)\n")
		fmt.Printf("  - NATS port is available\n")
		fmt.Printf("  - Data directory is writable\n")
		fmt.Printf("  - AI API keys are configured (if AI engine is enabled)\n")
		fmt.Printf("  - Rust engine binary is available (if enabled)\n\n")
		fmt.Printf("%s\n\n", bold("FLAGS"))
		fmt.Printf("  %-28s  %s\n", "--config <path>", "Config file to check")
		fmt.Printf("  %-28s  %s\n", "--json", "Output results as JSON")
	case "stop":
		fmt.Printf("%s\n\n", bold("1sec stop"))
		fmt.Printf("Gracefully stop a running 1SEC instance via the API.\n\n")
		fmt.Printf("%s\n\n", bold("FLAGS"))
		fmt.Printf("  %-28s  %s\n", "--config <path>", "Config file to derive API address")
		fmt.Printf("  %-28s  %s\n", "--host <host>", "API host (overrides config)")
		fmt.Printf("  %-28s  %s\n", "--port <port>", "API port (overrides config)")
		fmt.Printf("  %-28s  %s\n", "--timeout <duration>", "Request timeout (default: 5s)")
	case "docker":
		fmt.Printf("%s\n\n", bold("1sec docker"))
		fmt.Printf("Manage the 1SEC Docker Compose deployment.\n\n")
		fmt.Printf("%s\n\n", bold("SUBCOMMANDS"))
		fmt.Printf("  %-20s  %s\n", "up", "Start 1SEC via Docker Compose (detached)")
		fmt.Printf("  %-20s  %s\n", "down", "Stop and remove containers")
		fmt.Printf("  %-20s  %s\n", "logs", "Follow container logs")
		fmt.Printf("  %-20s  %s\n", "status", "Show container status")
		fmt.Printf("  %-20s  %s\n", "build", "Build the Docker image from source")
		fmt.Printf("  %-20s  %s\n", "pull", "Pull the latest image from registry")
		fmt.Printf("\n%s\n\n", bold("FLAGS"))
		fmt.Printf("  %-28s  %s\n", "--compose-file <path>", "Path to docker-compose.yml (default: deploy/docker/docker-compose.yml)")
		fmt.Printf("  %-28s  %s\n", "--env-file <path>", "Path to .env file (default: .env)")
		fmt.Printf("\n%s\n\n", bold("EXAMPLES"))
		fmt.Printf("  1sec docker up\n")
		fmt.Printf("  1sec docker logs\n")
		fmt.Printf("  1sec docker status\n")
		fmt.Printf("  1sec docker down\n")
		fmt.Printf("  1sec docker build\n")
	default:
		fmt.Fprintf(os.Stderr, red("error: ")+"unknown command %q — run '1sec help' for usage\n", subcmd)
		os.Exit(1)
	}
}

// ---------------------------------------------------------------------------
// API helpers
// ---------------------------------------------------------------------------

func apiBase(configPath, hostOverride string, portOverride int) string {
	host := "127.0.0.1"
	port := 1780

	cfg, err := core.LoadConfig(configPath)
	if err == nil && cfg != nil {
		if cfg.Server.Host != "" && cfg.Server.Host != "0.0.0.0" {
			host = cfg.Server.Host
		}
		if cfg.Server.Port != 0 {
			port = cfg.Server.Port
		}
	}

	if hostOverride != "" {
		host = hostOverride
	}
	if portOverride != 0 {
		port = portOverride
	}

	return fmt.Sprintf("http://%s:%d", host, port)
}

func apiGet(url string, timeout time.Duration) ([]byte, error) {
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("connecting to 1SEC API at %s: %w", url, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return body, fmt.Errorf("API returned HTTP %d: %s", resp.StatusCode, string(body))
	}
	return body, nil
}

func apiPost(url string, payload []byte, timeout time.Duration) ([]byte, error) {
	client := &http.Client{Timeout: timeout}
	resp, err := client.Post(url, "application/json", strings.NewReader(string(payload)))
	if err != nil {
		return nil, fmt.Errorf("connecting to 1SEC API at %s: %w", url, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return body, fmt.Errorf("API returned HTTP %d: %s", resp.StatusCode, string(body))
	}
	return body, nil
}

// ---------------------------------------------------------------------------
// registerModules — registers all 16 modules with the engine
// ---------------------------------------------------------------------------

func registerModules(engine *core.Engine) {
	modules := []core.Module{
		network.New(),
		apifortress.New(),
		iot.New(),
		injection.New(),
		supplychain.New(),
		ransomware.New(),
		auth.New(),
		deepfake.New(),
		identity.New(),
		llmfirewall.New(),
		aicontainment.New(),
		datapoisoning.New(),
		quantumcrypto.New(),
		runtime.New(),
		cloudposture.New(),
		aiengine.New(),
	}
	for _, mod := range modules {
		if err := engine.Registry.Register(mod); err != nil {
			engine.Logger.Warn().Err(err).Str("module", mod.Name()).Msg("failed to register module")
		}
	}
}

// ---------------------------------------------------------------------------
// cmdUp — start the 1SEC engine
// ---------------------------------------------------------------------------

func cmdUp(args []string) {
	fs := flag.NewFlagSet("up", flag.ExitOnError)
	configPath := fs.String("config", "configs/default.yaml", "Config file path")
	moduleList := fs.String("modules", "", "Comma-separated list of modules to enable (disables all others)")
	logLevel := fs.String("log-level", "", "Log level override: debug, info, warn, error")
	dryRun := fs.Bool("dry-run", false, "Validate config and modules, then exit")
	quiet := fs.Bool("quiet", false, "Suppress banner and non-essential output")
	fs.BoolVar(quiet, "q", false, "Suppress banner and non-essential output")
	noColor := fs.Bool("no-color", false, "Disable color output")
	fs.Parse(args)

	if *noColor {
		os.Setenv("NO_COLOR", "1")
	}

	if !*quiet {
		fmt.Fprint(os.Stderr, bannerText())
	}

	// Load config
	cfg, err := core.LoadConfig(*configPath)
	if err != nil {
		errorf("loading config: %v", err)
	}

	// Override log level if specified
	if *logLevel != "" {
		cfg.Logging.Level = *logLevel
	}

	// Selective module enabling: disable everything, then enable only the listed ones
	if *moduleList != "" {
		selected := make(map[string]bool)
		for _, name := range strings.Split(*moduleList, ",") {
			name = strings.TrimSpace(name)
			if name != "" {
				selected[name] = true
			}
		}
		for key, mod := range cfg.Modules {
			mod.Enabled = selected[key]
			cfg.Modules[key] = mod
		}
	}

	// Create engine
	engine, err := core.NewEngine(cfg)
	if err != nil {
		errorf("creating engine: %v", err)
	}

	// Pass config path so the Rust sidecar can read the same config
	engine.SetConfigPath(*configPath)

	// Register all modules
	registerModules(engine)

	// Dry run: validate and exit
	if *dryRun {
		enabled := 0
		for _, mod := range engine.Registry.All() {
			if cfg.IsModuleEnabled(mod.Name()) {
				enabled++
			}
		}
		fmt.Fprintf(os.Stdout, "%s Config valid. %d/%d modules enabled.\n",
			green("✓"), enabled, engine.Registry.Count())
		os.Exit(0)
	}

	if !*quiet {
		fmt.Fprintf(os.Stderr, "%s Starting 1SEC engine...\n", dim("▸"))
	}

	// Start API server
	srv := api.NewServer(engine)
	if err := srv.Start(); err != nil {
		errorf("starting API server: %v", err)
	}

	// Start engine (event bus + modules)
	if err := engine.Start(); err != nil {
		errorf("starting engine: %v", err)
	}

	// Start syslog ingestion if enabled
	var syslogSrv *ingest.SyslogServer
	if cfg.Syslog.Enabled {
		syslogSrv = ingest.NewSyslogServer(&cfg.Syslog, engine.Bus, engine.Logger)
		if err := syslogSrv.Start(engine.Context()); err != nil {
			errorf("starting syslog ingestion: %v", err)
		}
		if !*quiet {
			fmt.Fprintf(os.Stderr, "%s Syslog ingestion on :%d (%s)\n",
				green("✓"), cfg.Syslog.Port, cfg.Syslog.Protocol)
		}
	}

	if !*quiet {
		rustStatus := ""
		if cfg.RustEngine.Enabled && engine.RustSidecar != nil && engine.RustSidecar.Running() {
			rustStatus = fmt.Sprintf(", rust engine %s", green("active"))
		}
		fmt.Fprintf(os.Stderr, "%s 1SEC running — %d modules active, API on :%d%s\n",
			green("✓"), engine.Registry.Count(), cfg.Server.Port, rustStatus)
		fmt.Fprintf(os.Stderr, "%s Press Ctrl+C to stop\n", dim("▸"))
	}

	// Block until signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh

	if !*quiet {
		fmt.Fprintf(os.Stderr, "\n%s Received %s, shutting down...\n", dim("▸"), sig)
	}

	if syslogSrv != nil {
		syslogSrv.Stop()
	}
	srv.Stop()
	engine.Shutdown()

	if !*quiet {
		fmt.Fprintf(os.Stderr, "%s 1SEC stopped.\n", green("✓"))
	}
}

// ---------------------------------------------------------------------------
// cmdStatus — fetch status from a running instance
// ---------------------------------------------------------------------------

func cmdStatus(args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	configPath := fs.String("config", "configs/default.yaml", "Config file path")
	host := fs.String("host", "", "API host override")
	port := fs.Int("port", 0, "API port override")
	jsonOut := fs.Bool("json", false, "Output raw JSON")
	output := fs.String("output", "", "Write output to file")
	timeoutStr := fs.String("timeout", "5s", "Request timeout")
	fs.Parse(args)

	timeout, err := time.ParseDuration(*timeoutStr)
	if err != nil {
		errorf("invalid timeout %q: %v", *timeoutStr, err)
	}

	base := apiBase(*configPath, *host, *port)
	body, err := apiGet(base+"/api/v1/status", timeout)
	if err != nil {
		errorf("%v", err)
	}

	w, cleanup := outputWriter(*output)
	defer cleanup()

	if *jsonOut {
		fmt.Fprintln(w, string(body))
		return
	}

	var status map[string]interface{}
	if err := json.Unmarshal(body, &status); err != nil {
		errorf("parsing response: %v", err)
	}

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

// ---------------------------------------------------------------------------
// cmdAlerts — fetch alerts from a running instance
// ---------------------------------------------------------------------------

func cmdAlerts(args []string) {
	fs := flag.NewFlagSet("alerts", flag.ExitOnError)
	configPath := fs.String("config", "configs/default.yaml", "Config file path")
	host := fs.String("host", "", "API host override")
	port := fs.Int("port", 0, "API port override")
	severity := fs.String("severity", "", "Minimum severity: INFO, LOW, MEDIUM, HIGH, CRITICAL")
	module := fs.String("module", "", "Filter by source module")
	limit := fs.Int("limit", 20, "Maximum alerts to fetch")
	jsonOut := fs.Bool("json", false, "Output raw JSON")
	output := fs.String("output", "", "Write output to file")
	timeoutStr := fs.String("timeout", "5s", "Request timeout")
	fs.Parse(args)

	timeout, err := time.ParseDuration(*timeoutStr)
	if err != nil {
		errorf("invalid timeout %q: %v", *timeoutStr, err)
	}

	base := apiBase(*configPath, *host, *port)
	url := fmt.Sprintf("%s/api/v1/alerts?limit=%d", base, *limit)
	if *severity != "" {
		url += "&min_severity=" + strings.ToUpper(*severity)
	}

	body, err := apiGet(url, timeout)
	if err != nil {
		errorf("%v", err)
	}

	w, cleanup := outputWriter(*output)
	defer cleanup()

	// Client-side module filter
	if *module != "" && !*jsonOut {
		var resp map[string]interface{}
		if err := json.Unmarshal(body, &resp); err != nil {
			errorf("parsing response: %v", err)
		}
		alerts, _ := resp["alerts"].([]interface{})
		filtered := make([]interface{}, 0)
		for _, a := range alerts {
			alert := a.(map[string]interface{})
			if fmt.Sprintf("%v", alert["module"]) == *module {
				filtered = append(filtered, a)
			}
		}
		resp["alerts"] = filtered
		resp["total"] = len(filtered)
		body, _ = json.MarshalIndent(resp, "", "  ")
	}

	if *jsonOut {
		if *module != "" {
			// Re-filter for JSON output too
			var resp map[string]interface{}
			json.Unmarshal(body, &resp)
			alerts, _ := resp["alerts"].([]interface{})
			filtered := make([]interface{}, 0)
			for _, a := range alerts {
				alert := a.(map[string]interface{})
				if fmt.Sprintf("%v", alert["module"]) == *module {
					filtered = append(filtered, a)
				}
			}
			resp["alerts"] = filtered
			resp["total"] = len(filtered)
			body, _ = json.MarshalIndent(resp, "", "  ")
		}
		fmt.Fprintln(w, string(body))
		return
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(body, &resp); err != nil {
		errorf("parsing response: %v", err)
	}

	alerts, _ := resp["alerts"].([]interface{})
	if len(alerts) == 0 {
		fmt.Fprintf(w, "%s No alerts found.\n", dim("▸"))
		return
	}

	fmt.Fprintf(w, "%s Alerts (%d)\n\n", bold("🔔"), len(alerts))
	for _, a := range alerts {
		alert := a.(map[string]interface{})
		sev := fmt.Sprintf("%v", alert["severity"])
		sevColor := dim
		switch sev {
		case "CRITICAL":
			sevColor = red
		case "HIGH":
			sevColor = red
		case "MEDIUM":
			sevColor = yellow
		case "LOW":
			sevColor = cyan
		}
		fmt.Fprintf(w, "  %s [%s] %s\n", sevColor("●"), sevColor(fmt.Sprintf("%-8s", sev)), alert["title"])
		fmt.Fprintf(w, "    %s  %s  %s\n",
			dim(fmt.Sprintf("module=%v", alert["module"])),
			dim(fmt.Sprintf("type=%v", alert["type"])),
			dim(fmt.Sprintf("id=%v", alert["id"])))
		if desc, ok := alert["description"]; ok && desc != "" {
			fmt.Fprintf(w, "    %s\n", desc)
		}
		fmt.Fprintln(w)
	}
}

// ---------------------------------------------------------------------------
// cmdScan — submit a payload for on-demand analysis
// ---------------------------------------------------------------------------

func cmdScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	configPath := fs.String("config", "configs/default.yaml", "Config file path")
	host := fs.String("host", "", "API host override")
	port := fs.Int("port", 0, "API port override")
	module := fs.String("module", "external", "Module to attribute the event to")
	eventType := fs.String("type", "scan", "Event type")
	severity := fs.String("severity", "MEDIUM", "Event severity")
	inputFile := fs.String("input", "-", "Read payload from file (- for stdin)")
	jsonOut := fs.Bool("json", false, "Output raw JSON response")
	timeoutStr := fs.String("timeout", "10s", "Request timeout")
	fs.Parse(args)

	timeout, err := time.ParseDuration(*timeoutStr)
	if err != nil {
		errorf("invalid timeout %q: %v", *timeoutStr, err)
	}

	// Read payload from stdin or file
	var reader io.Reader
	if *inputFile == "-" || *inputFile == "" {
		// Check if stdin has data
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

	// Parse severity
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

	// Build the event
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

	// Try to parse payload as JSON and merge into Details
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

	base := apiBase(*configPath, *host, *port)
	body, err := apiPost(base+"/api/v1/events", eventJSON, timeout)
	if err != nil {
		errorf("%v", err)
	}

	if *jsonOut {
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

// ---------------------------------------------------------------------------
// cmdModules — list all defense modules
// ---------------------------------------------------------------------------

func cmdModules(args []string) {
	fs := flag.NewFlagSet("modules", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "Output as JSON")
	tier := fs.Int("tier", 0, "Filter by tier (1-6)")
	fs.Parse(args)

	type moduleInfo struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Tier        int    `json:"tier"`
		TierName    string `json:"tier_name"`
	}

	all := []moduleInfo{
		{"network_guardian", "DDoS mitigation, rate limiting, IP reputation, geo-fencing", 1, "Network & Perimeter"},
		{"api_fortress", "BOLA detection, schema validation, shadow API discovery", 1, "Network & Perimeter"},
		{"iot_shield", "Device fingerprinting, protocol anomaly, firmware integrity", 1, "Network & Perimeter"},
		{"injection_shield", "SQLi, XSS, SSRF, command injection, template injection, NoSQL injection, path traversal", 2, "Application Layer"},
		{"supply_chain", "SBOM analysis, package integrity, CI/CD hardening, typosquatting detection", 2, "Application Layer"},
		{"ransomware", "Encryption detection, canary files, exfiltration detection", 2, "Application Layer"},
		{"auth_fortress", "Brute force, credential stuffing, session theft, MFA bypass detection", 3, "Identity & Access"},
		{"deepfake_shield", "Synthetic voice/video detection, AI phishing detection", 3, "Identity & Access"},
		{"identity_monitor", "Synthetic identity, privilege escalation, service account monitoring", 3, "Identity & Access"},
		{"llm_firewall", "Prompt injection, output filtering, jailbreak detection", 4, "AI-Specific Defense"},
		{"ai_containment", "Action sandboxing, shadow AI detection", 4, "AI-Specific Defense"},
		{"data_poisoning", "Training data integrity, RAG verification, adversarial input detection", 4, "AI-Specific Defense"},
		{"quantum_crypto", "Crypto inventory, PQC migration readiness, crypto-agility", 5, "Cryptography"},
		{"runtime_watcher", "File integrity, container escape, privilege escalation detection", 6, "Runtime & Infrastructure"},
		{"cloud_posture", "Config drift, misconfiguration, secrets sprawl detection", 6, "Runtime & Infrastructure"},
		{"ai_analysis_engine", "Two-tier LLM pipeline: triage + deep classification", 0, "Cross-Cutting"},
	}

	// Filter by tier
	filtered := all
	if *tier > 0 {
		filtered = make([]moduleInfo, 0)
		for _, m := range all {
			if m.Tier == *tier {
				filtered = append(filtered, m)
			}
		}
	}

	if *jsonOut {
		data, _ := json.MarshalIndent(map[string]interface{}{
			"modules": filtered,
			"total":   len(filtered),
		}, "", "  ")
		fmt.Println(string(data))
		return
	}

	fmt.Printf("%s Defense Modules (%d)\n\n", bold("🛡"), len(filtered))
	currentTier := -1
	for _, m := range filtered {
		if m.Tier != currentTier {
			currentTier = m.Tier
			tierLabel := m.TierName
			if m.Tier > 0 {
				tierLabel = fmt.Sprintf("Tier %d: %s", m.Tier, m.TierName)
			}
			fmt.Printf("  %s\n", bold(tierLabel))
		}
		fmt.Printf("    %s %-24s %s\n", cyan("●"), m.Name, dim(m.Description))
	}
	fmt.Println()
}

// ---------------------------------------------------------------------------
// cmdConfig — show or validate resolved configuration
// ---------------------------------------------------------------------------

func cmdConfig(args []string) {
	fs := flag.NewFlagSet("config", flag.ExitOnError)
	configPath := fs.String("config", "configs/default.yaml", "Config file path")
	validate := fs.Bool("validate", false, "Validate config and exit")
	jsonOut := fs.Bool("json", false, "Output as JSON")
	output := fs.String("output", "", "Write output to file")
	fs.Parse(args)

	cfg, err := core.LoadConfig(*configPath)
	if err != nil {
		if *validate {
			fmt.Fprintf(os.Stderr, "%s Config invalid: %v\n", red("✗"), err)
			os.Exit(1)
		}
		errorf("loading config: %v", err)
	}

	if *validate {
		// Additional validation checks
		issues := make([]string, 0)
		if cfg.Server.Port < 1 || cfg.Server.Port > 65535 {
			issues = append(issues, fmt.Sprintf("server.port %d is out of range (1-65535)", cfg.Server.Port))
		}
		if cfg.Bus.Port < 1 || cfg.Bus.Port > 65535 {
			issues = append(issues, fmt.Sprintf("bus.port %d is out of range (1-65535)", cfg.Bus.Port))
		}
		if cfg.Server.Port == cfg.Bus.Port {
			issues = append(issues, fmt.Sprintf("server.port and bus.port are both %d — they must differ", cfg.Server.Port))
		}
		if cfg.Alerts.MaxStore < 1 {
			issues = append(issues, "alerts.max_store must be positive")
		}
		validLevels := map[string]bool{"debug": true, "info": true, "warn": true, "error": true}
		if !validLevels[cfg.LogLevel()] {
			issues = append(issues, fmt.Sprintf("logging.level %q is not valid (debug, info, warn, error)", cfg.Logging.Level))
		}

		if len(issues) > 0 {
			fmt.Fprintf(os.Stderr, "%s Config has %d issue(s):\n", red("✗"), len(issues))
			for _, issue := range issues {
				fmt.Fprintf(os.Stderr, "  - %s\n", issue)
			}
			os.Exit(1)
		}

		enabledCount := 0
		for _, mod := range cfg.Modules {
			if mod.Enabled {
				enabledCount++
			}
		}
		fmt.Fprintf(os.Stdout, "%s Config valid (%s). %d/%d modules enabled.\n",
			green("✓"), *configPath, enabledCount, len(cfg.Modules))
		os.Exit(0)
	}

	w, cleanup := outputWriter(*output)
	defer cleanup()

	if *jsonOut {
		data, err := json.MarshalIndent(cfg, "", "  ")
		if err != nil {
			errorf("marshaling config: %v", err)
		}
		fmt.Fprintln(w, string(data))
		return
	}

	// Pretty-print YAML
	data, err := yaml.Marshal(cfg)
	if err != nil {
		errorf("marshaling config: %v", err)
	}
	fmt.Fprint(w, string(data))
}

// ---------------------------------------------------------------------------
// cmdCheck — pre-flight diagnostics
// ---------------------------------------------------------------------------

func cmdCheck(args []string) {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	configPath := fs.String("config", "configs/default.yaml", "Config file path")
	jsonOut := fs.Bool("json", false, "Output as JSON")
	fs.Parse(args)

	type checkResult struct {
		Name   string `json:"name"`
		Status string `json:"status"` // "pass", "fail", "warn"
		Detail string `json:"detail,omitempty"`
	}

	results := make([]checkResult, 0)
	pass := func(name, detail string) { results = append(results, checkResult{name, "pass", detail}) }
	fail := func(name, detail string) { results = append(results, checkResult{name, "fail", detail}) }
	warn := func(name, detail string) { results = append(results, checkResult{name, "warn", detail}) }

	// 1. Config loadable
	cfg, err := core.LoadConfig(*configPath)
	if err != nil {
		fail("config", fmt.Sprintf("failed to load %s: %v", *configPath, err))
	} else {
		pass("config", fmt.Sprintf("loaded %s", *configPath))
	}

	if cfg != nil {
		// 2. API port available
		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.Server.Port))
		if err != nil {
			fail("api_port", fmt.Sprintf("port %d is already in use", cfg.Server.Port))
		} else {
			ln.Close()
			pass("api_port", fmt.Sprintf("port %d is available", cfg.Server.Port))
		}

		// 3. NATS port available (only if embedded)
		if cfg.Bus.Embedded {
			ln, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.Bus.Port))
			if err != nil {
				fail("nats_port", fmt.Sprintf("port %d is already in use", cfg.Bus.Port))
			} else {
				ln.Close()
				pass("nats_port", fmt.Sprintf("port %d is available", cfg.Bus.Port))
			}
		} else {
			pass("nats_port", "external NATS — skipped port check")
		}

		// 4. Data directory writable
		dataDir := cfg.Bus.DataDir
		if err := os.MkdirAll(dataDir, 0755); err != nil {
			fail("data_dir", fmt.Sprintf("cannot create %s: %v", dataDir, err))
		} else {
			testFile := dataDir + "/.1sec-check"
			if err := os.WriteFile(testFile, []byte("ok"), 0644); err != nil {
				fail("data_dir", fmt.Sprintf("cannot write to %s: %v", dataDir, err))
			} else {
				os.Remove(testFile)
				pass("data_dir", fmt.Sprintf("%s is writable", dataDir))
			}
		}

		// 5. AI API keys (if AI engine is enabled)
		if cfg.IsModuleEnabled("ai_analysis_engine") {
			hasKey := false
			settings := cfg.GetModuleSettings("ai_analysis_engine")
			if _, ok := settings["gemini_api_key"]; ok {
				hasKey = true
			}
			if keys, ok := settings["gemini_api_keys"]; ok {
				if arr, ok := keys.([]interface{}); ok && len(arr) > 0 {
					hasKey = true
				}
			}
			// Check environment variables
			for _, env := range []string{"GEMINI_API_KEY", "GEMINI_API_KEY_2", "GEMINI_API_KEY_3", "GEMINI_API_KEY_4"} {
				if os.Getenv(env) != "" {
					hasKey = true
					break
				}
			}
			if hasKey {
				pass("ai_keys", "Gemini API key(s) found")
			} else {
				warn("ai_keys", "no Gemini API keys configured — AI engine will not function (set GEMINI_API_KEY or configure in YAML)")
			}
		} else {
			pass("ai_keys", "AI engine disabled — key check skipped")
		}

		// 6. Port conflict check
		if cfg.Server.Port == cfg.Bus.Port {
			fail("port_conflict", fmt.Sprintf("API port (%d) and NATS port (%d) are the same", cfg.Server.Port, cfg.Bus.Port))
		} else {
			pass("port_conflict", "API and NATS ports are distinct")
		}

		// 7. Rust engine binary (if enabled)
		if cfg.RustEngine.Enabled {
			binary := cfg.RustEngine.Binary
			if binary == "" {
				binary = "1sec-engine"
			}
			if _, err := exec.LookPath(binary); err != nil {
				// Check common locations
				found := false
				for _, candidate := range []string{
					binary,
					"./1sec-engine",
					"./rust/1sec-engine/target/release/1sec-engine",
				} {
					if _, err := os.Stat(candidate); err == nil {
						found = true
						pass("rust_engine", fmt.Sprintf("binary found at %s", candidate))
						break
					}
				}
				if !found {
					warn("rust_engine", fmt.Sprintf("binary %q not found — build with: cd rust/1sec-engine && cargo build --release", binary))
				}
			} else {
				pass("rust_engine", fmt.Sprintf("binary %q found in PATH", binary))
			}
		} else {
			pass("rust_engine", "disabled — binary check skipped")
		}
	}

	// Output
	if *jsonOut {
		data, _ := json.MarshalIndent(map[string]interface{}{
			"checks": results,
			"total":  len(results),
		}, "", "  ")
		fmt.Println(string(data))
		return
	}

	fmt.Printf("%s Pre-flight Diagnostics\n\n", bold("🔍"))
	failures := 0
	warnings := 0
	for _, r := range results {
		var icon string
		switch r.Status {
		case "pass":
			icon = green("✓")
		case "fail":
			icon = red("✗")
			failures++
		case "warn":
			icon = yellow("!")
			warnings++
		}
		fmt.Printf("  %s %-16s %s\n", icon, r.Name, dim(r.Detail))
	}
	fmt.Println()

	if failures > 0 {
		fmt.Fprintf(os.Stderr, "%s %d check(s) failed. Fix issues before running '1sec up'.\n", red("✗"), failures)
		os.Exit(1)
	}
	if warnings > 0 {
		fmt.Printf("%s All checks passed with %d warning(s).\n", yellow("!"), warnings)
	} else {
		fmt.Printf("%s All checks passed. Ready to run '1sec up'.\n", green("✓"))
	}
}

// ---------------------------------------------------------------------------
// cmdStop — gracefully stop a running instance via API
// ---------------------------------------------------------------------------

func cmdStop(args []string) {
	fs := flag.NewFlagSet("stop", flag.ExitOnError)
	configPath := fs.String("config", "configs/default.yaml", "Config file path")
	host := fs.String("host", "", "API host override")
	port := fs.Int("port", 0, "API port override")
	timeoutStr := fs.String("timeout", "5s", "Request timeout")
	fs.Parse(args)

	timeout, err := time.ParseDuration(*timeoutStr)
	if err != nil {
		errorf("invalid timeout %q: %v", *timeoutStr, err)
	}

	base := apiBase(*configPath, *host, *port)

	// First check if the instance is reachable
	_, err = apiGet(base+"/health", timeout)
	if err != nil {
		errorf("cannot reach 1SEC instance at %s — is it running?", base)
	}

	// Send shutdown request
	body, err := apiPost(base+"/api/v1/shutdown", []byte("{}"), timeout)
	if err != nil {
		// Connection reset is expected — the server shuts down after responding
		if strings.Contains(err.Error(), "connection reset") ||
			strings.Contains(err.Error(), "EOF") ||
			strings.Contains(err.Error(), "connection refused") {
			fmt.Fprintf(os.Stdout, "%s 1SEC instance is shutting down.\n", green("✓"))
			return
		}
		errorf("shutdown request failed: %v", err)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(body, &resp); err != nil {
		fmt.Fprintf(os.Stdout, "%s Shutdown signal sent.\n", green("✓"))
		return
	}

	fmt.Fprintf(os.Stdout, "%s %s\n", green("✓"), resp["message"])
}

// ---------------------------------------------------------------------------
// cmdDocker — manage the Docker Compose deployment
// ---------------------------------------------------------------------------

func cmdDocker(args []string) {
	fs := flag.NewFlagSet("docker", flag.ExitOnError)
	composeFile := fs.String("compose-file", "deploy/docker/docker-compose.yml", "Path to docker-compose.yml")
	envFile := fs.String("env-file", ".env", "Path to .env file")
	fs.Parse(args)

	subcmds := fs.Args()
	if len(subcmds) == 0 {
		cmdHelp("docker")
		os.Exit(0)
	}

	sub := subcmds[0]

	// Build the base docker compose command args
	baseArgs := []string{"compose", "--file", *composeFile}
	if _, err := os.Stat(*envFile); err == nil {
		baseArgs = append(baseArgs, "--env-file", *envFile)
	}

	var dockerArgs []string
	switch sub {
	case "up":
		dockerArgs = append(baseArgs, "up", "--detach", "--remove-orphans")
		fmt.Fprintf(os.Stderr, "%s Starting 1SEC via Docker Compose...\n", dim("▸"))
	case "down":
		dockerArgs = append(baseArgs, "down")
		fmt.Fprintf(os.Stderr, "%s Stopping 1SEC containers...\n", dim("▸"))
	case "logs":
		dockerArgs = append(baseArgs, "logs", "--follow", "--tail=100")
	case "status":
		dockerArgs = append(baseArgs, "ps")
	case "build":
		dockerArgs = append(baseArgs, "build", "--no-cache")
		fmt.Fprintf(os.Stderr, "%s Building 1SEC Docker image from source...\n", dim("▸"))
	case "pull":
		dockerArgs = append(baseArgs, "pull")
		fmt.Fprintf(os.Stderr, "%s Pulling latest 1SEC image...\n", dim("▸"))
	default:
		fmt.Fprintf(os.Stderr, red("error: ")+"unknown docker subcommand %q\n\n", sub)
		cmdHelp("docker")
		os.Exit(1)
	}

	// Exec docker with the constructed args — replaces current process so
	// signals (Ctrl+C) pass through naturally to docker compose.
	if err := execDocker(dockerArgs); err != nil {
		errorf("docker %s failed: %v", sub, err)
	}
}

// execDocker runs `docker <args>` by finding the docker binary in PATH.
func execDocker(args []string) error {
	dockerBin, err := findExecutable("docker")
	if err != nil {
		return fmt.Errorf("docker not found in PATH — install Docker from https://docs.docker.com/get-docker/")
	}
	return runSubprocess(dockerBin, args)
}

// findExecutable searches PATH for the named binary.
func findExecutable(name string) (string, error) {
	pathEnv := os.Getenv("PATH")
	if pathEnv == "" {
		return "", fmt.Errorf("%s not found", name)
	}
	sep := ":"
	if os.PathSeparator == '\\' {
		sep = ";"
		name += ".exe"
	}
	for _, dir := range strings.Split(pathEnv, sep) {
		full := dir + string(os.PathSeparator) + name
		if fi, err := os.Stat(full); err == nil && !fi.IsDir() {
			return full, nil
		}
	}
	return "", fmt.Errorf("%s not found in PATH", name)
}

// runSubprocess runs an external binary with args, streaming stdout/stderr
// directly to the terminal. Blocks until the process exits.
func runSubprocess(bin string, args []string) error {
	cmd := exec.Command(bin, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		return err
	}
	return nil
}
