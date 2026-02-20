package main

// ---------------------------------------------------------------------------
// cmd_profile.go — named configuration profiles (Recommendation #6)
//
// Profiles are stored in ~/.1sec/profiles/<name>.yaml and allow operators
// to switch between environments (dev, staging, prod) without passing
// --config --host --port every time.
//
// Usage:
//   1sec profile list                     — list all profiles
//   1sec profile create <name>            — create a profile interactively
//   1sec profile show <name>              — show a profile's config path
//   1sec profile delete <name>            — delete a profile
//   1sec profile use <name>               — set as default (writes ONESEC_PROFILE)
//
// Any command can use --profile <name> to load that profile's config.
// ---------------------------------------------------------------------------

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// profileDir returns the directory where profiles are stored.
func profileDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, ".1sec", "profiles")
}

// profilePath returns the full path for a named profile.
func profilePath(name string) string {
	return filepath.Join(profileDir(), name+".yaml")
}

// resolveProfile returns the config path for a given profile name.
// If profileName is empty, checks ONESEC_PROFILE env, then falls back to configPath.
func resolveProfile(profileName, configPath string) string {
	if profileName == "" {
		profileName = os.Getenv("ONESEC_PROFILE")
	}
	if profileName == "" {
		return configPath
	}

	pp := profilePath(profileName)
	if _, err := os.Stat(pp); err != nil {
		warnf("profile %q not found at %s, falling back to %s", profileName, pp, configPath)
		return configPath
	}
	return pp
}

type profileMeta struct {
	Name        string `json:"name" yaml:"name"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	ConfigPath  string `json:"config_path" yaml:"config_path"`
}

func cmdProfile(args []string) {
	if len(args) == 0 {
		cmdProfileList()
		return
	}

	switch args[0] {
	case "list", "ls":
		cmdProfileList()
	case "create", "add":
		cmdProfileCreate(args[1:])
	case "show":
		cmdProfileShow(args[1:])
	case "delete", "rm":
		cmdProfileDelete(args[1:])
	case "use":
		cmdProfileUse(args[1:])
	default:
		errorf("unknown profile subcommand %q — try: list, create, show, delete, use", args[0])
	}
}

func cmdProfileList() {
	dir := profileDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Printf("%s No profiles found. Create one with: 1sec profile create <name>\n", dim("▸"))
			return
		}
		errorf("reading profiles directory: %v", err)
	}

	profiles := make([]profileMeta, 0)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".yaml")
		profiles = append(profiles, profileMeta{
			Name:       name,
			ConfigPath: filepath.Join(dir, e.Name()),
		})
	}

	if len(profiles) == 0 {
		fmt.Printf("%s No profiles found. Create one with: 1sec profile create <name>\n", dim("▸"))
		return
	}

	current := os.Getenv("ONESEC_PROFILE")

	fmt.Printf("%s Profiles (%d)\n\n", bold("👤"), len(profiles))
	tbl := NewTable(os.Stdout, "NAME", "PATH", "ACTIVE")
	for _, p := range profiles {
		active := ""
		if p.Name == current {
			active = green("●")
		}
		tbl.AddRow(p.Name, p.ConfigPath, active)
	}
	tbl.Render()
	fmt.Println()
}

func cmdProfileCreate(args []string) {
	fs := flag.NewFlagSet("profile-create", flag.ExitOnError)
	desc := fs.String("description", "", "Profile description")
	from := fs.String("from", "", "Copy config from existing file")
	minimal := fs.Bool("minimal", false, "Generate minimal config")
	fs.Parse(args)

	remaining := fs.Args()
	if len(remaining) == 0 {
		errorf("profile name required — usage: 1sec profile create <name>")
	}
	name := remaining[0]

	// Validate name
	if strings.ContainsAny(name, "/\\. ") {
		errorf("profile name must not contain slashes, dots, or spaces")
	}

	pp := profilePath(name)
	if _, err := os.Stat(pp); err == nil {
		errorf("profile %q already exists at %s", name, pp)
	}

	// Ensure directory exists
	if err := os.MkdirAll(profileDir(), 0755); err != nil {
		errorf("creating profiles directory: %v", err)
	}

	var content string
	if *from != "" {
		data, err := os.ReadFile(*from)
		if err != nil {
			errorf("reading source config %q: %v", *from, err)
		}
		content = string(data)
	} else if *minimal {
		content = minimalConfig()
	} else {
		content = fullConfig()
	}

	// Prepend profile metadata as a comment
	header := fmt.Sprintf("# 1SEC Profile: %s\n", name)
	if *desc != "" {
		header += fmt.Sprintf("# Description: %s\n", *desc)
	}
	header += "#\n"

	if err := os.WriteFile(pp, []byte(header+content), 0644); err != nil {
		errorf("writing profile: %v", err)
	}

	fmt.Fprintf(os.Stdout, "%s Profile %s created at %s\n", green("✓"), bold(name), pp)
	fmt.Fprintf(os.Stdout, "%s Use with: 1sec --profile %s <command>\n", dim("▸"), name)
}

func cmdProfileShow(args []string) {
	fs := flag.NewFlagSet("profile-show", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "Output as JSON")
	fs.Parse(args)

	remaining := fs.Args()
	if len(remaining) == 0 {
		errorf("profile name required — usage: 1sec profile show <name>")
	}
	name := remaining[0]

	pp := profilePath(name)
	if _, err := os.Stat(pp); err != nil {
		errorf("profile %q not found", name)
	}

	if *jsonOut {
		data, _ := json.MarshalIndent(profileMeta{
			Name:       name,
			ConfigPath: pp,
		}, "", "  ")
		fmt.Println(string(data))
		return
	}

	// Read and display the config
	data, err := os.ReadFile(pp)
	if err != nil {
		errorf("reading profile: %v", err)
	}

	fmt.Printf("%s Profile: %s\n", bold("👤"), bold(name))
	fmt.Printf("  Path: %s\n\n", pp)

	// Parse and show key settings
	var raw map[string]interface{}
	if yaml.Unmarshal(data, &raw) == nil {
		if server, ok := raw["server"].(map[string]interface{}); ok {
			fmt.Printf("  %-16s %v\n", "Host:", server["host"])
			fmt.Printf("  %-16s %v\n", "Port:", server["port"])
		}
		if logging, ok := raw["logging"].(map[string]interface{}); ok {
			fmt.Printf("  %-16s %v\n", "Log Level:", logging["level"])
		}
	}
	fmt.Println()
}

func cmdProfileDelete(args []string) {
	if len(args) == 0 {
		errorf("profile name required — usage: 1sec profile delete <name>")
	}
	name := args[0]

	pp := profilePath(name)
	if _, err := os.Stat(pp); err != nil {
		errorf("profile %q not found", name)
	}

	if err := os.Remove(pp); err != nil {
		errorf("deleting profile: %v", err)
	}

	fmt.Fprintf(os.Stdout, "%s Profile %s deleted.\n", green("✓"), bold(name))
}

func cmdProfileUse(args []string) {
	if len(args) == 0 {
		errorf("profile name required — usage: 1sec profile use <name>")
	}
	name := args[0]

	pp := profilePath(name)
	if _, err := os.Stat(pp); err != nil {
		errorf("profile %q not found — create it first with: 1sec profile create %s", name, name)
	}

	fmt.Fprintf(os.Stdout, "%s To activate profile %s, set the environment variable:\n\n", green("✓"), bold(name))
	fmt.Fprintf(os.Stdout, "  export ONESEC_PROFILE=%s\n\n", name)
	fmt.Fprintf(os.Stdout, "%s Or use --profile %s with any command.\n", dim("▸"), name)
}
