package runtime

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/1sec-project/1sec/internal/core"
	"github.com/rs/zerolog"
)

const ModuleName = "runtime_watcher"

// Watcher is the Runtime Watcher module providing file integrity monitoring,
// container escape detection, privilege escalation monitoring, LOLBin detection,
// fileless malware detection, UEFI/bootkit indicators, memory injection detection,
// persistence mechanism detection, and WMI/scheduled task abuse detection.
type Watcher struct {
	logger   zerolog.Logger
	bus      *core.EventBus
	pipeline *core.AlertPipeline
	cfg      *core.Config
	ctx      context.Context
	cancel   context.CancelFunc
	fim      *FileIntegrityMonitor
	procMon  *ProcessMonitor
}

func New() *Watcher { return &Watcher{} }

func (w *Watcher) Name() string { return ModuleName }
func (w *Watcher) Description() string {
	return "File integrity monitoring, container escape detection, privilege escalation, LOLBin detection, fileless malware, UEFI/bootkit indicators, memory injection, and persistence mechanism detection"
}

func (w *Watcher) Start(ctx context.Context, bus *core.EventBus, pipeline *core.AlertPipeline, cfg *core.Config) error {
	w.ctx, w.cancel = context.WithCancel(ctx)
	w.bus = bus
	w.pipeline = pipeline
	w.cfg = cfg
	w.logger = zerolog.New(zerolog.NewConsoleWriter()).With().Timestamp().Str("module", ModuleName).Logger()

	settings := cfg.GetModuleSettings(ModuleName)
	watchPaths := getStringSliceSetting(settings, "watch_paths", []string{})
	scanInterval := getIntSetting(settings, "scan_interval_seconds", 300)
	w.fim = NewFileIntegrityMonitor(watchPaths, time.Duration(scanInterval)*time.Second)
	w.procMon = NewProcessMonitor()

	if len(watchPaths) > 0 {
		go w.fimLoop()
	}

	w.logger.Info().
		Int("watch_paths", len(watchPaths)).
		Int("scan_interval", scanInterval).
		Msg("runtime watcher started")
	return nil
}

func (w *Watcher) Stop() error {
	if w.cancel != nil {
		w.cancel()
	}
	return nil
}

func (w *Watcher) HandleEvent(event *core.SecurityEvent) error {
	switch event.Type {
	case "file_change", "file_modified", "file_created", "file_deleted":
		w.handleFileEvent(event)
	case "process_start", "process_exec":
		w.handleProcessEvent(event)
	case "privilege_change", "setuid", "capability_change":
		w.handlePrivilegeEvent(event)
	case "container_event":
		w.handleContainerEvent(event)
	case "memory_injection", "process_hollowing", "dll_injection":
		w.handleMemoryInjection(event)
	case "persistence_created", "scheduled_task", "wmi_subscription",
		"registry_run_key", "startup_item", "cron_job", "systemd_service":
		w.handlePersistenceEvent(event)
	case "firmware_event", "uefi_event", "bootloader_change":
		w.handleFirmwareEvent(event)
	case "fileless_execution", "powershell_exec", "wmi_exec", "mshta_exec":
		w.handleFilelessEvent(event)
	}
	return nil
}

func (w *Watcher) handleFileEvent(event *core.SecurityEvent) {
	filePath := getStringDetail(event, "path")
	if filePath == "" {
		return
	}
	if isSensitivePath(filePath) {
		w.raiseAlert(event, core.SeverityCritical,
			"Sensitive File Modified",
			fmt.Sprintf("Critical system file modified: %s. This may indicate system compromise.", filePath),
			"sensitive_file_change")
	}
	if isSuspiciousFile(filePath) {
		w.raiseAlert(event, core.SeverityHigh,
			"Suspicious File Detected",
			fmt.Sprintf("Suspicious file detected: %s", filePath),
			"suspicious_file")
	}
}

func (w *Watcher) handleProcessEvent(event *core.SecurityEvent) {
	processName := getStringDetail(event, "process_name")
	cmdLine := getStringDetail(event, "command_line")
	parentProcess := getStringDetail(event, "parent_process")

	if processName == "" && cmdLine == "" {
		return
	}

	// LOLBin detection — Living Off the Land Binaries
	if lolbin := w.procMon.IsLOLBin(processName, cmdLine, parentProcess); lolbin.Detected {
		w.raiseAlert(event, core.SeverityHigh,
			"Living Off the Land Binary Abuse Detected",
			fmt.Sprintf("LOLBin %q used for %s. Command: %s. Parent: %s. "+
				"Attackers use legitimate system binaries to evade detection. "+
				"MITRE ATT&CK %s.",
				processName, lolbin.Technique, truncate(cmdLine, 150),
				parentProcess, lolbin.MitreID),
			"lolbin_abuse")
	}

	// Suspicious process detection
	if w.procMon.IsSuspicious(processName, cmdLine, parentProcess) {
		w.raiseAlert(event, core.SeverityHigh,
			"Suspicious Process Detected",
			fmt.Sprintf("Suspicious process: %s (cmd: %s, parent: %s)",
				processName, truncate(cmdLine, 100), parentProcess),
			"suspicious_process")
	}

	// Reverse shell detection
	if w.procMon.IsReverseShell(cmdLine) {
		w.raiseAlert(event, core.SeverityCritical,
			"Reverse Shell Detected",
			fmt.Sprintf("Possible reverse shell: %s", truncate(cmdLine, 200)),
			"reverse_shell")
	}
}

func (w *Watcher) handlePrivilegeEvent(event *core.SecurityEvent) {
	user := getStringDetail(event, "user")
	action := getStringDetail(event, "action")
	target := getStringDetail(event, "target")

	w.raiseAlert(event, core.SeverityHigh,
		"Privilege Escalation Detected",
		fmt.Sprintf("User %s performed privilege action %q on %s", user, action, target),
		"privilege_escalation")
}

func (w *Watcher) handleContainerEvent(event *core.SecurityEvent) {
	action := getStringDetail(event, "action")
	containerID := getStringDetail(event, "container_id")

	escapeIndicators := []string{
		"mount_host_fs", "nsenter", "privileged_exec",
		"host_pid_access", "host_network_access", "cap_sys_admin",
		"docker_socket_mount", "proc_mount", "sys_ptrace",
		"apparmor_disabled", "seccomp_disabled",
	}

	for _, indicator := range escapeIndicators {
		if strings.Contains(action, indicator) {
			w.raiseAlert(event, core.SeverityCritical,
				"Container Escape Attempt",
				fmt.Sprintf("Container %s attempted escape via %s. "+
					"MITRE ATT&CK T1611.", truncate(containerID, 12), action),
				"container_escape")
			return
		}
	}
}

// handleMemoryInjection detects process hollowing, DLL injection, reflective loading,
// and other in-memory attack techniques used by APTs.
func (w *Watcher) handleMemoryInjection(event *core.SecurityEvent) {
	technique := getStringDetail(event, "technique")
	targetProcess := getStringDetail(event, "target_process")
	sourceProcess := getStringDetail(event, "source_process")
	targetPID := getStringDetail(event, "target_pid")

	techniqueDescriptions := map[string]struct {
		title   string
		mitreID string
	}{
		"process_hollowing":     {"Process Hollowing", "T1055.012"},
		"dll_injection":         {"DLL Injection", "T1055.001"},
		"reflective_loading":    {"Reflective DLL Loading", "T1620.001"},
		"thread_hijacking":      {"Thread Execution Hijacking", "T1055.003"},
		"apc_injection":         {"APC Queue Injection", "T1055.004"},
		"atom_bombing":          {"AtomBombing Injection", "T1055"},
		"process_doppelganging": {"Process Doppelgänging", "T1055.013"},
		"veh_hooking":           {"Vectored Exception Handler Hooking", "T1055"},
		"ntfs_transaction":      {"NTFS Transaction Injection", "T1055"},
		"early_bird":            {"Early Bird APC Injection", "T1055.004"},
		"module_stomping":       {"Module Stomping", "T1055"},
	}

	desc, known := techniqueDescriptions[technique]
	if !known {
		desc.title = "Memory Injection"
		desc.mitreID = "T1055"
	}

	w.raiseAlert(event, core.SeverityCritical,
		fmt.Sprintf("%s Detected", desc.title),
		fmt.Sprintf("Process %s (PID: %s) injected into %s using %s technique. "+
			"In-memory code execution evades file-based detection. "+
			"MITRE ATT&CK %s.",
			sourceProcess, targetPID, targetProcess, technique, desc.mitreID),
		"memory_injection")
}

// handlePersistenceEvent detects malicious persistence mechanisms including
// scheduled tasks, WMI subscriptions, registry run keys, cron jobs, and systemd services.
func (w *Watcher) handlePersistenceEvent(event *core.SecurityEvent) {
	mechanism := event.Type
	name := getStringDetail(event, "name")
	command := getStringDetail(event, "command")
	user := getStringDetail(event, "user")
	path := getStringDetail(event, "path")

	// Check for suspicious persistence commands
	suspiciousPatterns := []struct {
		pattern string
		reason  string
	}{
		{"powershell", "PowerShell execution in persistence"},
		{"cmd /c", "Command shell in persistence"},
		{"certutil", "CertUtil abuse for download/decode"},
		{"bitsadmin", "BITSAdmin abuse for download"},
		{"mshta", "MSHTA script execution"},
		{"regsvr32", "Regsvr32 proxy execution"},
		{"rundll32", "Rundll32 proxy execution"},
		{"wscript", "Windows Script Host execution"},
		{"cscript", "Windows Script Host execution"},
		{"/dev/tcp/", "Network connection in persistence"},
		{"curl |", "Remote script download and execute"},
		{"wget |", "Remote script download and execute"},
		{"base64", "Encoded payload in persistence"},
		{"-enc ", "Encoded PowerShell command"},
		{"-encodedcommand", "Encoded PowerShell command"},
		{"iex(", "PowerShell Invoke-Expression"},
		{"invoke-expression", "PowerShell Invoke-Expression"},
		{"downloadstring", "Remote payload download"},
		{"downloadfile", "Remote payload download"},
		{"hidden", "Hidden window execution"},
		{"bypass", "Execution policy bypass"},
	}

	cmdLower := strings.ToLower(command)
	for _, sp := range suspiciousPatterns {
		if strings.Contains(cmdLower, sp.pattern) {
			w.raiseAlert(event, core.SeverityCritical,
				"Malicious Persistence Mechanism Detected",
				fmt.Sprintf("Suspicious %s persistence created by user %q. "+
					"Name: %s, Command: %s. Reason: %s. Path: %s. "+
					"MITRE ATT&CK T1053/T1547.",
					mechanism, user, name, truncate(command, 150), sp.reason, path),
				"malicious_persistence")
			return
		}
	}

	// Non-suspicious but still worth logging
	w.raiseAlert(event, core.SeverityMedium,
		"Persistence Mechanism Created",
		fmt.Sprintf("New %s persistence: %s by user %q. Command: %s",
			mechanism, name, user, truncate(command, 100)),
		"persistence_created")
}

// handleFirmwareEvent detects UEFI bootkit indicators, firmware tampering,
// and Secure Boot bypass attempts.
func (w *Watcher) handleFirmwareEvent(event *core.SecurityEvent) {
	action := getStringDetail(event, "action")
	component := getStringDetail(event, "component")
	hash := getStringDetail(event, "hash")
	expectedHash := getStringDetail(event, "expected_hash")
	secureBootStatus := getStringDetail(event, "secure_boot")

	// Secure Boot disabled or bypassed
	if strings.EqualFold(secureBootStatus, "disabled") || strings.EqualFold(secureBootStatus, "bypassed") {
		w.raiseAlert(event, core.SeverityCritical,
			"Secure Boot Disabled/Bypassed",
			fmt.Sprintf("Secure Boot is %s on this system. Component: %s. "+
				"This allows unsigned bootloaders and bootkits like BlackLotus to execute. "+
				"MITRE ATT&CK T1542.003.",
				secureBootStatus, component),
			"secure_boot_bypass")
	}

	// Firmware hash mismatch
	if hash != "" && expectedHash != "" && hash != expectedHash {
		w.raiseAlert(event, core.SeverityCritical,
			"Firmware Tampering Detected",
			fmt.Sprintf("Firmware component %s hash mismatch. Expected: %s, Got: %s. "+
				"This indicates a potential bootkit or firmware rootkit. "+
				"Known threats: BlackLotus, LoJax, MosaicRegressor. "+
				"MITRE ATT&CK T1542.",
				component, truncate(expectedHash, 16), truncate(hash, 16)),
			"firmware_tampering")
	}

	// UEFI variable modification
	if strings.Contains(action, "uefi_var_write") || strings.Contains(action, "efi_variable_modified") {
		w.raiseAlert(event, core.SeverityHigh,
			"UEFI Variable Modified",
			fmt.Sprintf("UEFI variable modified: %s. Action: %s. "+
				"Unauthorized UEFI variable writes can indicate bootkit installation. "+
				"MITRE ATT&CK T1542.003.",
				component, action),
			"uefi_modification")
	}

	// Boot configuration change
	if strings.Contains(action, "bootloader_change") || strings.Contains(action, "bcd_modified") {
		w.raiseAlert(event, core.SeverityCritical,
			"Boot Configuration Modified",
			fmt.Sprintf("Boot configuration changed: %s. "+
				"Bootloader modifications can enable pre-OS malware execution. "+
				"MITRE ATT&CK T1542.",
				component),
			"boot_config_change")
	}
}

// handleFilelessEvent detects fileless malware execution via PowerShell, WMI,
// MSHTA, and other LOLBin-based in-memory techniques.
func (w *Watcher) handleFilelessEvent(event *core.SecurityEvent) {
	processName := getStringDetail(event, "process_name")
	cmdLine := getStringDetail(event, "command_line")
	parentProcess := getStringDetail(event, "parent_process")
	scriptContent := getStringDetail(event, "script_content")

	cmdLower := strings.ToLower(cmdLine)
	scriptLower := strings.ToLower(scriptContent)

	// Encoded PowerShell commands (extremely common in fileless attacks)
	if strings.Contains(cmdLower, "-enc") || strings.Contains(cmdLower, "-encodedcommand") ||
		strings.Contains(cmdLower, "frombase64string") {
		w.raiseAlert(event, core.SeverityCritical,
			"Encoded Fileless Execution Detected",
			fmt.Sprintf("Encoded fileless execution via %s. Parent: %s. "+
				"Command: %s. Base64-encoded commands are a primary fileless malware technique. "+
				"MITRE ATT&CK T1059.001.",
				processName, parentProcess, truncate(cmdLine, 200)),
			"encoded_fileless_exec")
		return
	}

	// PowerShell download cradles
	downloadPatterns := []string{
		"downloadstring", "downloadfile", "invoke-webrequest",
		"wget", "curl", "start-bitstransfer",
		"net.webclient", "invoke-restmethod",
		"[system.net.webclient]", "bitstransfer",
	}
	for _, pattern := range downloadPatterns {
		if strings.Contains(cmdLower, pattern) || strings.Contains(scriptLower, pattern) {
			w.raiseAlert(event, core.SeverityCritical,
				"Fileless Download Cradle Detected",
				fmt.Sprintf("Download cradle via %s: %s. Parent: %s. "+
					"Remote payload downloaded and executed in memory. "+
					"MITRE ATT&CK T1059.001.",
					processName, truncate(cmdLine, 200), parentProcess),
				"download_cradle")
			return
		}
	}

	// AMSI bypass attempts
	amsiPatterns := []string{
		"amsiutils", "amsiinitfailed", "amsi.dll",
		"amsiscanbuffer", "amsicontext",
		"set-mppreference -disablerealtimemonitoring",
	}
	for _, pattern := range amsiPatterns {
		if strings.Contains(cmdLower, pattern) || strings.Contains(scriptLower, pattern) {
			w.raiseAlert(event, core.SeverityCritical,
				"AMSI Bypass Attempt Detected",
				fmt.Sprintf("AMSI bypass via %s: %s. "+
					"Attacker is disabling antimalware scanning to execute malicious scripts. "+
					"MITRE ATT&CK T1562.001.",
					processName, truncate(cmdLine, 200)),
				"amsi_bypass")
			return
		}
	}

	// WMI-based execution
	if strings.Contains(cmdLower, "wmic") || strings.Contains(cmdLower, "invoke-wmimethod") ||
		strings.Contains(cmdLower, "get-wmiobject") {
		w.raiseAlert(event, core.SeverityHigh,
			"WMI-Based Execution Detected",
			fmt.Sprintf("WMI execution via %s: %s. Parent: %s. "+
				"WMI is commonly abused for lateral movement and fileless execution. "+
				"MITRE ATT&CK T1047.",
				processName, truncate(cmdLine, 200), parentProcess),
			"wmi_execution")
		return
	}

	// Generic fileless alert
	w.raiseAlert(event, core.SeverityHigh,
		"Fileless Execution Detected",
		fmt.Sprintf("Fileless execution via %s. Parent: %s. Command: %s. "+
			"MITRE ATT&CK T1059.",
			processName, parentProcess, truncate(cmdLine, 200)),
		"fileless_execution")
}

func (w *Watcher) fimLoop() {
	w.fim.BaselineScan()
	ticker := time.NewTicker(w.fim.interval)
	defer ticker.Stop()
	for {
		select {
		case <-w.ctx.Done():
			return
		case <-ticker.C:
			changes := w.fim.Scan()
			for _, change := range changes {
				severity := core.SeverityMedium
				if isSensitivePath(change.Path) {
					severity = core.SeverityCritical
				}
				event := core.NewSecurityEvent(ModuleName, "file_integrity_violation", severity,
					fmt.Sprintf("File integrity change: %s (%s)", change.Path, change.Type))
				event.Details["path"] = change.Path
				event.Details["change_type"] = change.Type
				event.Details["old_hash"] = change.OldHash
				event.Details["new_hash"] = change.NewHash
				if w.bus != nil {
					_ = w.bus.PublishEvent(event)
				}
				alert := core.NewAlert(event,
					fmt.Sprintf("File Integrity Violation: %s", change.Type),
					fmt.Sprintf("File %s was %s. Old hash: %s, New hash: %s",
						change.Path, change.Type, truncate(change.OldHash, 16), truncate(change.NewHash, 16)))
				if w.pipeline != nil {
					w.pipeline.Process(alert)
				}
			}
		}
	}
}

func (w *Watcher) raiseAlert(event *core.SecurityEvent, severity core.Severity, title, description, alertType string) {
	newEvent := core.NewSecurityEvent(ModuleName, alertType, severity, description)
	newEvent.SourceIP = event.SourceIP
	newEvent.Details["original_event_id"] = event.ID
	if w.bus != nil {
		_ = w.bus.PublishEvent(newEvent)
	}
	alert := core.NewAlert(newEvent, title, description)
	if w.pipeline != nil {
		w.pipeline.Process(alert)
	}
}

// ---------------------------------------------------------------------------
// FileIntegrityMonitor
// ---------------------------------------------------------------------------

type FileIntegrityMonitor struct {
	mu       sync.RWMutex
	baseline map[string]string
	paths    []string
	interval time.Duration
}

type FileChange struct {
	Path    string
	Type    string
	OldHash string
	NewHash string
}

func NewFileIntegrityMonitor(paths []string, interval time.Duration) *FileIntegrityMonitor {
	return &FileIntegrityMonitor{baseline: make(map[string]string), paths: paths, interval: interval}
}

func (fim *FileIntegrityMonitor) BaselineScan() {
	fim.mu.Lock()
	defer fim.mu.Unlock()
	for _, watchPath := range fim.paths {
		_ = filepath.Walk(watchPath, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			hash, err := hashFile(path)
			if err == nil {
				fim.baseline[path] = hash
			}
			return nil
		})
	}
}

func (fim *FileIntegrityMonitor) Scan() []FileChange {
	fim.mu.Lock()
	defer fim.mu.Unlock()
	var changes []FileChange
	currentFiles := make(map[string]string)
	for _, watchPath := range fim.paths {
		_ = filepath.Walk(watchPath, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			hash, err := hashFile(path)
			if err == nil {
				currentFiles[path] = hash
			}
			return nil
		})
	}
	for path, newHash := range currentFiles {
		oldHash, existed := fim.baseline[path]
		if !existed {
			changes = append(changes, FileChange{Path: path, Type: "created", NewHash: newHash})
		} else if oldHash != newHash {
			changes = append(changes, FileChange{Path: path, Type: "modified", OldHash: oldHash, NewHash: newHash})
		}
	}
	for path, oldHash := range fim.baseline {
		if _, exists := currentFiles[path]; !exists {
			changes = append(changes, FileChange{Path: path, Type: "deleted", OldHash: oldHash})
		}
	}
	fim.baseline = currentFiles
	return changes
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// ---------------------------------------------------------------------------
// ProcessMonitor — suspicious process, reverse shell, and LOLBin detection
// ---------------------------------------------------------------------------

type ProcessMonitor struct {
	suspiciousProcesses  map[string]bool
	reverseShellPatterns []string
	lolbins              map[string]lolbinInfo
}

type lolbinInfo struct {
	Techniques []lolbinTechnique
}

type lolbinTechnique struct {
	Pattern   string
	Technique string
	MitreID   string
}

type LOLBinResult struct {
	Detected  bool
	Technique string
	MitreID   string
}

func NewProcessMonitor() *ProcessMonitor {
	pm := &ProcessMonitor{
		suspiciousProcesses: map[string]bool{
			"nc": true, "ncat": true, "netcat": true,
			"nmap": true, "masscan": true, "zmap": true,
			"mimikatz": true, "lazagne": true, "hashcat": true,
			"john": true, "hydra": true, "medusa": true,
			"sqlmap": true, "nikto": true, "dirb": true,
			"gobuster": true, "wfuzz": true, "ffuf": true,
			"msfconsole": true, "msfvenom": true, "metasploit": true,
			"cobaltstrike": true, "empire": true, "sliver": true,
			"chisel": true, "socat": true, "cryptominer": true,
			"xmrig": true, "ccminer": true, "minerd": true,
			"rubeus": true, "sharphound": true, "bloodhound": true,
			"impacket": true, "crackmapexec": true, "evil-winrm": true,
			"psexec": true, "procdump": true, "nanodump": true,
			"secretsdump": true, "kerbrute": true, "responder": true,
		},
		reverseShellPatterns: []string{
			"bash -i >& /dev/tcp/", "bash -i >& /dev/udp/",
			"nc -e /bin/", "ncat -e /bin/",
			"python -c 'import socket", "python3 -c 'import socket",
			"perl -e 'use Socket", "ruby -rsocket -e",
			"php -r '$sock=fsockopen", "powershell -nop -c \"$client",
			"IEX(New-Object Net.WebClient)", "/dev/tcp/", "mkfifo /tmp/",
			"bash -c 'bash -i", "0<&196;exec 196<>/dev/tcp/",
			"exec 5<>/dev/tcp/", "lua -e \"require('socket')",
			"openssl s_client -connect",
		},
		lolbins: buildLOLBinDatabase(),
	}
	return pm
}

func buildLOLBinDatabase() map[string]lolbinInfo {
	return map[string]lolbinInfo{
		"certutil": {Techniques: []lolbinTechnique{
			{Pattern: "-urlcache", Technique: "File download", MitreID: "T1105"},
			{Pattern: "-decode", Technique: "Base64 decode", MitreID: "T1140"},
			{Pattern: "-encode", Technique: "Base64 encode", MitreID: "T1027"},
			{Pattern: "-verifyctl", Technique: "Download and execute", MitreID: "T1105"},
		}},
		"mshta": {Techniques: []lolbinTechnique{
			{Pattern: "http", Technique: "Remote HTA execution", MitreID: "T1218.005"},
			{Pattern: "vbscript", Technique: "VBScript execution", MitreID: "T1218.005"},
			{Pattern: "javascript", Technique: "JavaScript execution", MitreID: "T1218.005"},
		}},
		"regsvr32": {Techniques: []lolbinTechnique{
			{Pattern: "/s /n /u /i:http", Technique: "Squiblydoo attack", MitreID: "T1218.010"},
			{Pattern: "scrobj.dll", Technique: "COM scriptlet execution", MitreID: "T1218.010"},
		}},
		"rundll32": {Techniques: []lolbinTechnique{
			{Pattern: "javascript:", Technique: "JavaScript execution", MitreID: "T1218.011"},
			{Pattern: "shell32.dll,control_rundll", Technique: "CPL execution", MitreID: "T1218.011"},
			{Pattern: "advpack.dll,launchinf", Technique: "INF execution", MitreID: "T1218.011"},
			{Pattern: "comsvcs.dll,minidump", Technique: "Process memory dump (credential theft)", MitreID: "T1003.001"},
		}},
		"bitsadmin": {Techniques: []lolbinTechnique{
			{Pattern: "/transfer", Technique: "File download", MitreID: "T1197"},
			{Pattern: "/create", Technique: "Persistence via BITS job", MitreID: "T1197"},
		}},
		"wmic": {Techniques: []lolbinTechnique{
			{Pattern: "process call create", Technique: "Remote process creation", MitreID: "T1047"},
			{Pattern: "/node:", Technique: "Remote WMI execution", MitreID: "T1047"},
			{Pattern: "os get", Technique: "System reconnaissance", MitreID: "T1082"},
		}},
		"msiexec": {Techniques: []lolbinTechnique{
			{Pattern: "/q", Technique: "Silent MSI execution", MitreID: "T1218.007"},
			{Pattern: "http", Technique: "Remote MSI execution", MitreID: "T1218.007"},
		}},
		"cmstp": {Techniques: []lolbinTechnique{
			{Pattern: "/ni /s", Technique: "UAC bypass via CMSTP", MitreID: "T1218.003"},
		}},
		"installutil": {Techniques: []lolbinTechnique{
			{Pattern: "/logfile=", Technique: ".NET assembly execution", MitreID: "T1218.004"},
		}},
		"msbuild": {Techniques: []lolbinTechnique{
			{Pattern: "", Technique: "Inline task code execution", MitreID: "T1127.001"},
		}},
		"csc": {Techniques: []lolbinTechnique{
			{Pattern: "/out:", Technique: "C# compilation and execution", MitreID: "T1127"},
		}},
		"xwizard": {Techniques: []lolbinTechnique{
			{Pattern: "runwizard", Technique: "COM object execution", MitreID: "T1218"},
		}},
		"forfiles": {Techniques: []lolbinTechnique{
			{Pattern: "/c", Technique: "Command execution via forfiles", MitreID: "T1202"},
		}},
		"pcalua": {Techniques: []lolbinTechnique{
			{Pattern: "-a", Technique: "Program Compatibility Assistant proxy", MitreID: "T1202"},
		}},
		"bash": {Techniques: []lolbinTechnique{
			{Pattern: "wsl", Technique: "WSL execution bypass", MitreID: "T1202"},
		}},
		"wsl": {Techniques: []lolbinTechnique{
			{Pattern: "", Technique: "WSL execution bypass", MitreID: "T1202"},
		}},
		"explorer": {Techniques: []lolbinTechnique{
			{Pattern: "/root,", Technique: "DLL side-loading via Explorer", MitreID: "T1574.002"},
		}},
		"control": {Techniques: []lolbinTechnique{
			{Pattern: "", Technique: "Control Panel item execution", MitreID: "T1218.002"},
		}},
		"esentutl": {Techniques: []lolbinTechnique{
			{Pattern: "/y", Technique: "File copy (ADS/locked file access)", MitreID: "T1003"},
		}},
		"expand": {Techniques: []lolbinTechnique{
			{Pattern: "", Technique: "CAB file extraction", MitreID: "T1140"},
		}},
		"extrac32": {Techniques: []lolbinTechnique{
			{Pattern: "/y", Technique: "CAB extraction bypass", MitreID: "T1140"},
		}},
		"findstr": {Techniques: []lolbinTechnique{
			{Pattern: "/v /l", Technique: "ADS file download", MitreID: "T1105"},
		}},
		"hh": {Techniques: []lolbinTechnique{
			{Pattern: "http", Technique: "Remote CHM execution", MitreID: "T1218.001"},
		}},
		"ieexec": {Techniques: []lolbinTechnique{
			{Pattern: "http", Technique: "Remote .NET assembly execution", MitreID: "T1218"},
		}},
		"infdefaultinstall": {Techniques: []lolbinTechnique{
			{Pattern: "", Technique: "INF file execution", MitreID: "T1218"},
		}},
		"makecab": {Techniques: []lolbinTechnique{
			{Pattern: "", Technique: "Data staging via CAB", MitreID: "T1074"},
		}},
		"mavinject": {Techniques: []lolbinTechnique{
			{Pattern: "/injectrunning", Technique: "DLL injection into running process", MitreID: "T1055.001"},
		}},
		"replace": {Techniques: []lolbinTechnique{
			{Pattern: "/a", Technique: "File copy to restricted location", MitreID: "T1105"},
		}},
		"sc": {Techniques: []lolbinTechnique{
			{Pattern: "create", Technique: "Service creation for persistence", MitreID: "T1543.003"},
			{Pattern: "config", Technique: "Service modification", MitreID: "T1543.003"},
		}},
		"schtasks": {Techniques: []lolbinTechnique{
			{Pattern: "/create", Technique: "Scheduled task persistence", MitreID: "T1053.005"},
		}},
		"reg": {Techniques: []lolbinTechnique{
			{Pattern: "save", Technique: "Registry hive dump (credential theft)", MitreID: "T1003.002"},
			{Pattern: "add", Technique: "Registry modification", MitreID: "T1112"},
			{Pattern: "export", Technique: "Registry export", MitreID: "T1012"},
		}},
		"nltest": {Techniques: []lolbinTechnique{
			{Pattern: "/dclist", Technique: "Domain controller enumeration", MitreID: "T1018"},
			{Pattern: "/domain_trusts", Technique: "Domain trust discovery", MitreID: "T1482"},
		}},
		"dsquery": {Techniques: []lolbinTechnique{
			{Pattern: "", Technique: "Active Directory enumeration", MitreID: "T1018"},
		}},
		"net": {Techniques: []lolbinTechnique{
			{Pattern: "user /domain", Technique: "Domain user enumeration", MitreID: "T1087.002"},
			{Pattern: "group /domain", Technique: "Domain group enumeration", MitreID: "T1069.002"},
			{Pattern: "localgroup administrators", Technique: "Local admin enumeration", MitreID: "T1069.001"},
		}},
		"whoami": {Techniques: []lolbinTechnique{
			{Pattern: "/priv", Technique: "Privilege enumeration", MitreID: "T1033"},
			{Pattern: "/all", Technique: "Full identity enumeration", MitreID: "T1033"},
		}},
		"tasklist": {Techniques: []lolbinTechnique{
			{Pattern: "/svc", Technique: "Service enumeration", MitreID: "T1007"},
		}},
		"netsh": {Techniques: []lolbinTechnique{
			{Pattern: "firewall", Technique: "Firewall modification", MitreID: "T1562.004"},
			{Pattern: "advfirewall", Technique: "Firewall rule modification", MitreID: "T1562.004"},
			{Pattern: "portproxy", Technique: "Port forwarding", MitreID: "T1090"},
		}},
	}
}

func (pm *ProcessMonitor) IsLOLBin(name, cmdLine, parent string) LOLBinResult {
	nameLower := strings.ToLower(name)
	// Strip .exe extension for matching
	baseName := strings.TrimSuffix(nameLower, ".exe")

	info, isLOLBin := pm.lolbins[baseName]
	if !isLOLBin {
		return LOLBinResult{}
	}

	cmdLower := strings.ToLower(cmdLine)
	for _, tech := range info.Techniques {
		if tech.Pattern == "" || strings.Contains(cmdLower, tech.Pattern) {
			return LOLBinResult{
				Detected:  true,
				Technique: tech.Technique,
				MitreID:   tech.MitreID,
			}
		}
	}
	return LOLBinResult{}
}

func (pm *ProcessMonitor) IsSuspicious(name, cmdLine, parent string) bool {
	nameLower := strings.ToLower(name)
	if pm.suspiciousProcesses[nameLower] {
		return true
	}
	suspiciousParents := map[string][]string{
		"apache2":  {"bash", "sh", "python", "perl", "ruby"},
		"httpd":    {"bash", "sh", "python", "perl", "ruby"},
		"nginx":    {"bash", "sh", "python", "perl", "ruby"},
		"java":     {"bash", "sh", "cmd", "powershell"},
		"node":     {"bash", "sh", "cmd", "powershell"},
		"postgres": {"bash", "sh", "python"},
		"mysql":    {"bash", "sh", "python"},
		"w3wp":     {"cmd", "powershell", "bash"},
		"iis":      {"cmd", "powershell"},
		"tomcat":   {"bash", "sh", "cmd", "powershell"},
		"php-fpm":  {"bash", "sh", "python"},
	}
	parentLower := strings.ToLower(parent)
	if children, ok := suspiciousParents[parentLower]; ok {
		for _, child := range children {
			if nameLower == child {
				return true
			}
		}
	}
	return false
}

func (pm *ProcessMonitor) IsReverseShell(cmdLine string) bool {
	cmdLower := strings.ToLower(cmdLine)
	for _, pattern := range pm.reverseShellPatterns {
		if strings.Contains(cmdLower, strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

func isSensitivePath(path string) bool {
	sensitivePaths := []string{
		"/etc/passwd", "/etc/shadow", "/etc/sudoers",
		"/etc/ssh/sshd_config", "/etc/crontab",
		"/root/.ssh/authorized_keys", "/root/.bashrc",
		"C:\\Windows\\System32\\config\\SAM",
		"C:\\Windows\\System32\\config\\SYSTEM",
		"C:\\Windows\\System32\\config\\SECURITY",
		"/var/spool/cron",
		"/etc/pam.d/", "/etc/ld.so.preload",
		"/boot/grub/grub.cfg", "/boot/efi/",
		"/sys/firmware/efi/",
	}
	pathLower := strings.ToLower(filepath.ToSlash(path))
	for _, sp := range sensitivePaths {
		if strings.Contains(pathLower, strings.ToLower(filepath.ToSlash(sp))) {
			return true
		}
	}
	return false
}

func isSuspiciousFile(path string) bool {
	suspiciousExts := []string{
		".exe", ".dll", ".so", ".dylib",
		".sh", ".bat", ".ps1", ".vbs",
		".php", ".jsp", ".asp", ".aspx",
		".py", ".pl", ".rb", ".hta",
		".scr", ".cpl", ".inf", ".msi",
		".wsf", ".wsh", ".chm",
	}
	ext := strings.ToLower(filepath.Ext(path))
	for _, se := range suspiciousExts {
		if ext == se {
			return true
		}
	}
	return false
}

func getStringDetail(event *core.SecurityEvent, key string) string {
	if event.Details == nil {
		return ""
	}
	if val, ok := event.Details[key].(string); ok {
		return val
	}
	return ""
}

func getIntSetting(settings map[string]interface{}, key string, defaultVal int) int {
	if val, ok := settings[key]; ok {
		switch v := val.(type) {
		case int:
			return v
		case float64:
			return int(v)
		}
	}
	return defaultVal
}

func getStringSliceSetting(settings map[string]interface{}, key string, defaultVal []string) []string {
	if val, ok := settings[key]; ok {
		switch v := val.(type) {
		case []interface{}:
			result := make([]string, 0, len(v))
			for _, item := range v {
				if s, ok := item.(string); ok {
					result = append(result, s)
				}
			}
			return result
		case []string:
			return v
		}
	}
	return defaultVal
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
