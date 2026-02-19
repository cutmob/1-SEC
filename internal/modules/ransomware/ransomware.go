package ransomware

import (
	"context"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/1sec-project/1sec/internal/core"
	"github.com/rs/zerolog"
)

const ModuleName = "ransomware"

// Interceptor is the Ransomware Interceptor module providing encryption detection,
// canary file monitoring, data exfiltration detection, wiper detection, shadow copy
// deletion detection, and backup destruction detection.
type Interceptor struct {
	logger        zerolog.Logger
	bus           *core.EventBus
	pipeline      *core.AlertPipeline
	cfg           *core.Config
	ctx           context.Context
	cancel        context.CancelFunc
	fileTracker   *FileActivityTracker
	exfilTracker  *ExfilTracker
	wiperTracker  *WiperTracker
	backupTracker *BackupDestructionTracker
}

func New() *Interceptor { return &Interceptor{} }

func (i *Interceptor) Name() string { return ModuleName }
func (i *Interceptor) Description() string {
	return "Ransomware detection via file encryption patterns, canary files, data exfiltration monitoring, wiper detection, shadow copy deletion, and backup destruction detection"
}

func (i *Interceptor) Start(ctx context.Context, bus *core.EventBus, pipeline *core.AlertPipeline, cfg *core.Config) error {
	i.ctx, i.cancel = context.WithCancel(ctx)
	i.bus = bus
	i.pipeline = pipeline
	i.cfg = cfg
	i.logger = zerolog.New(zerolog.NewConsoleWriter()).With().Timestamp().Str("module", ModuleName).Logger()

	settings := cfg.GetModuleSettings(ModuleName)
	encryptionThreshold := getIntSetting(settings, "encryption_threshold", 10)
	exfilMBThreshold := getIntSetting(settings, "exfil_mb_threshold", 100)

	i.fileTracker = NewFileActivityTracker(encryptionThreshold)
	i.exfilTracker = NewExfilTracker(int64(exfilMBThreshold) * 1024 * 1024)
	i.wiperTracker = NewWiperTracker()
	i.backupTracker = NewBackupDestructionTracker()

	go i.fileTracker.CleanupLoop(i.ctx)
	go i.exfilTracker.CleanupLoop(i.ctx)
	go i.wiperTracker.CleanupLoop(i.ctx)
	go i.backupTracker.CleanupLoop(i.ctx)

	i.logger.Info().
		Int("encryption_threshold", encryptionThreshold).
		Int("exfil_mb_threshold", exfilMBThreshold).
		Msg("ransomware interceptor started")

	return nil
}

func (i *Interceptor) Stop() error {
	if i.cancel != nil {
		i.cancel()
	}
	return nil
}

func (i *Interceptor) HandleEvent(event *core.SecurityEvent) error {
	switch event.Type {
	case "file_modified", "file_change", "file_renamed":
		i.handleFileActivity(event)
	case "file_created":
		i.handleFileCreated(event)
	case "network_egress", "data_transfer", "upload":
		i.handleEgress(event)
	case "canary_triggered":
		i.handleCanaryTriggered(event)
	case "process_execution", "command_execution":
		i.handleProcessExecution(event)
	case "shadow_copy_delete", "vss_manipulation":
		i.handleShadowCopyDeletion(event)
	case "backup_destruction", "backup_delete":
		i.handleBackupDestruction(event)
	case "wiper_activity", "disk_write", "mbr_write", "partition_write":
		i.handleWiperActivity(event)
	}
	return nil
}

func (i *Interceptor) handleFileActivity(event *core.SecurityEvent) {
	path := getStringDetail(event, "path")
	processName := getStringDetail(event, "process_name")
	entropy := getFloatDetail(event, "entropy")

	if isRansomwareExtension(path) {
		i.raiseAlert(event, core.SeverityCritical,
			"Ransomware Extension Detected [T1486]",
			fmt.Sprintf("File with known ransomware extension detected: %s (process: %s). MITRE ATT&CK T1486: Data Encrypted for Impact.",
				path, processName),
			"ransomware_extension")
		return
	}

	result := i.fileTracker.RecordModification(processName, path, entropy)

	if result.MassEncryption {
		i.raiseAlert(event, core.SeverityCritical,
			"Mass File Encryption Detected [T1486]",
			fmt.Sprintf("Process %s has modified %d files in %s with high entropy (avg: %.2f). Strongly indicates ransomware activity. MITRE ATT&CK T1486: Data Encrypted for Impact.",
				processName, result.FileCount, result.Duration.String(), result.AvgEntropy),
			"mass_encryption")
	}

	if result.HighEntropy {
		i.raiseAlert(event, core.SeverityHigh,
			"High Entropy File Modification [T1486]",
			fmt.Sprintf("File %s modified with entropy %.2f by process %s. High entropy suggests encryption. MITRE ATT&CK T1486.",
				path, entropy, processName),
			"high_entropy")
	}

	if result.RapidRename {
		i.raiseAlert(event, core.SeverityHigh,
			"Rapid File Renaming Detected [T1486]",
			fmt.Sprintf("Process %s is rapidly renaming files (%d in %s). Common ransomware behavior. MITRE ATT&CK T1486.",
				processName, result.RenameCount, result.Duration.String()),
			"rapid_rename")
	}
}

func (i *Interceptor) handleFileCreated(event *core.SecurityEvent) {
	path := getStringDetail(event, "path")

	if isRansomNote(path) {
		i.raiseAlert(event, core.SeverityCritical,
			"Ransom Note Detected [T1491]",
			fmt.Sprintf("Possible ransom note created: %s. MITRE ATT&CK T1491: Defacement / T1486: Data Encrypted for Impact.", path),
			"ransom_note")
	}
}

func (i *Interceptor) handleEgress(event *core.SecurityEvent) {
	bytesTransferred := getIntDetail(event, "bytes")
	destIP := event.DestIP
	if destIP == "" {
		destIP = getStringDetail(event, "destination")
	}

	if bytesTransferred <= 0 {
		return
	}

	exceeded := i.exfilTracker.Record(event.SourceIP, destIP, int64(bytesTransferred))
	if exceeded {
		stats := i.exfilTracker.GetStats(event.SourceIP)
		i.raiseAlert(event, core.SeverityCritical,
			"Data Exfiltration Detected [T1041]",
			fmt.Sprintf("Abnormal data egress from %s: %.2f MB transferred to %d unique destinations in the last hour. Threshold: %.2f MB. MITRE ATT&CK T1041: Exfiltration Over C2 Channel.",
				event.SourceIP, float64(stats.TotalBytes)/(1024*1024), stats.UniqueDestinations, float64(i.exfilTracker.threshold)/(1024*1024)),
			"data_exfiltration")
	}
}

func (i *Interceptor) handleCanaryTriggered(event *core.SecurityEvent) {
	canaryPath := getStringDetail(event, "canary_path")
	processName := getStringDetail(event, "process_name")

	i.raiseAlert(event, core.SeverityCritical,
		"Canary File Triggered",
		fmt.Sprintf("Canary file %s was accessed/modified by process %s. Strong indicator of ransomware or unauthorized file access.",
			canaryPath, processName),
		"canary_triggered")
}

// handleProcessExecution inspects command-line executions for shadow copy deletion,
// backup destruction, recovery disabling, and wiper-related commands.
// This catches ransomware pre-encryption preparation (T1490: Inhibit System Recovery).
func (i *Interceptor) handleProcessExecution(event *core.SecurityEvent) {
	commandLine := strings.ToLower(getStringDetail(event, "command_line"))
	processName := strings.ToLower(getStringDetail(event, "process_name"))

	if commandLine == "" && processName == "" {
		return
	}

	// Shadow copy / VSS deletion commands
	vssPatterns := []struct {
		pattern string
		desc    string
	}{
		{"vssadmin delete shadows", "vssadmin shadow copy deletion"},
		{"vssadmin resize shadowstorage", "vssadmin shadow storage resize (to zero)"},
		{"wmic shadowcopy delete", "WMI shadow copy deletion"},
		{"get-wmiobject win32_shadowcopy | foreach-object {$_.delete()}", "PowerShell WMI shadow copy deletion"},
		{"win32_shadowcopy", "WMI shadow copy manipulation"},
		{"delete shadows /all", "shadow copy bulk deletion"},
		{"delete shadows /quiet", "silent shadow copy deletion"},
	}

	for _, vp := range vssPatterns {
		if strings.Contains(commandLine, vp.pattern) {
			i.backupTracker.RecordEvent(event.SourceIP, "vss_delete")
			i.raiseAlert(event, core.SeverityCritical,
				"Shadow Copy Deletion Detected [T1490]",
				fmt.Sprintf("Command detected: %s (%s). Process: %s. MITRE ATT&CK T1490: Inhibit System Recovery. This is a critical pre-ransomware indicator.",
					vp.desc, commandLine, processName),
				"shadow_copy_delete")
			i.checkCompoundAttack(event)
			return
		}
	}

	// Backup destruction commands
	backupPatterns := []struct {
		pattern string
		desc    string
	}{
		{"wbadmin delete catalog", "Windows backup catalog deletion"},
		{"wbadmin delete systemstatebackup", "system state backup deletion"},
		{"bcdedit /set {default} recoveryenabled no", "Windows recovery disabled via bcdedit"},
		{"bcdedit /set {default} bootstatuspolicy ignoreallfailures", "boot failure recovery disabled"},
		{"bcdedit /set safeboot", "safe boot configuration tampering"},
		{"reagentc /disable", "Windows Recovery Environment disabled"},
		{"delete catalog -quiet", "quiet backup catalog deletion"},
	}

	for _, bp := range backupPatterns {
		if strings.Contains(commandLine, bp.pattern) {
			i.backupTracker.RecordEvent(event.SourceIP, "backup_destroy")
			i.raiseAlert(event, core.SeverityCritical,
				"Backup Destruction Detected [T1490]",
				fmt.Sprintf("Command detected: %s (%s). Process: %s. MITRE ATT&CK T1490: Inhibit System Recovery. Attacker is destroying recovery options.",
					bp.desc, commandLine, processName),
				"backup_destruction")
			i.checkCompoundAttack(event)
			return
		}
	}

	// Wiper / disk destruction commands
	wiperPatterns := []struct {
		pattern string
		desc    string
	}{
		{"format c:", "disk format command"},
		{"format d:", "disk format command"},
		{"cipher /w:", "disk overwrite via cipher"},
		{"sdelete", "secure deletion tool"},
		{"dd if=/dev/zero", "zero-fill disk wipe (Linux)"},
		{"dd if=/dev/urandom", "random overwrite disk wipe (Linux)"},
		{"shred -", "file shredding (Linux)"},
		{"wipefs", "filesystem signature wipe (Linux)"},
		{"mkfs.", "filesystem reformat (Linux)"},
		{"\\\\.\\.\\physicaldrive", "raw physical drive access"},
	}

	for _, wp := range wiperPatterns {
		if strings.Contains(commandLine, wp.pattern) {
			i.wiperTracker.RecordEvent(event.SourceIP, processName, "command_wipe")
			i.raiseAlert(event, core.SeverityCritical,
				"Wiper Activity Detected [T1561]",
				fmt.Sprintf("Destructive command detected: %s (%s). Process: %s. MITRE ATT&CK T1561: Disk Wipe. System destruction in progress.",
					wp.desc, commandLine, processName),
				"wiper_activity")
			return
		}
	}

	// Service stopping (often precedes ransomware encryption)
	serviceStopPatterns := []string{
		"net stop vss", "net stop sql", "net stop exchange",
		"net stop backup", "net stop veeam", "net stop sophos",
		"net stop mssql", "net stop mysql", "net stop oracle",
		"sc config vss start= disabled", "sc stop vss",
		"taskkill /f /im sqlservr", "taskkill /f /im oracle",
		"taskkill /f /im veeam", "taskkill /f /im backup",
	}

	for _, sp := range serviceStopPatterns {
		if strings.Contains(commandLine, sp) {
			i.backupTracker.RecordEvent(event.SourceIP, "service_stop")
			i.raiseAlert(event, core.SeverityHigh,
				"Critical Service Stopped [T1489]",
				fmt.Sprintf("Security/backup/database service stopped: %s. Process: %s. MITRE ATT&CK T1489: Service Stop. Ransomware often stops services before encryption.",
					commandLine, processName),
				"service_stop")
			i.checkCompoundAttack(event)
			return
		}
	}
}

// handleShadowCopyDeletion handles direct shadow copy deletion events from OS-level monitoring.
func (i *Interceptor) handleShadowCopyDeletion(event *core.SecurityEvent) {
	method := getStringDetail(event, "method")
	processName := getStringDetail(event, "process_name")
	target := getStringDetail(event, "target")

	if method == "" {
		method = "unknown"
	}

	i.backupTracker.RecordEvent(event.SourceIP, "vss_delete")

	i.raiseAlert(event, core.SeverityCritical,
		"Shadow Copy Deletion Detected [T1490]",
		fmt.Sprintf("Volume Shadow Copy deletion detected via %s. Process: %s, Target: %s. MITRE ATT&CK T1490: Inhibit System Recovery. This is a critical pre-ransomware indicator — attackers delete shadow copies to prevent file recovery.",
			method, processName, target),
		"shadow_copy_delete")

	i.checkCompoundAttack(event)
}

// handleBackupDestruction handles backup deletion/corruption events.
func (i *Interceptor) handleBackupDestruction(event *core.SecurityEvent) {
	backupType := getStringDetail(event, "backup_type")
	processName := getStringDetail(event, "process_name")
	action := getStringDetail(event, "action")
	target := getStringDetail(event, "target")

	if backupType == "" {
		backupType = "unknown"
	}
	if action == "" {
		action = "destroyed"
	}

	i.backupTracker.RecordEvent(event.SourceIP, "backup_destroy")

	i.raiseAlert(event, core.SeverityCritical,
		"Backup Destruction Detected [T1490]",
		fmt.Sprintf("Backup %s detected. Type: %s, Target: %s, Process: %s. MITRE ATT&CK T1490: Inhibit System Recovery. Attacker is eliminating recovery options before deploying ransomware.",
			action, backupType, target, processName),
		"backup_destruction")

	i.checkCompoundAttack(event)
}

// handleWiperActivity handles disk wipe, MBR overwrite, and partition destruction events.
func (i *Interceptor) handleWiperActivity(event *core.SecurityEvent) {
	wiperType := getStringDetail(event, "wiper_type")
	processName := getStringDetail(event, "process_name")
	target := getStringDetail(event, "target")
	bytesWritten := getIntDetail(event, "bytes_written")
	writeOffset := getIntDetail(event, "offset")

	if wiperType == "" {
		wiperType = event.Type
	}

	i.wiperTracker.RecordEvent(event.SourceIP, processName, wiperType)

	// MBR/GPT overwrites are always critical — offset 0 on a physical drive is the MBR
	if event.Type == "mbr_write" || writeOffset == 0 {
		i.raiseAlert(event, core.SeverityCritical,
			"MBR/GPT Overwrite Detected [T1561.002]",
			fmt.Sprintf("Master Boot Record or GPT overwrite detected. Process: %s, Target: %s, Bytes: %d, Offset: %d. MITRE ATT&CK T1561.002: Disk Structure Wipe. System will be unbootable.",
				processName, target, bytesWritten, writeOffset),
			"mbr_overwrite")
		return
	}

	// Partition table destruction
	if event.Type == "partition_write" {
		i.raiseAlert(event, core.SeverityCritical,
			"Partition Table Destruction [T1561.002]",
			fmt.Sprintf("Partition table modification detected. Process: %s, Target: %s, Bytes: %d. MITRE ATT&CK T1561.002: Disk Structure Wipe.",
				processName, target, bytesWritten),
			"partition_destroy")
		return
	}

	// Check for zero-fill or random-fill wipe patterns
	pattern := getStringDetail(event, "write_pattern")
	severity := core.SeverityCritical
	title := "Disk Wipe Activity Detected [T1561.001]"
	desc := fmt.Sprintf("Disk wipe activity detected. Type: %s, Process: %s, Target: %s, Bytes written: %d",
		wiperType, processName, target, bytesWritten)

	if pattern == "zero_fill" {
		desc += ". Write pattern: zero-fill (all 0x00 bytes). MITRE ATT&CK T1561.001: Disk Content Wipe."
	} else if pattern == "random_fill" {
		desc += ". Write pattern: random data overwrite. MITRE ATT&CK T1561.001: Disk Content Wipe."
	} else {
		desc += fmt.Sprintf(". MITRE ATT&CK T1561: Disk Wipe.")
	}

	// Track cumulative wipe activity
	stats := i.wiperTracker.GetStats(event.SourceIP)
	if stats.EventCount > 3 {
		desc += fmt.Sprintf(" ESCALATION: %d wipe events from this host in %s — coordinated destruction campaign.",
			stats.EventCount, stats.Duration.String())
	}

	i.raiseAlert(event, severity, title, desc, "wiper_activity")
}

// checkCompoundAttack detects when multiple pre-ransomware indicators fire together,
// which is a near-certain sign of imminent ransomware deployment.
func (i *Interceptor) checkCompoundAttack(event *core.SecurityEvent) {
	stats := i.backupTracker.GetStats(event.SourceIP)

	// If we see VSS deletion + backup destruction + service stops from the same host,
	// this is a compound ransomware preparation attack
	indicators := 0
	if stats.VSSDeletes > 0 {
		indicators++
	}
	if stats.BackupDestroys > 0 {
		indicators++
	}
	if stats.ServiceStops > 0 {
		indicators++
	}

	if indicators >= 2 {
		i.raiseAlert(event, core.SeverityCritical,
			"COMPOUND RANSOMWARE PREPARATION [T1490+T1489]",
			fmt.Sprintf("Multiple ransomware preparation indicators detected from %s: %d VSS deletions, %d backup destructions, %d service stops in %s. MITRE ATT&CK T1490+T1489. IMMEDIATE ACTION REQUIRED: Ransomware deployment is imminent. Isolate this host NOW.",
				event.SourceIP, stats.VSSDeletes, stats.BackupDestroys, stats.ServiceStops, stats.Duration.String()),
			"compound_ransomware_prep")
	}
}

func (i *Interceptor) raiseAlert(event *core.SecurityEvent, severity core.Severity, title, description, alertType string) {
	newEvent := core.NewSecurityEvent(ModuleName, alertType, severity, description)
	newEvent.SourceIP = event.SourceIP
	newEvent.Details["original_event_id"] = event.ID

	if i.bus != nil {
		_ = i.bus.PublishEvent(newEvent)
	}

	alert := core.NewAlert(newEvent, title, description)
	alert.Mitigations = getRansomwareMitigations(alertType)
	if i.pipeline != nil {
		i.pipeline.Process(alert)
	}
}

// getRansomwareMitigations returns context-specific mitigations based on alert type.
func getRansomwareMitigations(alertType string) []string {
	base := []string{
		"Immediately isolate the affected system from the network",
		"Preserve forensic evidence for investigation",
	}

	switch alertType {
	case "shadow_copy_delete", "backup_destruction", "compound_ransomware_prep":
		return append(base,
			"Verify offline/air-gapped backup integrity immediately",
			"Block the responsible process and user account",
			"Check for lateral movement to other systems",
			"Ransomware deployment is likely imminent — escalate to incident response",
			"Do NOT restart the system — it may trigger encryption payload",
		)
	case "wiper_activity", "mbr_overwrite", "partition_destroy":
		return append(base,
			"This is a DESTRUCTIVE attack — data recovery may not be possible",
			"Power off affected systems to prevent further destruction",
			"Do NOT attempt to reboot — MBR/partition may be destroyed",
			"Engage disk forensics team for potential data recovery",
			"Check for wiper propagation to other networked systems",
		)
	case "service_stop":
		return append(base,
			"Restart critical services if safe to do so",
			"Monitor for subsequent encryption activity",
			"Verify backup service availability",
		)
	case "data_exfiltration":
		return append(base,
			"Block outbound connections from the affected host",
			"Identify what data was transferred and to where",
			"This may indicate double-extortion ransomware (encrypt + leak)",
		)
	default:
		return append(base,
			"Identify and terminate the malicious process",
			"Verify backup integrity before attempting restoration",
			"Do not pay the ransom — it does not guarantee data recovery",
		)
	}
}

// ---------------------------------------------------------------------------
// WiperTracker monitors disk wipe activity patterns.
// ---------------------------------------------------------------------------

type WiperTracker struct {
	mu      sync.RWMutex
	records map[string]*wiperRecord // sourceIP -> record
}

type wiperRecord struct {
	events    []wiperEvent
	firstSeen time.Time
	lastSeen  time.Time
}

type wiperEvent struct {
	timestamp   time.Time
	processName string
	wiperType   string
}

type WiperStats struct {
	EventCount int
	Duration   time.Duration
}

func NewWiperTracker() *WiperTracker {
	return &WiperTracker{
		records: make(map[string]*wiperRecord),
	}
}

func (wt *WiperTracker) RecordEvent(sourceIP, processName, wiperType string) {
	wt.mu.Lock()
	defer wt.mu.Unlock()

	now := time.Now()
	rec, exists := wt.records[sourceIP]
	if !exists {
		rec = &wiperRecord{
			firstSeen: now,
		}
		wt.records[sourceIP] = rec
	}

	rec.events = append(rec.events, wiperEvent{
		timestamp:   now,
		processName: processName,
		wiperType:   wiperType,
	})
	rec.lastSeen = now
}

func (wt *WiperTracker) GetStats(sourceIP string) WiperStats {
	wt.mu.RLock()
	defer wt.mu.RUnlock()

	rec, exists := wt.records[sourceIP]
	if !exists {
		return WiperStats{}
	}
	return WiperStats{
		EventCount: len(rec.events),
		Duration:   rec.lastSeen.Sub(rec.firstSeen),
	}
}

func (wt *WiperTracker) CleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			wt.mu.Lock()
			cutoff := time.Now().Add(-1 * time.Hour)
			for ip, rec := range wt.records {
				if rec.lastSeen.Before(cutoff) {
					delete(wt.records, ip)
				}
			}
			wt.mu.Unlock()
		}
	}
}

// ---------------------------------------------------------------------------
// BackupDestructionTracker monitors backup/VSS/service-stop compound attacks.
// ---------------------------------------------------------------------------

type BackupDestructionTracker struct {
	mu      sync.RWMutex
	records map[string]*backupDestructionRecord // sourceIP -> record
}

type backupDestructionRecord struct {
	vssDeletes     int
	backupDestroys int
	serviceStops   int
	firstSeen      time.Time
	lastSeen       time.Time
}

type BackupDestructionStats struct {
	VSSDeletes     int
	BackupDestroys int
	ServiceStops   int
	Duration       time.Duration
}

func NewBackupDestructionTracker() *BackupDestructionTracker {
	return &BackupDestructionTracker{
		records: make(map[string]*backupDestructionRecord),
	}
}

func (bt *BackupDestructionTracker) RecordEvent(sourceIP, eventType string) {
	bt.mu.Lock()
	defer bt.mu.Unlock()

	now := time.Now()
	rec, exists := bt.records[sourceIP]
	if !exists || now.Sub(rec.lastSeen) > 30*time.Minute {
		rec = &backupDestructionRecord{
			firstSeen: now,
		}
		bt.records[sourceIP] = rec
	}

	switch eventType {
	case "vss_delete":
		rec.vssDeletes++
	case "backup_destroy":
		rec.backupDestroys++
	case "service_stop":
		rec.serviceStops++
	}
	rec.lastSeen = now
}

func (bt *BackupDestructionTracker) GetStats(sourceIP string) BackupDestructionStats {
	bt.mu.RLock()
	defer bt.mu.RUnlock()

	rec, exists := bt.records[sourceIP]
	if !exists {
		return BackupDestructionStats{}
	}
	return BackupDestructionStats{
		VSSDeletes:     rec.vssDeletes,
		BackupDestroys: rec.backupDestroys,
		ServiceStops:   rec.serviceStops,
		Duration:       rec.lastSeen.Sub(rec.firstSeen),
	}
}

func (bt *BackupDestructionTracker) CleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			bt.mu.Lock()
			cutoff := time.Now().Add(-1 * time.Hour)
			for ip, rec := range bt.records {
				if rec.lastSeen.Before(cutoff) {
					delete(bt.records, ip)
				}
			}
			bt.mu.Unlock()
		}
	}
}

// ---------------------------------------------------------------------------
// FileActivityTracker monitors file modification patterns for ransomware behavior.
// ---------------------------------------------------------------------------

type FileActivityTracker struct {
	mu                  sync.RWMutex
	processActivity     map[string]*processFileActivity
	encryptionThreshold int
}

type processFileActivity struct {
	modifiedFiles map[string]bool
	renamedFiles  int
	totalEntropy  float64
	entropyCount  int
	firstSeen     time.Time
	lastSeen      time.Time
}

type ActivityResult struct {
	MassEncryption bool
	HighEntropy    bool
	RapidRename    bool
	FileCount      int
	RenameCount    int
	AvgEntropy     float64
	Duration       time.Duration
}

func NewFileActivityTracker(threshold int) *FileActivityTracker {
	return &FileActivityTracker{
		processActivity:     make(map[string]*processFileActivity),
		encryptionThreshold: threshold,
	}
}

func (ft *FileActivityTracker) RecordModification(process, path string, entropy float64) ActivityResult {
	ft.mu.Lock()
	defer ft.mu.Unlock()

	result := ActivityResult{}
	now := time.Now()

	activity, exists := ft.processActivity[process]
	if !exists || now.Sub(activity.lastSeen) > 5*time.Minute {
		activity = &processFileActivity{
			modifiedFiles: make(map[string]bool),
			firstSeen:     now,
		}
		ft.processActivity[process] = activity
	}

	activity.modifiedFiles[path] = true
	activity.lastSeen = now

	if entropy > 0 {
		activity.totalEntropy += entropy
		activity.entropyCount++
	}

	result.FileCount = len(activity.modifiedFiles)
	result.Duration = now.Sub(activity.firstSeen)

	if activity.entropyCount > 0 {
		result.AvgEntropy = activity.totalEntropy / float64(activity.entropyCount)
	}

	// High entropy indicates encryption (random data has entropy ~8.0)
	if entropy > 7.5 {
		result.HighEntropy = true
	}

	// Mass encryption: many files modified with high average entropy
	if result.FileCount >= ft.encryptionThreshold && result.AvgEntropy > 7.0 {
		result.MassEncryption = true
	}

	// Rapid rename detection
	if strings.Contains(strings.ToLower(path), "renamed") || isRansomwareExtension(path) {
		activity.renamedFiles++
	}
	result.RenameCount = activity.renamedFiles
	if activity.renamedFiles > 5 && result.Duration < 2*time.Minute {
		result.RapidRename = true
	}

	return result
}

func (ft *FileActivityTracker) CleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ft.mu.Lock()
			cutoff := time.Now().Add(-30 * time.Minute)
			for proc, activity := range ft.processActivity {
				if activity.lastSeen.Before(cutoff) {
					delete(ft.processActivity, proc)
				}
			}
			ft.mu.Unlock()
		}
	}
}

// ---------------------------------------------------------------------------
// ExfilTracker monitors data egress for exfiltration detection.
// ---------------------------------------------------------------------------

type ExfilTracker struct {
	mu        sync.RWMutex
	records   map[string]*exfilRecord // sourceIP -> record
	threshold int64
}

type exfilRecord struct {
	totalBytes   int64
	destinations map[string]bool
	firstSeen    time.Time
	lastSeen     time.Time
}

type ExfilStats struct {
	TotalBytes         int64
	UniqueDestinations int
}

func NewExfilTracker(thresholdBytes int64) *ExfilTracker {
	return &ExfilTracker{
		records:   make(map[string]*exfilRecord),
		threshold: thresholdBytes,
	}
}

func (et *ExfilTracker) Record(sourceIP, destIP string, bytes int64) bool {
	et.mu.Lock()
	defer et.mu.Unlock()

	now := time.Now()
	rec, exists := et.records[sourceIP]
	if !exists || now.Sub(rec.firstSeen) > time.Hour {
		rec = &exfilRecord{
			destinations: make(map[string]bool),
			firstSeen:    now,
		}
		et.records[sourceIP] = rec
	}

	rec.totalBytes += bytes
	rec.lastSeen = now
	if destIP != "" {
		rec.destinations[destIP] = true
	}

	return rec.totalBytes > et.threshold
}

func (et *ExfilTracker) GetStats(sourceIP string) ExfilStats {
	et.mu.RLock()
	defer et.mu.RUnlock()

	rec, exists := et.records[sourceIP]
	if !exists {
		return ExfilStats{}
	}
	return ExfilStats{
		TotalBytes:         rec.totalBytes,
		UniqueDestinations: len(rec.destinations),
	}
}

func (et *ExfilTracker) CleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			et.mu.Lock()
			cutoff := time.Now().Add(-2 * time.Hour)
			for ip, rec := range et.records {
				if rec.lastSeen.Before(cutoff) {
					delete(et.records, ip)
				}
			}
			et.mu.Unlock()
		}
	}
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

func isRansomwareExtension(path string) bool {
	ransomExts := []string{
		".encrypted", ".locked", ".crypto", ".crypt",
		".locky", ".cerber", ".zepto", ".thor",
		".aesir", ".zzzzz", ".micro", ".enc",
		".crypted", ".crinf", ".r5a", ".xrtn",
		".xtbl", ".crypt1", ".da_vinci_code",
		".magic", ".SUPERCRYPT", ".CTBL", ".CTB2",
		".wncry", ".wcry", ".wncryt", ".WNCRYPT",
		".petya", ".notpetya", ".gandcrab",
		".ryuk", ".sodinokibi", ".revil",
		".conti", ".lockbit", ".blackcat",
		".alphv", ".hive", ".royal",
		".play", ".blackbasta", ".akira",
		".rhysida", ".medusa", ".bianlian",
	}
	pathLower := strings.ToLower(path)
	for _, ext := range ransomExts {
		if strings.HasSuffix(pathLower, strings.ToLower(ext)) {
			return true
		}
	}
	return false
}

func isRansomNote(path string) bool {
	notePatterns := []string{
		"readme", "how_to_decrypt", "how_to_recover",
		"decrypt_instructions", "ransom", "restore_files",
		"your_files", "attention", "warning",
		"recovery_key", "decrypt_your_files",
		"!readme!", "help_decrypt", "read_me",
		"_readme_", "how_to_back", "restore_data",
		"recover_your_files", "files_encrypted",
		"important_read_me", "decrypt_info",
	}
	pathLower := strings.ToLower(path)
	for _, pattern := range notePatterns {
		if strings.Contains(pathLower, pattern) {
			ext := strings.ToLower(pathAfterLastDot(path))
			if ext == "txt" || ext == "html" || ext == "hta" || ext == "" {
				return true
			}
		}
	}
	return false
}

func pathAfterLastDot(s string) string {
	idx := strings.LastIndex(s, ".")
	if idx < 0 {
		return ""
	}
	return s[idx+1:]
}

// ShannonEntropy calculates the Shannon entropy of a byte slice.
func ShannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	freq := make(map[byte]float64)
	for _, b := range data {
		freq[b]++
	}
	length := float64(len(data))
	entropy := 0.0
	for _, count := range freq {
		p := count / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
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

func getIntDetail(event *core.SecurityEvent, key string) int {
	if event.Details == nil {
		return 0
	}
	switch v := event.Details[key].(type) {
	case int:
		return v
	case float64:
		return int(v)
	}
	return 0
}

func getFloatDetail(event *core.SecurityEvent, key string) float64 {
	if event.Details == nil {
		return 0
	}
	switch v := event.Details[key].(type) {
	case float64:
		return v
	case int:
		return float64(v)
	}
	return 0
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
