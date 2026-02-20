package ransomware

import (
	"context"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/1sec-project/1sec/internal/core"
	"github.com/rs/zerolog"
)

// ─── Helpers ─────────────────────────────────────────────────────────────────

type capturingPipeline struct {
	pipeline *core.AlertPipeline
	mu       sync.Mutex
	alerts   []*core.Alert
}

func makeCapturingPipeline() *capturingPipeline {
	cp := &capturingPipeline{}
	cp.pipeline = core.NewAlertPipeline(zerolog.Nop(), 10000)
	cp.pipeline.AddHandler(func(a *core.Alert) {
		cp.mu.Lock()
		cp.alerts = append(cp.alerts, a)
		cp.mu.Unlock()
	})
	return cp
}

func (cp *capturingPipeline) count() int {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	return len(cp.alerts)
}

func (cp *capturingPipeline) alertTitles() []string {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	titles := make([]string, len(cp.alerts))
	for i, a := range cp.alerts {
		titles[i] = a.Title
	}
	return titles
}

func startedModule(t *testing.T) *Interceptor {
	t.Helper()
	i := New()
	cfg := core.DefaultConfig()
	if err := i.Start(context.Background(), nil, nil, cfg); err != nil {
		t.Fatalf("Interceptor.Start() error: %v", err)
	}
	return i
}

func startedModuleWithPipeline(t *testing.T, cp *capturingPipeline) *Interceptor {
	t.Helper()
	i := New()
	cfg := core.DefaultConfig()
	if err := i.Start(context.Background(), nil, cp.pipeline, cfg); err != nil {
		t.Fatalf("Interceptor.Start() error: %v", err)
	}
	return i
}

// ─── Module Interface ─────────────────────────────────────────────────────────

func TestInterceptor_Name(t *testing.T) {
	i := New()
	if i.Name() != ModuleName {
		t.Errorf("Name() = %q, want %q", i.Name(), ModuleName)
	}
}

func TestInterceptor_Description(t *testing.T) {
	i := New()
	if i.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

func TestInterceptor_Start_Stop(t *testing.T) {
	i := New()
	cfg := core.DefaultConfig()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := i.Start(ctx, nil, nil, cfg); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	if i.fileTracker == nil {
		t.Error("fileTracker should be initialized")
	}
	if i.exfilTracker == nil {
		t.Error("exfilTracker should be initialized")
	}
	if i.wiperTracker == nil {
		t.Error("wiperTracker should be initialized")
	}
	if i.backupTracker == nil {
		t.Error("backupTracker should be initialized")
	}
	if err := i.Stop(); err != nil {
		t.Fatalf("Stop() error: %v", err)
	}
}

// ─── isRansomwareExtension ────────────────────────────────────────────────────

func TestIsRansomwareExtension(t *testing.T) {
	ransomExts := []string{
		"file.encrypted", "file.locked", "file.crypto", "file.locky",
		"file.wncry", "file.ryuk", "file.conti", "file.lockbit",
		"file.blackcat", "file.akira", "file.medusa",
	}
	for _, f := range ransomExts {
		if !isRansomwareExtension(f) {
			t.Errorf("expected %q to be detected as ransomware extension", f)
		}
	}

	normalFiles := []string{
		"file.txt", "file.pdf", "file.docx", "file.jpg", "file.go",
	}
	for _, f := range normalFiles {
		if isRansomwareExtension(f) {
			t.Errorf("expected %q to NOT be detected as ransomware extension", f)
		}
	}
}

// ─── isRansomNote ─────────────────────────────────────────────────────────────

func TestIsRansomNote(t *testing.T) {
	notes := []string{
		"README.txt", "HOW_TO_DECRYPT.txt", "RANSOM_NOTE.html",
		"RESTORE_FILES.hta", "YOUR_FILES.txt", "!README!.txt",
		"DECRYPT_INSTRUCTIONS.txt", "how_to_recover.html",
	}
	for _, n := range notes {
		if !isRansomNote(n) {
			t.Errorf("expected %q to be detected as ransom note", n)
		}
	}

	notNotes := []string{
		"readme.go", "readme.py", "config.yaml", "main.go",
		"readme.pdf", // pdf not in the extension list
	}
	for _, n := range notNotes {
		if isRansomNote(n) {
			t.Errorf("expected %q to NOT be detected as ransom note", n)
		}
	}
}

// ─── ShannonEntropy ───────────────────────────────────────────────────────────

func TestShannonEntropy(t *testing.T) {
	// Empty = 0
	if e := ShannonEntropy(nil); e != 0 {
		t.Errorf("ShannonEntropy(nil) = %f, want 0", e)
	}
	if e := ShannonEntropy([]byte{}); e != 0 {
		t.Errorf("ShannonEntropy([]) = %f, want 0", e)
	}

	// All same bytes = 0
	data := make([]byte, 100)
	if e := ShannonEntropy(data); e != 0 {
		t.Errorf("ShannonEntropy(all zeros) = %f, want 0", e)
	}

	// Two equally distributed bytes = 1 bit
	data2 := make([]byte, 100)
	for i := range data2 {
		data2[i] = byte(i % 2)
	}
	e := ShannonEntropy(data2)
	if e < 0.9 || e > 1.1 {
		t.Errorf("ShannonEntropy(50/50) = %f, want ~1.0", e)
	}

	// Random-like data should have high entropy
	data3 := make([]byte, 256)
	for i := range data3 {
		data3[i] = byte(i)
	}
	e3 := ShannonEntropy(data3)
	if e3 < 7.9 {
		t.Errorf("ShannonEntropy(all bytes) = %f, want ~8.0", e3)
	}
}

// ─── FileActivityTracker ──────────────────────────────────────────────────────

func TestFileActivityTracker_HighEntropy(t *testing.T) {
	ft := NewFileActivityTracker(10)
	result := ft.RecordModification("evil.exe", "/data/file1.doc", 7.8)
	if !result.HighEntropy {
		t.Error("expected HighEntropy=true for entropy 7.8")
	}
}

func TestFileActivityTracker_NormalEntropy(t *testing.T) {
	ft := NewFileActivityTracker(10)
	result := ft.RecordModification("notepad.exe", "/data/file1.txt", 4.0)
	if result.HighEntropy {
		t.Error("expected HighEntropy=false for entropy 4.0")
	}
}

func TestFileActivityTracker_MassEncryption(t *testing.T) {
	ft := NewFileActivityTracker(5)
	var result ActivityResult
	for i := 0; i < 10; i++ {
		result = ft.RecordModification("evil.exe", "/data/file"+string(rune('a'+i))+".doc", 7.5)
	}
	if !result.MassEncryption {
		t.Error("expected MassEncryption=true for 10 files with high entropy")
	}
}

func TestFileActivityTracker_NoMassEncryption_LowEntropy(t *testing.T) {
	ft := NewFileActivityTracker(5)
	var result ActivityResult
	for i := 0; i < 10; i++ {
		result = ft.RecordModification("notepad.exe", "/data/file"+string(rune('a'+i))+".txt", 3.0)
	}
	if result.MassEncryption {
		t.Error("expected MassEncryption=false for low entropy files")
	}
}

func TestFileActivityTracker_RapidRename(t *testing.T) {
	ft := NewFileActivityTracker(10)
	var result ActivityResult
	for i := 0; i < 10; i++ {
		result = ft.RecordModification("evil.exe", "/data/file"+string(rune('a'+i))+".encrypted", 7.0)
	}
	if !result.RapidRename {
		t.Error("expected RapidRename=true for rapid ransomware extension renames")
	}
}

func TestFileActivityTracker_CleanupLoop(t *testing.T) {
	ft := NewFileActivityTracker(10)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		ft.CleanupLoop(ctx)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("CleanupLoop did not exit after context cancellation")
	}
}

// ─── ExfilTracker ─────────────────────────────────────────────────────────────

func TestExfilTracker_BelowThreshold(t *testing.T) {
	et := NewExfilTracker(100 * 1024 * 1024) // 100 MB
	exceeded := et.Record("10.0.0.1", "evil.com", 1024)
	if exceeded {
		t.Error("1KB should not exceed 100MB threshold")
	}
}

func TestExfilTracker_ExceedsThreshold(t *testing.T) {
	et := NewExfilTracker(1024) // 1 KB threshold
	et.Record("10.0.0.1", "evil.com", 500)
	exceeded := et.Record("10.0.0.1", "evil.com", 600)
	if !exceeded {
		t.Error("1100 bytes should exceed 1024 byte threshold")
	}
}

func TestExfilTracker_GetStats(t *testing.T) {
	et := NewExfilTracker(1024 * 1024)
	et.Record("10.0.0.1", "dest1.com", 1000)
	et.Record("10.0.0.1", "dest2.com", 2000)
	et.Record("10.0.0.1", "dest1.com", 500)

	stats := et.GetStats("10.0.0.1")
	if stats.TotalBytes != 3500 {
		t.Errorf("TotalBytes = %d, want 3500", stats.TotalBytes)
	}
	if stats.UniqueDestinations != 2 {
		t.Errorf("UniqueDestinations = %d, want 2", stats.UniqueDestinations)
	}
}

func TestExfilTracker_GetStats_Unknown(t *testing.T) {
	et := NewExfilTracker(1024)
	stats := et.GetStats("unknown")
	if stats.TotalBytes != 0 {
		t.Error("unknown IP should have 0 bytes")
	}
}

// ─── WiperTracker ─────────────────────────────────────────────────────────────

func TestWiperTracker_RecordAndStats(t *testing.T) {
	wt := NewWiperTracker()
	wt.RecordEvent("10.0.0.1", "dd", "zero_fill")
	wt.RecordEvent("10.0.0.1", "dd", "random_fill")
	wt.RecordEvent("10.0.0.1", "shred", "overwrite")

	stats := wt.GetStats("10.0.0.1")
	if stats.EventCount != 3 {
		t.Errorf("EventCount = %d, want 3", stats.EventCount)
	}
}

func TestWiperTracker_GetStats_Unknown(t *testing.T) {
	wt := NewWiperTracker()
	stats := wt.GetStats("unknown")
	if stats.EventCount != 0 {
		t.Error("unknown IP should have 0 events")
	}
}

func TestWiperTracker_CleanupLoop(t *testing.T) {
	wt := NewWiperTracker()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		wt.CleanupLoop(ctx)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("CleanupLoop did not exit after context cancellation")
	}
}

// ─── BackupDestructionTracker ─────────────────────────────────────────────────

func TestBackupDestructionTracker_CompoundAttack(t *testing.T) {
	bt := NewBackupDestructionTracker()
	bt.RecordEvent("10.0.0.1", "vss_delete")
	bt.RecordEvent("10.0.0.1", "backup_destroy")
	bt.RecordEvent("10.0.0.1", "service_stop")

	stats := bt.GetStats("10.0.0.1")
	if stats.VSSDeletes != 1 {
		t.Errorf("VSSDeletes = %d, want 1", stats.VSSDeletes)
	}
	if stats.BackupDestroys != 1 {
		t.Errorf("BackupDestroys = %d, want 1", stats.BackupDestroys)
	}
	if stats.ServiceStops != 1 {
		t.Errorf("ServiceStops = %d, want 1", stats.ServiceStops)
	}
}

func TestBackupDestructionTracker_CleanupLoop(t *testing.T) {
	bt := NewBackupDestructionTracker()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		bt.CleanupLoop(ctx)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("CleanupLoop did not exit after context cancellation")
	}
}

// ─── getRansomwareMitigations ─────────────────────────────────────────────────

func TestGetRansomwareMitigations(t *testing.T) {
	types := []string{
		"shadow_copy_delete", "backup_destruction", "compound_ransomware_prep",
		"wiper_activity", "mbr_overwrite", "partition_destroy",
		"service_stop", "data_exfiltration", "unknown_type",
	}
	for _, at := range types {
		m := getRansomwareMitigations(at)
		if len(m) < 2 {
			t.Errorf("getRansomwareMitigations(%q) returned only %d items, want >= 2", at, len(m))
		}
	}
}

// ─── HandleEvent Integration ──────────────────────────────────────────────────

func TestInterceptor_HandleEvent_RansomwareExtension(t *testing.T) {
	cp := makeCapturingPipeline()
	i := startedModuleWithPipeline(t, cp)
	defer i.Stop()

	ev := core.NewSecurityEvent("test", "file_modified", core.SeverityInfo, "file modified")
	ev.Details["path"] = "/data/important.encrypted"
	ev.Details["process_name"] = "evil.exe"
	ev.Details["entropy"] = 7.9
	ev.SourceIP = "10.0.0.1"

	i.HandleEvent(ev)

	titles := cp.alertTitles()
	found := false
	for _, title := range titles {
		if title == "Ransomware Extension Detected [T1486]" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected ransomware extension alert, got: %v", titles)
	}
}

func TestInterceptor_HandleEvent_RansomNote(t *testing.T) {
	cp := makeCapturingPipeline()
	i := startedModuleWithPipeline(t, cp)
	defer i.Stop()

	ev := core.NewSecurityEvent("test", "file_created", core.SeverityInfo, "file created")
	ev.Details["path"] = "/data/HOW_TO_DECRYPT.txt"
	ev.SourceIP = "10.0.0.1"

	i.HandleEvent(ev)

	titles := cp.alertTitles()
	found := false
	for _, title := range titles {
		if title == "Ransom Note Detected [T1491]" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected ransom note alert, got: %v", titles)
	}
}

func TestInterceptor_HandleEvent_DataExfiltration(t *testing.T) {
	cp := makeCapturingPipeline()
	i := New()
	cfg := core.DefaultConfig()
	cfg.Modules[ModuleName] = core.ModuleConfig{
		Enabled: true,
		Settings: map[string]interface{}{
			"exfil_mb_threshold": 1, // 1 MB threshold for testing
		},
	}
	i.Start(context.Background(), nil, cp.pipeline, cfg)
	defer i.Stop()

	ev := core.NewSecurityEvent("test", "network_egress", core.SeverityInfo, "egress")
	ev.SourceIP = "10.0.0.1"
	ev.DestIP = "evil.com"
	ev.Details["bytes"] = 2 * 1024 * 1024 // 2 MB
	ev.Details["destination"] = "evil.com"

	i.HandleEvent(ev)

	titles := cp.alertTitles()
	found := false
	for _, title := range titles {
		if title == "Data Exfiltration Detected [T1041]" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected data exfiltration alert, got: %v", titles)
	}
}

func TestInterceptor_HandleEvent_CanaryTriggered(t *testing.T) {
	cp := makeCapturingPipeline()
	i := startedModuleWithPipeline(t, cp)
	defer i.Stop()

	ev := core.NewSecurityEvent("test", "canary_triggered", core.SeverityInfo, "canary")
	ev.Details["canary_path"] = "/data/.canary_file"
	ev.Details["process_name"] = "suspicious.exe"
	ev.SourceIP = "10.0.0.1"

	i.HandleEvent(ev)

	titles := cp.alertTitles()
	found := false
	for _, title := range titles {
		if title == "Canary File Triggered" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected canary triggered alert, got: %v", titles)
	}
}

func TestInterceptor_HandleEvent_ShadowCopyDeletion(t *testing.T) {
	cp := makeCapturingPipeline()
	i := startedModuleWithPipeline(t, cp)
	defer i.Stop()

	ev := core.NewSecurityEvent("test", "process_execution", core.SeverityInfo, "process exec")
	ev.Details["command_line"] = "vssadmin delete shadows /all /quiet"
	ev.Details["process_name"] = "cmd.exe"
	ev.SourceIP = "10.0.0.1"

	i.HandleEvent(ev)

	titles := cp.alertTitles()
	found := false
	for _, title := range titles {
		if title == "Shadow Copy Deletion Detected [T1490]" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected shadow copy deletion alert, got: %v", titles)
	}
}

func TestInterceptor_HandleEvent_BackupDestruction(t *testing.T) {
	cp := makeCapturingPipeline()
	i := startedModuleWithPipeline(t, cp)
	defer i.Stop()

	ev := core.NewSecurityEvent("test", "process_execution", core.SeverityInfo, "process exec")
	ev.Details["command_line"] = "bcdedit /set {default} recoveryenabled no"
	ev.Details["process_name"] = "bcdedit.exe"
	ev.SourceIP = "10.0.0.1"

	i.HandleEvent(ev)

	titles := cp.alertTitles()
	found := false
	for _, title := range titles {
		if title == "Backup Destruction Detected [T1490]" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected backup destruction alert, got: %v", titles)
	}
}

func TestInterceptor_HandleEvent_WiperCommand(t *testing.T) {
	cp := makeCapturingPipeline()
	i := startedModuleWithPipeline(t, cp)
	defer i.Stop()

	ev := core.NewSecurityEvent("test", "process_execution", core.SeverityInfo, "process exec")
	ev.Details["command_line"] = "dd if=/dev/zero of=/dev/sda bs=1M"
	ev.Details["process_name"] = "dd"
	ev.SourceIP = "10.0.0.1"

	i.HandleEvent(ev)

	titles := cp.alertTitles()
	found := false
	for _, title := range titles {
		if title == "Wiper Activity Detected [T1561]" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected wiper activity alert, got: %v", titles)
	}
}

func TestInterceptor_HandleEvent_ServiceStop(t *testing.T) {
	cp := makeCapturingPipeline()
	i := startedModuleWithPipeline(t, cp)
	defer i.Stop()

	ev := core.NewSecurityEvent("test", "process_execution", core.SeverityInfo, "process exec")
	ev.Details["command_line"] = "net stop vss"
	ev.Details["process_name"] = "net.exe"
	ev.SourceIP = "10.0.0.1"

	i.HandleEvent(ev)

	titles := cp.alertTitles()
	found := false
	for _, title := range titles {
		if title == "Critical Service Stopped [T1489]" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected service stop alert, got: %v", titles)
	}
}

func TestInterceptor_HandleEvent_MBROverwrite(t *testing.T) {
	cp := makeCapturingPipeline()
	i := startedModuleWithPipeline(t, cp)
	defer i.Stop()

	ev := core.NewSecurityEvent("test", "mbr_write", core.SeverityInfo, "MBR write")
	ev.Details["process_name"] = "wiper.exe"
	ev.Details["target"] = "\\\\.\\PhysicalDrive0"
	ev.Details["bytes_written"] = 512
	ev.Details["offset"] = 0
	ev.SourceIP = "10.0.0.1"

	i.HandleEvent(ev)

	titles := cp.alertTitles()
	found := false
	for _, title := range titles {
		if title == "MBR/GPT Overwrite Detected [T1561.002]" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected MBR overwrite alert, got: %v", titles)
	}
}

func TestInterceptor_HandleEvent_ShadowCopyEvent(t *testing.T) {
	cp := makeCapturingPipeline()
	i := startedModuleWithPipeline(t, cp)
	defer i.Stop()

	ev := core.NewSecurityEvent("test", "shadow_copy_delete", core.SeverityInfo, "VSS delete")
	ev.Details["method"] = "vssadmin"
	ev.Details["process_name"] = "cmd.exe"
	ev.Details["target"] = "all"
	ev.SourceIP = "10.0.0.1"

	i.HandleEvent(ev)

	if cp.count() == 0 {
		t.Error("expected alert for shadow_copy_delete event")
	}
}

func TestInterceptor_HandleEvent_BackupDestroyEvent(t *testing.T) {
	cp := makeCapturingPipeline()
	i := startedModuleWithPipeline(t, cp)
	defer i.Stop()

	ev := core.NewSecurityEvent("test", "backup_destruction", core.SeverityInfo, "backup destroy")
	ev.Details["backup_type"] = "windows_backup"
	ev.Details["process_name"] = "wbadmin.exe"
	ev.Details["action"] = "deleted"
	ev.Details["target"] = "system_state"
	ev.SourceIP = "10.0.0.1"

	i.HandleEvent(ev)

	if cp.count() == 0 {
		t.Error("expected alert for backup_destruction event")
	}
}

func TestInterceptor_HandleEvent_CompoundAttack(t *testing.T) {
	cp := makeCapturingPipeline()
	i := startedModuleWithPipeline(t, cp)
	defer i.Stop()

	// VSS deletion
	ev1 := core.NewSecurityEvent("test", "shadow_copy_delete", core.SeverityInfo, "VSS delete")
	ev1.Details["method"] = "vssadmin"
	ev1.SourceIP = "10.0.0.1"
	i.HandleEvent(ev1)

	// Backup destruction
	ev2 := core.NewSecurityEvent("test", "backup_destruction", core.SeverityInfo, "backup destroy")
	ev2.Details["backup_type"] = "windows"
	ev2.SourceIP = "10.0.0.1"
	i.HandleEvent(ev2)

	titles := cp.alertTitles()
	found := false
	for _, title := range titles {
		if title == "COMPOUND RANSOMWARE PREPARATION [T1490+T1489]" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected compound ransomware preparation alert, got: %v", titles)
	}
}

// ─── pathAfterLastDot ─────────────────────────────────────────────────────────

func TestPathAfterLastDot(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"file.txt", "txt"},
		{"file.tar.gz", "gz"},
		{"noext", ""},
		{"", ""},
		{".hidden", "hidden"},
	}
	for _, tc := range tests {
		got := pathAfterLastDot(tc.input)
		if got != tc.want {
			t.Errorf("pathAfterLastDot(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

// ─── Compile-time interface check ─────────────────────────────────────────────

var _ core.Module = (*Interceptor)(nil)

// Suppress unused import
var _ = math.Log2
