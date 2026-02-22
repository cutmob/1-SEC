package cloudposture

import (
	"context"
	"sync"
	"testing"

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

func (cp *capturingPipeline) hasAlertType(alertType string) bool {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	for _, a := range cp.alerts {
		if a.Type == alertType {
			return true
		}
	}
	return false
}

func startedModule(t *testing.T) *Manager {
	t.Helper()
	m := New()
	cfg := core.DefaultConfig()
	if err := m.Start(context.Background(), nil, nil, cfg); err != nil {
		t.Fatalf("Manager.Start() error: %v", err)
	}
	return m
}

func startedModuleWithPipeline(t *testing.T, cp *capturingPipeline) *Manager {
	t.Helper()
	m := New()
	cfg := core.DefaultConfig()
	if err := m.Start(context.Background(), nil, cp.pipeline, cfg); err != nil {
		t.Fatalf("Manager.Start() error: %v", err)
	}
	return m
}

// ─── Module Interface ─────────────────────────────────────────────────────────

func TestManager_Name(t *testing.T) {
	m := New()
	if m.Name() != ModuleName {
		t.Errorf("Name() = %q, want %q", m.Name(), ModuleName)
	}
}

func TestManager_Description(t *testing.T) {
	m := New()
	if m.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

func TestManager_Start_Stop(t *testing.T) {
	m := New()
	cfg := core.DefaultConfig()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := m.Start(ctx, nil, nil, cfg); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	if m.driftTracker == nil {
		t.Error("driftTracker should be initialized after Start")
	}
	if m.secretScanner == nil {
		t.Error("secretScanner should be initialized after Start")
	}
	if m.policyEngine == nil {
		t.Error("policyEngine should be initialized after Start")
	}
	if err := m.Stop(); err != nil {
		t.Fatalf("Stop() error: %v", err)
	}
}

// ─── DriftTracker ─────────────────────────────────────────────────────────────

func TestDriftTracker_RecordChange_RapidChanges(t *testing.T) {
	dt := NewDriftTracker()

	var result DriftResult
	for i := 0; i < 12; i++ {
		result = dt.RecordChange("vpc-123", "security_group", "update", "admin", "old", "new")
	}

	if !result.RapidChanges {
		t.Error("expected RapidChanges after >10 changes")
	}
	if result.ChangeCount < 11 {
		t.Errorf("ChangeCount = %d, want > 10", result.ChangeCount)
	}
}

func TestDriftTracker_RecordChange_SecurityDegradation(t *testing.T) {
	dt := NewDriftTracker()

	tests := []struct {
		name         string
		resourceType string
		changeType   string
		oldValue     string
		newValue     string
	}{
		{"public access", "storage_bucket", "acl_change", "private", "public-read"},
		{"encryption disabled", "database", "encryption", "true", "disabled"},
		{"logging disabled", "vpc", "logging", "true", "disabled"},
		{"firewall opened", "security_group", "firewall", "10.0.0.0/8", "0.0.0.0/0"},
		{"MFA disabled", "iam", "mfa", "true", "disabled"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := dt.RecordChange(tc.name+"-resource", tc.resourceType, tc.changeType, "admin", tc.oldValue, tc.newValue)
			if !result.SecurityDegradation {
				t.Errorf("expected SecurityDegradation for %s", tc.name)
			}
			if result.DegradationReason == "" {
				t.Error("DegradationReason should not be empty")
			}
		})
	}
}

func TestCheckSecurityDegradation(t *testing.T) {
	tests := []struct {
		name         string
		resourceType string
		changeType   string
		oldValue     string
		newValue     string
		wantEmpty    bool
	}{
		{"public access enabled", "bucket", "acl", "private", "public-read", false},
		{"encryption disabled", "db", "encryption", "true", "false", false},
		{"logging disabled", "vpc", "logging", "enabled", "false", false},
		{"firewall 0.0.0.0/0", "sg", "firewall", "10.0.0.0/8", "0.0.0.0/0", false},
		{"MFA disabled", "iam", "mfa", "true", "false", false},
		{"no degradation", "bucket", "tag", "v1", "v2", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := checkSecurityDegradation(tc.resourceType, tc.changeType, tc.oldValue, tc.newValue)
			if tc.wantEmpty && result != "" {
				t.Errorf("expected empty degradation, got %q", result)
			}
			if !tc.wantEmpty && result == "" {
				t.Error("expected non-empty degradation reason")
			}
		})
	}
}

// ─── SecretScanner ────────────────────────────────────────────────────────────

func TestSecretScanner_AllPatterns(t *testing.T) {
	ss := NewSecretScanner()

	tests := []struct {
		name    string
		input   string
		wantHit bool
	}{
		{"aws_access_key", "key=AKIAIOSFODNN7EXAMPLE", true},
		{"aws_secret_key", "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", true},
		{"github_token", "token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij", true},
		{"github_oauth", "oauth: gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij", true},
		{"gitlab_token", "token: glpat-xxxxxxxxxxxxxxxxxxxx", true},
		{"slack_token", "xoxb-" + "0000000000" + "-" + "0000000000" + "-" + "ABCDEFGHIJKLMNOPQRSTUVWX", true},
		{"openai_key", "sk-abcdefghijklmnopqrstuvwxyz", true},
		{"stripe_key", "sk_test_abcdefghijklmnopqrstuvwxyz", true},
		{"private_key", "-----BEGIN RSA PRIVATE KEY-----", true},
		{"private_key_ec", "-----BEGIN EC PRIVATE KEY-----", true},
		{"private_key_plain", "-----BEGIN PRIVATE KEY-----", true},
		{"generic_secret", `password = "supersecretpassword123"`, true},
		{"connection_string", "mongodb://admin:password123@db.example.com:27017/mydb", true},
		{"jwt_token", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			findings := ss.Scan(tc.input)
			if tc.wantHit && len(findings) == 0 {
				t.Errorf("expected secret detection for %s", tc.name)
			}
		})
	}
}

func TestSecretScanner_NoFalsePositives(t *testing.T) {
	ss := NewSecretScanner()

	clean := []string{
		"Hello, this is a normal log message",
		"User logged in successfully from 10.0.0.1",
		"Processing request for /api/v1/users",
		"The quick brown fox jumps over the lazy dog",
		"Error: connection timeout after 30 seconds",
	}

	for _, text := range clean {
		findings := ss.Scan(text)
		if len(findings) > 0 {
			t.Errorf("false positive for %q: found %v", text, findings[0].Type)
		}
	}
}

// ─── CloudPolicyEngine ────────────────────────────────────────────────────────

func TestCloudPolicyEngine_PublicBucket(t *testing.T) {
	pe := NewCloudPolicyEngine()

	acls := []string{"public-read", "public-read-write"}
	for _, acl := range acls {
		ev := core.NewSecurityEvent("test", "config_scan", core.SeverityInfo, "scan")
		ev.Details["resource_type"] = "storage_bucket"
		ev.Details["resource"] = "my-bucket"
		ev.Details["acl"] = acl

		results := pe.CheckMisconfigurations(ev)
		if len(results) == 0 {
			t.Errorf("expected public bucket detection for ACL %q", acl)
			continue
		}
		if results[0].AlertType != "public_bucket" {
			t.Errorf("AlertType = %q, want %q", results[0].AlertType, "public_bucket")
		}
	}
}

func TestCloudPolicyEngine_OpenSecurityGroup(t *testing.T) {
	pe := NewCloudPolicyEngine()

	sensitivePorts := []string{"22", "3389", "3306", "5432", "27017"}
	for _, port := range sensitivePorts {
		ev := core.NewSecurityEvent("test", "config_scan", core.SeverityInfo, "scan")
		ev.Details["resource_type"] = "security_group"
		ev.Details["ingress_cidr"] = "0.0.0.0/0"
		ev.Details["port"] = port

		results := pe.CheckMisconfigurations(ev)
		if len(results) == 0 {
			t.Errorf("expected open security group detection for port %s", port)
			continue
		}
		if results[0].AlertType != "open_security_group" {
			t.Errorf("AlertType = %q, want %q", results[0].AlertType, "open_security_group")
		}
	}
}

func TestCloudPolicyEngine_PublicDatabase(t *testing.T) {
	pe := NewCloudPolicyEngine()

	ev := core.NewSecurityEvent("test", "config_scan", core.SeverityInfo, "scan")
	ev.Details["resource_type"] = "database"
	ev.Details["resource"] = "prod-db"
	ev.Details["publicly_accessible"] = "true"

	results := pe.CheckMisconfigurations(ev)
	if len(results) == 0 {
		t.Fatal("expected public database detection")
	}
	if results[0].AlertType != "public_database" {
		t.Errorf("AlertType = %q, want %q", results[0].AlertType, "public_database")
	}
}

func TestCloudPolicyEngine_OverlyPermissiveIAM(t *testing.T) {
	pe := NewCloudPolicyEngine()

	tests := []struct {
		name   string
		policy string
	}{
		{"wildcard action", `{"Action": "*", "Resource": "arn:aws:s3:::*"}`},
		{"wildcard resource", `{"Action": "s3:GetObject", "Resource": "*"}`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ev := core.NewSecurityEvent("test", "config_scan", core.SeverityInfo, "scan")
			ev.Details["resource_type"] = "iam_policy"
			ev.Details["resource"] = "admin-policy"
			ev.Details["policy"] = tc.policy

			results := pe.CheckMisconfigurations(ev)
			if len(results) == 0 {
				t.Error("expected overly permissive IAM detection")
				return
			}
			if results[0].AlertType != "permissive_iam" {
				t.Errorf("AlertType = %q, want %q", results[0].AlertType, "permissive_iam")
			}
		})
	}
}

// ─── HandleEvent Integration ──────────────────────────────────────────────────

func TestManager_HandleEvent_ConfigChange(t *testing.T) {
	cp := makeCapturingPipeline()
	m := startedModuleWithPipeline(t, cp)
	defer m.Stop()

	// Trigger security degradation
	ev := core.NewSecurityEvent("test", "config_change", core.SeverityInfo, "config changed")
	ev.Details["resource"] = "prod-bucket"
	ev.Details["resource_type"] = "storage_bucket"
	ev.Details["change_type"] = "acl_change"
	ev.Details["user"] = "admin"
	ev.Details["old_value"] = "private"
	ev.Details["new_value"] = "public-read"
	ev.SourceIP = "10.0.0.1"

	if err := m.HandleEvent(ev); err != nil {
		t.Fatalf("HandleEvent() error: %v", err)
	}

	if cp.count() == 0 {
		t.Error("expected alert for security degradation (private to public)")
	}
}

func TestManager_HandleEvent_SecretDetection(t *testing.T) {
	cp := makeCapturingPipeline()
	m := startedModuleWithPipeline(t, cp)
	defer m.Stop()

	ev := core.NewSecurityEvent("test", "secret_detected", core.SeverityInfo, "secret found")
	ev.Details["secret_type"] = "AWS Access Key"
	ev.Details["location"] = "s3://config-bucket/app.env"
	ev.Details["file"] = "app.env"
	ev.SourceIP = "10.0.0.1"

	if err := m.HandleEvent(ev); err != nil {
		t.Fatalf("HandleEvent() error: %v", err)
	}

	if cp.count() == 0 {
		t.Error("expected alert for secret detection")
	}
	if !cp.hasAlertType("secret_detected") {
		t.Error("expected secret_detected alert type")
	}
}

func TestManager_HandleEvent_PolicyCheck(t *testing.T) {
	cp := makeCapturingPipeline()
	m := startedModuleWithPipeline(t, cp)
	defer m.Stop()

	tests := []struct {
		name       string
		passCount  int
		failCount  int
		totalCount int
		wantAlert  bool
	}{
		{"low compliance", 30, 70, 100, true},   // 30% compliance → critical
		{"medium compliance", 60, 40, 100, true}, // 60% compliance → high
		{"high compliance", 80, 20, 100, true},   // 80% compliance → medium
		{"all pass", 100, 0, 100, false},          // 100% compliance → no alert
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			before := cp.count()
			ev := core.NewSecurityEvent("test", "policy_check", core.SeverityInfo, "compliance scan")
			ev.Details["framework"] = "CIS"
			ev.Details["pass_count"] = tc.passCount
			ev.Details["fail_count"] = tc.failCount
			ev.Details["total_checks"] = tc.totalCount

			m.HandleEvent(ev)

			after := cp.count()
			if tc.wantAlert && after <= before {
				t.Error("expected compliance alert")
			}
			if !tc.wantAlert && after > before {
				t.Error("expected no compliance alert")
			}
		})
	}
}

func TestManager_HandleEvent_ConfigScan(t *testing.T) {
	cp := makeCapturingPipeline()
	m := startedModuleWithPipeline(t, cp)
	defer m.Stop()

	ev := core.NewSecurityEvent("test", "config_scan", core.SeverityInfo, "posture scan")
	ev.Details["resource_type"] = "storage_bucket"
	ev.Details["resource"] = "open-bucket"
	ev.Details["acl"] = "public-read"
	ev.Details["critical_count"] = 3
	ev.Details["high_count"] = 5
	ev.Details["findings"] = "public bucket, no encryption, no versioning"
	ev.SourceIP = "10.0.0.1"

	if err := m.HandleEvent(ev); err != nil {
		t.Fatalf("HandleEvent() error: %v", err)
	}

	if cp.count() == 0 {
		t.Error("expected alerts for config scan with critical findings")
	}
}

// Compile-time interface check
var _ core.Module = (*Manager)(nil)

// ===========================================================================
// Kubernetes RBAC Tests
// ===========================================================================

func TestManager_HandleEvent_K8sRBACWildcard(t *testing.T) {
	cp := makeCapturingPipeline()
	m := startedModuleWithPipeline(t, cp)
	defer m.Stop()

	ev := core.NewSecurityEvent("test", "k8s_rbac_change", core.SeverityInfo, "rbac change")
	ev.Details["namespace"] = "default"
	ev.Details["role"] = "super-role"
	ev.Details["verbs"] = "*"
	ev.Details["resources"] = "pods,secrets"
	ev.Details["user"] = "admin@example.com"

	m.HandleEvent(ev)
	if !cp.hasAlertType("k8s_rbac_wildcard") {
		t.Error("expected k8s_rbac_wildcard alert for wildcard verbs")
	}
}

func TestManager_HandleEvent_K8sClusterAdminBinding(t *testing.T) {
	cp := makeCapturingPipeline()
	m := startedModuleWithPipeline(t, cp)
	defer m.Stop()

	ev := core.NewSecurityEvent("test", "k8s_rbac_change", core.SeverityInfo, "rbac change")
	ev.Details["namespace"] = "kube-system"
	ev.Details["role"] = "cluster-admin"
	ev.Details["verbs"] = "get,list"
	ev.Details["resources"] = "pods"
	ev.Details["user"] = "dev-user@example.com"

	m.HandleEvent(ev)
	if !cp.hasAlertType("k8s_cluster_admin_binding") {
		t.Error("expected k8s_cluster_admin_binding alert")
	}
}

func TestManager_HandleEvent_K8sSecretsAccess(t *testing.T) {
	cp := makeCapturingPipeline()
	m := startedModuleWithPipeline(t, cp)
	defer m.Stop()

	ev := core.NewSecurityEvent("test", "k8s_rbac_change", core.SeverityInfo, "rbac change")
	ev.Details["namespace"] = "production"
	ev.Details["role"] = "secret-reader"
	ev.Details["verbs"] = "get,list"
	ev.Details["resources"] = "secrets"
	ev.Details["user"] = "ci-bot"

	m.HandleEvent(ev)
	if !cp.hasAlertType("k8s_secrets_access") {
		t.Error("expected k8s_secrets_access alert")
	}
}

// ===========================================================================
// Kubernetes Admission Tests
// ===========================================================================

func TestManager_HandleEvent_K8sPrivilegedContainer(t *testing.T) {
	cp := makeCapturingPipeline()
	m := startedModuleWithPipeline(t, cp)
	defer m.Stop()

	ev := core.NewSecurityEvent("test", "k8s_admission", core.SeverityInfo, "admission")
	ev.Details["namespace"] = "default"
	ev.Details["resource"] = "nginx-pod"
	ev.Details["user"] = "developer"
	ev.Details["privileged"] = "true"

	m.HandleEvent(ev)
	if !cp.hasAlertType("k8s_privileged_container") {
		t.Error("expected k8s_privileged_container alert")
	}
}

func TestManager_HandleEvent_K8sHostNamespace(t *testing.T) {
	cp := makeCapturingPipeline()
	m := startedModuleWithPipeline(t, cp)
	defer m.Stop()

	ev := core.NewSecurityEvent("test", "k8s_admission", core.SeverityInfo, "admission")
	ev.Details["namespace"] = "monitoring"
	ev.Details["resource"] = "node-exporter"
	ev.Details["user"] = "ops-team"
	ev.Details["host_network"] = "true"
	ev.Details["host_pid"] = "true"

	m.HandleEvent(ev)
	if !cp.hasAlertType("k8s_host_namespace") {
		t.Error("expected k8s_host_namespace alert")
	}
}

// ===========================================================================
// Kubernetes Network Policy Tests
// ===========================================================================

func TestManager_HandleEvent_K8sNetPolDeleted(t *testing.T) {
	cp := makeCapturingPipeline()
	m := startedModuleWithPipeline(t, cp)
	defer m.Stop()

	ev := core.NewSecurityEvent("test", "k8s_network_policy", core.SeverityInfo, "netpol")
	ev.Details["namespace"] = "production"
	ev.Details["resource"] = "deny-all-ingress"
	ev.Details["user"] = "admin"
	ev.Details["policy_action"] = "deleted"

	m.HandleEvent(ev)
	if !cp.hasAlertType("k8s_netpol_deleted") {
		t.Error("expected k8s_netpol_deleted alert")
	}
}

// ===========================================================================
// Container Posture Tests
// ===========================================================================

func TestManager_HandleEvent_ContainerRunAsRoot(t *testing.T) {
	cp := makeCapturingPipeline()
	m := startedModuleWithPipeline(t, cp)
	defer m.Stop()

	ev := core.NewSecurityEvent("test", "container_config", core.SeverityInfo, "container config")
	ev.Details["image"] = "myapp:1.0"
	ev.Details["namespace"] = "production"
	ev.Details["run_as_root"] = "true"
	ev.Details["read_only_root_fs"] = "true"

	m.HandleEvent(ev)
	if !cp.hasAlertType("container_root_user") {
		t.Error("expected container_root_user alert")
	}
}

func TestManager_HandleEvent_ContainerWritableFS(t *testing.T) {
	cp := makeCapturingPipeline()
	m := startedModuleWithPipeline(t, cp)
	defer m.Stop()

	ev := core.NewSecurityEvent("test", "pod_security", core.SeverityInfo, "pod security")
	ev.Details["image"] = "nginx:latest"
	ev.Details["namespace"] = "default"
	ev.Details["run_as_root"] = "false"
	ev.Details["read_only_root_fs"] = "false"

	m.HandleEvent(ev)
	if !cp.hasAlertType("container_writable_fs") {
		t.Error("expected container_writable_fs alert")
	}
}

func TestManager_HandleEvent_ContainerDangerousCap(t *testing.T) {
	cp := makeCapturingPipeline()
	m := startedModuleWithPipeline(t, cp)
	defer m.Stop()

	ev := core.NewSecurityEvent("test", "container_config", core.SeverityInfo, "container config")
	ev.Details["image"] = "myapp:v2.0"
	ev.Details["namespace"] = "default"
	ev.Details["run_as_root"] = "false"
	ev.Details["read_only_root_fs"] = "true"
	ev.Details["capabilities"] = "NET_ADMIN,SYS_PTRACE"

	m.HandleEvent(ev)
	if !cp.hasAlertType("container_dangerous_cap") {
		t.Error("expected container_dangerous_cap alert")
	}
}

func TestManager_HandleEvent_ContainerUnpinnedImage(t *testing.T) {
	cp := makeCapturingPipeline()
	m := startedModuleWithPipeline(t, cp)
	defer m.Stop()

	ev := core.NewSecurityEvent("test", "container_config", core.SeverityInfo, "container config")
	ev.Details["image"] = "nginx:latest"
	ev.Details["namespace"] = "production"
	ev.Details["run_as_root"] = "false"
	ev.Details["read_only_root_fs"] = "true"

	m.HandleEvent(ev)
	if !cp.hasAlertType("container_unpinned_image") {
		t.Error("expected container_unpinned_image alert")
	}
}

// ===========================================================================
// Cloud Posture Mitigation Tests for K8s/Container Alert Types
// ===========================================================================

func TestGetCloudPostureMitigations_K8s(t *testing.T) {
	k8sTypes := []string{
		"k8s_rbac_wildcard", "k8s_cluster_admin_binding", "k8s_secrets_access",
		"k8s_privileged_container", "k8s_host_namespace", "k8s_netpol_deleted",
		"container_root_user", "container_writable_fs", "container_dangerous_cap",
		"container_unpinned_image",
	}
	for _, alertType := range k8sTypes {
		m := getCloudPostureMitigations(alertType)
		if len(m) < 2 {
			t.Errorf("expected at least 2 mitigations for %s, got %d", alertType, len(m))
		}
	}
}
