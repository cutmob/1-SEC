package core

import (
	"testing"
)

// ─── GetPresetPolicies ──────────────────────────────────────────────────────

func TestGetPresetPolicies_ValidPresets(t *testing.T) {
	for _, name := range []string{"lax", "balanced", "strict"} {
		policies := GetPresetPolicies(name)
		if policies == nil {
			t.Errorf("GetPresetPolicies(%q) returned nil", name)
			continue
		}
		if len(policies) == 0 {
			t.Errorf("GetPresetPolicies(%q) returned empty map", name)
		}
	}
}

func TestGetPresetPolicies_UnknownPreset(t *testing.T) {
	if policies := GetPresetPolicies("nonexistent"); policies != nil {
		t.Error("expected nil for unknown preset")
	}
}

func TestGetPresetPolicies_EmptyString(t *testing.T) {
	if policies := GetPresetPolicies(""); policies != nil {
		t.Error("expected nil for empty preset name")
	}
}

func TestValidPresets(t *testing.T) {
	presets := ValidPresets()
	if len(presets) != 3 {
		t.Errorf("expected 3 valid presets, got %d", len(presets))
	}
	expected := map[string]bool{"lax": true, "balanced": true, "strict": true}
	for _, p := range presets {
		if !expected[p] {
			t.Errorf("unexpected preset: %q", p)
		}
	}
}

// ─── All 16 modules covered ─────────────────────────────────────────────────

var allModules = []string{
	"network_guardian", "api_fortress", "iot_shield",
	"injection_shield", "supply_chain", "ransomware",
	"auth_fortress", "deepfake_shield", "identity_monitor",
	"llm_firewall", "ai_containment", "data_poisoning",
	"quantum_crypto", "runtime_watcher", "cloud_posture",
	"ai_analysis_engine",
}

func TestPresets_CoverAll16Modules(t *testing.T) {
	for _, preset := range []string{"lax", "balanced", "strict"} {
		policies := GetPresetPolicies(preset)
		for _, mod := range allModules {
			if _, ok := policies[mod]; !ok {
				t.Errorf("preset %q missing module %q", preset, mod)
			}
		}
		// Wildcard should also be present
		if _, ok := policies["*"]; !ok {
			t.Errorf("preset %q missing wildcard (*) policy", preset)
		}
	}
}

// ─── Preset policy structure validation ─────────────────────────────────────

func TestPresets_AllPoliciesHaveActions(t *testing.T) {
	for _, preset := range []string{"lax", "balanced", "strict"} {
		policies := GetPresetPolicies(preset)
		for module, policy := range policies {
			if len(policy.Actions) == 0 {
				t.Errorf("preset %q, module %q has no actions", preset, module)
			}
		}
	}
}

func TestPresets_AllPoliciesEnabled(t *testing.T) {
	for _, preset := range []string{"lax", "balanced", "strict"} {
		policies := GetPresetPolicies(preset)
		for module, policy := range policies {
			if !policy.Enabled {
				t.Errorf("preset %q, module %q is not enabled", preset, module)
			}
		}
	}
}

func TestPresets_ValidActionTypes(t *testing.T) {
	validActions := map[string]bool{
		"block_ip": true, "kill_process": true, "quarantine_file": true,
		"drop_connection": true, "disable_user": true, "webhook": true,
		"command": true, "log_only": true,
	}

	for _, preset := range []string{"lax", "balanced", "strict"} {
		policies := GetPresetPolicies(preset)
		for module, policy := range policies {
			for _, action := range policy.Actions {
				if !validActions[action.Action] {
					t.Errorf("preset %q, module %q has invalid action type: %q", preset, module, action.Action)
				}
			}
		}
	}
}

func TestPresets_ValidSeverityLevels(t *testing.T) {
	validSeverities := map[string]bool{
		"LOW": true, "MEDIUM": true, "HIGH": true, "CRITICAL": true,
	}

	for _, preset := range []string{"lax", "balanced", "strict"} {
		policies := GetPresetPolicies(preset)
		for module, policy := range policies {
			if !validSeverities[policy.MinSeverity] {
				t.Errorf("preset %q, module %q has invalid min_severity: %q", preset, module, policy.MinSeverity)
			}
			for _, action := range policy.Actions {
				if !validSeverities[action.MinSeverity] {
					t.Errorf("preset %q, module %q, action %q has invalid min_severity: %q",
						preset, module, action.Action, action.MinSeverity)
				}
			}
		}
	}
}

func TestPresets_PositiveCooldownsAndRateLimits(t *testing.T) {
	for _, preset := range []string{"lax", "balanced", "strict"} {
		policies := GetPresetPolicies(preset)
		for module, policy := range policies {
			if policy.CooldownSeconds < 0 {
				t.Errorf("preset %q, module %q has negative cooldown: %d", preset, module, policy.CooldownSeconds)
			}
			if policy.MaxActionsPerMin < 0 {
				t.Errorf("preset %q, module %q has negative rate limit: %d", preset, module, policy.MaxActionsPerMin)
			}
		}
	}
}

// ─── Preset philosophy validation ───────────────────────────────────────────

func TestLaxPreset_NoBlockingActions(t *testing.T) {
	policies := GetPresetPolicies("lax")
	blockingActions := map[string]bool{
		"block_ip": true, "kill_process": true, "quarantine_file": true,
		"drop_connection": true, "disable_user": true,
	}

	for module, policy := range policies {
		for _, action := range policy.Actions {
			if blockingActions[action.Action] {
				t.Errorf("lax preset should not have blocking action %q in module %q", action.Action, module)
			}
		}
	}
}

func TestStrictPreset_LowerSeverityThresholds(t *testing.T) {
	strict := GetPresetPolicies("strict")
	balanced := GetPresetPolicies("balanced")

	// Strict should generally have equal or lower severity thresholds than balanced
	for module := range strict {
		if module == "*" || module == "ai_analysis_engine" {
			continue // these may differ
		}
		sp := strict[module]
		bp, ok := balanced[module]
		if !ok {
			continue
		}
		sSev := ParseSeverity(sp.MinSeverity)
		bSev := ParseSeverity(bp.MinSeverity)
		if sSev > bSev {
			t.Errorf("strict preset module %q has higher min_severity (%s) than balanced (%s)",
				module, sp.MinSeverity, bp.MinSeverity)
		}
	}
}

func TestStrictPreset_ShorterCooldowns(t *testing.T) {
	strict := GetPresetPolicies("strict")
	balanced := GetPresetPolicies("balanced")

	for module := range strict {
		if module == "*" || module == "ai_analysis_engine" {
			continue
		}
		sp := strict[module]
		bp, ok := balanced[module]
		if !ok {
			continue
		}
		if sp.CooldownSeconds > bp.CooldownSeconds {
			t.Errorf("strict preset module %q has longer cooldown (%d) than balanced (%d)",
				module, sp.CooldownSeconds, bp.CooldownSeconds)
		}
	}
}

// ─── Preset constants ───────────────────────────────────────────────────────

func TestPresetConstants(t *testing.T) {
	if PresetLax != "lax" {
		t.Errorf("PresetLax = %q, want lax", PresetLax)
	}
	if PresetBalanced != "balanced" {
		t.Errorf("PresetBalanced = %q, want balanced", PresetBalanced)
	}
	if PresetStrict != "strict" {
		t.Errorf("PresetStrict = %q, want strict", PresetStrict)
	}
}
