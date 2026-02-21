package api

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/1sec-project/1sec/internal/core"
)

// handleEnforceStatus returns the enforcement engine status and stats.
func (s *Server) handleEnforceStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}

	re := s.engine.ResponseEngine
	if re == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"enabled": false,
			"dry_run": false,
			"stats":   map[string]interface{}{"total_policies": 0, "total_records": 0},
			"message": "enforcement engine not configured — add 'enforcement' section to config",
		})
		return
	}

	cfg := s.engine.Config.Enforcement
	var allowList []string
	if cfg != nil {
		allowList = cfg.GlobalAllowList
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"enabled":           cfg != nil && cfg.Enabled,
		"dry_run":           cfg != nil && cfg.DryRun,
		"global_allow_list": allowList,
		"stats":             re.Stats(),
	})
}

// handleEnforcePolicies returns all configured response policies.
func (s *Server) handleEnforcePolicies(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}

	re := s.engine.ResponseEngine
	if re == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"policies": map[string]interface{}{}})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"policies": re.GetPolicies()})
}

// handleEnforcePolicyAction handles enable/disable for a specific module's policy.
// URL pattern: /api/v1/enforce/policies/{module}/{action}
func (s *Server) handleEnforcePolicyAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}

	re := s.engine.ResponseEngine
	if re == nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "enforcement engine not configured"})
		return
	}

	// Parse: /api/v1/enforce/policies/{module}/{action}
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/enforce/policies/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) != 2 {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "expected /api/v1/enforce/policies/{module}/{enable|disable}"})
		return
	}

	module := parts[0]
	action := parts[1]

	switch action {
	case "enable":
		if re.SetPolicyEnabled(module, true) {
			s.logger.Warn().Str("module", module).Bool("enabled", true).Str("ip", r.RemoteAddr).Msg("enforcement policy toggled via API")
			writeJSON(w, http.StatusOK, map[string]interface{}{"module": module, "enabled": true})
		} else {
			writeJSON(w, http.StatusNotFound, map[string]interface{}{"error": "no policy found for module: " + module})
		}
	case "disable":
		if re.SetPolicyEnabled(module, false) {
			s.logger.Warn().Str("module", module).Bool("enabled", false).Str("ip", r.RemoteAddr).Msg("enforcement policy toggled via API")
			writeJSON(w, http.StatusOK, map[string]interface{}{"module": module, "enabled": false})
		} else {
			writeJSON(w, http.StatusNotFound, map[string]interface{}{"error": "no policy found for module: " + module})
		}
	default:
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "unknown action: " + action + " (use enable or disable)"})
	}
}

// handleEnforceHistory returns response action execution history.
func (s *Server) handleEnforceHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}

	re := s.engine.ResponseEngine
	if re == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"records": []interface{}{}})
		return
	}

	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	moduleFilter := r.URL.Query().Get("module")
	records := re.GetRecords(limit, moduleFilter)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"records": records,
		"count":   len(records),
	})
}

// handleEnforceDryRun toggles global dry-run mode.
// URL pattern: /api/v1/enforce/dry-run/{on|off}
func (s *Server) handleEnforceDryRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}

	mode := strings.TrimPrefix(r.URL.Path, "/api/v1/enforce/dry-run/")
	cfg := s.engine.Config.Enforcement
	if cfg == nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "enforcement not configured"})
		return
	}

	switch mode {
	case "on":
		previous := cfg.DryRun
		cfg.DryRun = true
		s.logger.Warn().
			Bool("previous", previous).
			Bool("new", true).
			Str("ip", r.RemoteAddr).
			Msg("enforcement dry-run toggled via API")
		writeJSON(w, http.StatusOK, map[string]interface{}{"dry_run": true, "previous": previous, "message": "global dry-run enabled"})
	case "off":
		previous := cfg.DryRun
		cfg.DryRun = false
		s.logger.Warn().
			Bool("previous", previous).
			Bool("new", false).
			Str("ip", r.RemoteAddr).
			Msg("enforcement dry-run toggled via API — enforcement is LIVE")
		writeJSON(w, http.StatusOK, map[string]interface{}{"dry_run": false, "previous": previous, "message": "global dry-run disabled — enforcement is LIVE"})
	default:
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "use /dry-run/on or /dry-run/off"})
	}
}

// handleEnforceTest simulates an alert for a module and returns what actions would fire.
// URL pattern: /api/v1/enforce/test/{module}?severity=HIGH
func (s *Server) handleEnforceTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}

	re := s.engine.ResponseEngine
	if re == nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "enforcement engine not configured"})
		return
	}

	module := strings.TrimPrefix(r.URL.Path, "/api/v1/enforce/test/")
	severity := core.ParseSeverity(r.URL.Query().Get("severity"))

	policies := re.GetPolicies()
	policy, ok := policies[module]
	if !ok {
		policy, ok = policies["*"]
	}
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]interface{}{
			"error":   "no policy found for module: " + module,
			"actions": []interface{}{},
		})
		return
	}

	matchingActions := make([]map[string]interface{}, 0)
	for _, rule := range policy.Actions {
		if severity >= rule.MinSeverity {
			matchingActions = append(matchingActions, map[string]interface{}{
				"action":       string(rule.Action),
				"min_severity": rule.MinSeverity.String(),
				"params":       rule.Params,
				"dry_run":      rule.DryRun,
				"description":  rule.Description,
			})
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"module":          module,
		"test_severity":   severity.String(),
		"policy_enabled":  policy.Enabled,
		"policy_dry_run":  policy.DryRun,
		"actions":         matchingActions,
		"total_matching":  len(matchingActions),
	})
}
