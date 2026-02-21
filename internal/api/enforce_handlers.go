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

// handleEnforceApprove approves a pending approval gate action.
// URL pattern: POST /api/v1/enforce/approve/{id}
func (s *Server) handleEnforceApprove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}

	re := s.engine.ResponseEngine
	if re == nil || re.ApprovalGate == nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "approval gate not configured"})
		return
	}

	id := strings.TrimPrefix(r.URL.Path, "/api/v1/enforce/approve/")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "approval ID required"})
		return
	}

	decidedBy := "api:" + r.RemoteAddr
	pa, err := re.ApprovalGate.Approve(id, decidedBy)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]interface{}{"error": err.Error()})
		return
	}

	s.logger.Warn().
		Str("approval_id", id).
		Str("action", string(pa.Action)).
		Str("target", pa.Target).
		Str("decided_by", decidedBy).
		Msg("action approved via API")

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"id":         pa.ID,
		"action":     string(pa.Action),
		"target":     pa.Target,
		"status":     pa.Status,
		"decided_by": pa.DecidedBy,
	})
}

// handleEnforceReject rejects a pending approval gate action.
// URL pattern: POST /api/v1/enforce/reject/{id}
func (s *Server) handleEnforceReject(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}

	re := s.engine.ResponseEngine
	if re == nil || re.ApprovalGate == nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "approval gate not configured"})
		return
	}

	id := strings.TrimPrefix(r.URL.Path, "/api/v1/enforce/reject/")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "approval ID required"})
		return
	}

	decidedBy := "api:" + r.RemoteAddr
	pa, err := re.ApprovalGate.Reject(id, decidedBy)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]interface{}{"error": err.Error()})
		return
	}

	s.logger.Warn().
		Str("approval_id", id).
		Str("action", string(pa.Action)).
		Str("decided_by", decidedBy).
		Msg("action rejected via API")

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"id":         pa.ID,
		"action":     string(pa.Action),
		"target":     pa.Target,
		"status":     pa.Status,
		"decided_by": pa.DecidedBy,
	})
}

// handleEnforceRollback rolls back a reversible enforcement action.
// URL pattern: POST /api/v1/enforce/rollback/{id}
func (s *Server) handleEnforceRollback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}

	re := s.engine.ResponseEngine
	if re == nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "enforcement engine not configured"})
		return
	}

	id := strings.TrimPrefix(r.URL.Path, "/api/v1/enforce/rollback/")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "record ID required"})
		return
	}

	record := re.FindRecord(id)
	if record == nil {
		writeJSON(w, http.StatusNotFound, map[string]interface{}{"error": "enforcement record not found"})
		return
	}

	if record.Status != core.ActionStatusSuccess {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":  "can only roll back successful actions",
			"status": string(record.Status),
		})
		return
	}

	switch record.Action {
	case core.ActionBlockIP:
		core.ExportedUnblockIP(record.Target, s.logger)
		record.Status = core.ActionStatusSkipped
		s.logger.Warn().
			Str("record_id", id).
			Str("action", string(record.Action)).
			Str("target", record.Target).
			Str("ip", r.RemoteAddr).
			Msg("enforcement action rolled back via API")
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"id":       id,
			"action":   string(record.Action),
			"target":   record.Target,
			"rollback": "completed",
		})
	default:
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":  "rollback not supported for this action type",
			"action": string(record.Action),
		})
	}
}
