package auth

// EngineScopes is a checked-in copy of the scope vocabulary in
// flwn-data-engine/app/api/tokens.py (AGENT_SCOPES). Scope names in tokens must come from this
// list; scopes_test.go enforces it and scripts/check_engine_scopes.sh diffs it against the
// engine source in CI.
var EngineScopes = map[string]bool{
	"memory:read":     true,
	"memory:write":    true,
	"memory:delete":   true,
	"memory:maintain": true,
	"files:read":      true,
	"files:write":     true,
	"files:delete":    true,
	"meetings:read":   true,
	"meetings:write":  true,
	"conflicts:read":  true,
	"conflicts:write": true,
	"atoms:read":      true,
	"atoms:run":       true,
	"atoms:propose":   true,
	"skills:read":     true,
	"skills:write":    true,
	"atoms:admin":     true,
	"aggregate:read":  true,
	"identity:read":   true,
	"identity:write":  true,
	"planning:read":   true,
	"planning:write":  true,
	"collab:read":     true,
	"collab:write":    true,
	"admin":           true,
}
