package auth

import (
	"sort"
	"strings"
)

// Role is a member's role in one workspace, as stored by the data engine.
type Role string

const (
	RoleOwner  Role = "owner"
	RoleAdmin  Role = "admin"
	RoleMember Role = "member"
	RoleViewer Role = "viewer"
)

// Scope names used by the backend (all from EngineScopes).
const (
	ScopeIdentityRead  = "identity:read"
	ScopeIdentityWrite = "identity:write"
	ScopePlanningRead  = "planning:read"
	ScopePlanningWrite = "planning:write"
)

var viewerScopes = []string{
	"identity:read", "planning:read", "collab:read", "files:read",
	"meetings:read", "memory:read", "conflicts:read",
}

var memberScopes = append(append([]string{}, viewerScopes...),
	"planning:write", "collab:write", "files:write", "meetings:write", "memory:write", "conflicts:write")

var adminScopes = append(append([]string{}, memberScopes...), "identity:write")

// roleScopes is the only source of human token scopes (docs/AUTH.md §14). Owner-only actions are
// role checks (RequireRole(owner)), not scopes, so the vocabulary matches the engine exactly.
var roleScopes = map[Role][]string{
	RoleViewer: viewerScopes,
	RoleMember: memberScopes,
	RoleAdmin:  adminScopes,
	RoleOwner:  adminScopes,
}

// NeverHumanScopes may never appear in a human token, whatever the role map says.
var NeverHumanScopes = map[string]bool{
	"admin": true, "memory:maintain": true, "memory:delete": true, "files:delete": true,
	"atoms:read": true, "atoms:run": true, "atoms:propose": true, "atoms:admin": true,
	"skills:read": true, "skills:write": true, "aggregate:read": true,
}

var roleRank = map[Role]int{RoleViewer: 1, RoleMember: 2, RoleAdmin: 3, RoleOwner: 4}

// ParseRole returns the role and whether it is one we know. Unknown roles are denied.
func ParseRole(s string) (Role, bool) {
	r := Role(s)
	_, ok := roleRank[r]
	return r, ok
}

// AtLeast reports whether r is at least min. Unknown roles are never at least anything.
func (r Role) AtLeast(min Role) bool {
	have, ok := roleRank[r]
	return ok && have >= roleRank[min]
}

// ScopesForRole returns a sorted copy of the scopes a role grants; nil for an unknown role.
func ScopesForRole(r Role) []string {
	src, ok := roleScopes[r]
	if !ok {
		return nil
	}
	out := make([]string, 0, len(src))
	for _, s := range src {
		if !NeverHumanScopes[s] && EngineScopes[s] {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// Intersect returns the scopes present in both lists, sorted. Effective scopes on a request are
// Intersect(token scopes, ScopesForRole(live role)): a demotion bites immediately, a promotion
// only on the next session or refresh.
func Intersect(a, b []string) []string {
	set := make(map[string]bool, len(b))
	for _, s := range b {
		set[s] = true
	}
	var out []string
	seen := map[string]bool{}
	for _, s := range a {
		if set[s] && !seen[s] {
			out = append(out, s)
			seen[s] = true
		}
	}
	sort.Strings(out)
	return out
}

// JoinScopes renders scopes in the engine's wire format: one space-separated string.
func JoinScopes(scopes []string) string { return strings.Join(scopes, " ") }

// SplitScopes parses the wire format.
func SplitScopes(s string) []string { return strings.Fields(s) }

// HasScope reports whether scope is in scopes.
func HasScope(scopes []string, scope string) bool {
	for _, s := range scopes {
		if s == scope {
			return true
		}
	}
	return false
}
