package auth

import (
	"encoding/json"
	"errors"

	"github.com/golang-jwt/jwt/v5"
)

// Token types (AUTH_DESIGN claim `typ`). Only human tokens are issued or accepted for now;
// agent, run and service tokens are parsed and rejected until a later phase enables them.
const (
	TypeHuman   = "human"
	TypeAgent   = "agent"
	TypeRun     = "run"
	TypeService = "service"
)

// ScopeString is the `scope` claim: one space-separated string, the engine's wire format.
// Decoding rejects arrays and any other JSON type.
type ScopeString string

func (s *ScopeString) UnmarshalJSON(b []byte) error {
	var str string
	if err := json.Unmarshal(b, &str); err != nil {
		return errors.New("scope must be a space-separated string")
	}
	*s = ScopeString(str)
	return nil
}

// Claims is the full AUTH_DESIGN claim set. Header: kid.
//
//	iss   issuer, always the backend
//	aud   services allowed to accept the token
//	sub   acting principal: human member id, agent member id, or service name
//	ws    the only workspace the token is valid for
//	typ   human | agent | run | service
//	mem   member the writes are attributed to
//	obo   human member id when an agent acts for a human
//	act   service that made the call, for engine-to-engine hops
//	agent agent member id or atom id
//	run   run id
//	scope allowed actions, space-separated
//	iat, exp, nbf, jti
type Claims struct {
	WorkspaceID string      `json:"ws"`
	Type        string      `json:"typ"`
	MemberID    string      `json:"mem,omitempty"`
	OnBehalfOf  string      `json:"obo,omitempty"`
	Actor       string      `json:"act,omitempty"`
	Agent       string      `json:"agent,omitempty"`
	Run         string      `json:"run,omitempty"`
	Scope       ScopeString `json:"scope"`

	jwt.RegisteredClaims
}

// Scopes returns the scope claim as a list.
func (c *Claims) Scopes() []string { return SplitScopes(string(c.Scope)) }
