package auth

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// MaxAccessTTL caps access-token lifetime, both when issuing and when verifying.
const MaxAccessTTL = 15 * time.Minute

const clockLeeway = 30 * time.Second

// ErrInvalidToken covers every reason a JWT is rejected. The cause is wrapped for logs only.
var ErrInvalidToken = errors.New("invalid access token")

// TokenConfig configures signing and verification.
type TokenConfig struct {
	Issuer    string            // always the backend, e.g. "flwn-backend"
	Audience  string            // the audience this service accepts and issues, e.g. "flwn-backend"
	Keys      map[string][]byte // kid -> HS256 secret (>= 32 bytes); old keys stay for rotation
	ActiveKID string            // kid used to sign
	TTL       time.Duration     // access-token lifetime, <= MaxAccessTTL
}

// TokenManager signs and verifies human access tokens.
type TokenManager struct {
	cfg TokenConfig
	now func() time.Time
}

func NewTokenManager(cfg TokenConfig) (*TokenManager, error) {
	if cfg.Issuer == "" || cfg.Audience == "" {
		return nil, errors.New("token issuer and audience are required")
	}
	if cfg.TTL <= 0 || cfg.TTL > MaxAccessTTL {
		return nil, fmt.Errorf("access token TTL must be in (0, %s]", MaxAccessTTL)
	}
	if _, ok := cfg.Keys[cfg.ActiveKID]; !ok || cfg.ActiveKID == "" {
		return nil, errors.New("active signing key id has no key")
	}
	for kid, k := range cfg.Keys {
		if len(k) < 32 {
			return nil, fmt.Errorf("signing key %q must be at least 32 bytes", kid)
		}
	}
	return &TokenManager{cfg: cfg, now: time.Now}, nil
}

// SetClock replaces the clock (tests).
func (m *TokenManager) SetClock(now func() time.Time) { m.now = now }

// IssuedToken is a signed access token plus what the server records about it.
type IssuedToken struct {
	Token     string
	JTI       string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// IssueHuman signs a human access token: sub = mem = member id.
func (m *TokenManager) IssueHuman(memberID, workspaceID string, scopes []string) (IssuedToken, error) {
	if memberID == "" || workspaceID == "" {
		return IssuedToken{}, errors.New("member and workspace are required")
	}
	for _, s := range scopes {
		if !EngineScopes[s] || NeverHumanScopes[s] {
			return IssuedToken{}, fmt.Errorf("scope %q may not be issued to a human", s)
		}
	}
	jti, err := randomID()
	if err != nil {
		return IssuedToken{}, err
	}
	now := m.now().UTC().Truncate(time.Second)
	exp := now.Add(m.cfg.TTL)
	claims := Claims{
		WorkspaceID: workspaceID,
		Type:        TypeHuman,
		MemberID:    memberID,
		Scope:       ScopeString(JoinScopes(scopes)),
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    m.cfg.Issuer,
			Subject:   memberID,
			Audience:  jwt.ClaimStrings{m.cfg.Audience},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(exp),
			ID:        jti,
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tok.Header["kid"] = m.cfg.ActiveKID
	signed, err := tok.SignedString(m.cfg.Keys[m.cfg.ActiveKID])
	if err != nil {
		return IssuedToken{}, fmt.Errorf("sign access token: %w", err)
	}
	return IssuedToken{Token: signed, JTI: jti, IssuedAt: now, ExpiresAt: exp}, nil
}

// Verify checks signature, algorithm, kid, iss, aud, time claims and the per-typ claim rules.
// It does not check revocation or membership; Service.Authenticate does that.
func (m *TokenManager) Verify(raw string) (*Claims, error) {
	if raw == "" || strings.Count(raw, ".") != 2 {
		return nil, ErrInvalidToken
	}
	claims := &Claims{}
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithIssuer(m.cfg.Issuer),
		jwt.WithAudience(m.cfg.Audience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(clockLeeway),
		jwt.WithTimeFunc(m.now),
		jwt.WithStrictDecoding(),
	)
	_, err := parser.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodHS256 {
			return nil, errors.New("unexpected algorithm")
		}
		kid, ok := t.Header["kid"].(string)
		if !ok {
			return nil, errors.New("missing kid")
		}
		key, ok := m.cfg.Keys[kid]
		if !ok {
			return nil, errors.New("unknown kid")
		}
		return key, nil
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	if err := m.checkClaims(claims); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	return claims, nil
}

func (m *TokenManager) checkClaims(c *Claims) error {
	if c.IssuedAt == nil || c.NotBefore == nil || c.ExpiresAt == nil {
		return errors.New("iat, nbf and exp are required")
	}
	now := m.now()
	if c.NotBefore.After(now.Add(clockLeeway)) {
		return errors.New("token not valid yet")
	}
	if c.ExpiresAt.Sub(c.IssuedAt.Time) > MaxAccessTTL {
		return errors.New("token lifetime too long")
	}
	if c.ID == "" || c.Subject == "" || c.WorkspaceID == "" {
		return errors.New("jti, sub and ws are required")
	}
	switch c.Type {
	case TypeHuman:
		if c.MemberID == "" || c.MemberID != c.Subject {
			return errors.New("human token needs mem equal to sub")
		}
		if c.OnBehalfOf != "" || c.Actor != "" || c.Agent != "" || c.Run != "" {
			return errors.New("human token may not carry obo, act, agent or run")
		}
		for _, s := range c.Scopes() {
			if !EngineScopes[s] || NeverHumanScopes[s] {
				return fmt.Errorf("scope %q not allowed in a human token", s)
			}
		}
	case TypeAgent, TypeRun, TypeService:
		return fmt.Errorf("%s tokens are not enabled", c.Type)
	default:
		return errors.New("unknown token type")
	}
	return nil
}
