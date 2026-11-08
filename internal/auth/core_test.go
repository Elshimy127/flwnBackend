package auth

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var testArgon = Argon2Params{MemoryKiB: 1024, Time: 1, Threads: 1, KeyLen: 32, SaltLen: 16}

func TestCanonicalEmail(t *testing.T) {
	ok := map[string]string{
		"  Alice@Example.COM ":      "alice@example.com",
		"a.b+tag@gmail.com":         "a.b+tag@gmail.com", // no dot/+ stripping
		"user@Bücher.example":       "user@xn--bcher-kva.example",
		"ÉLODIE@example.com":        "élodie@example.com",
		"Élodie@example.com":       "élodie@example.com", // NFC
		`"weird@local"@example.com`: `"weird@local"@example.com`,
	}
	for in, want := range ok {
		got, err := CanonicalEmail(in)
		if err != nil || got != want {
			t.Errorf("CanonicalEmail(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	bad := []string{"", "no-at", "@example.com", "a@", "a@localhost", "a b@example.com",
		"a@exa mple.com", "a\x00@example.com", strings.Repeat("a", 65) + "@example.com",
		"a@" + strings.Repeat("b", 250) + ".com", "a@.example.com", "a@example.com."}
	for _, in := range bad {
		if got, err := CanonicalEmail(in); err == nil {
			t.Errorf("CanonicalEmail(%q) = %q; want error", in, got)
		}
	}
}

func TestPasswordHashVerify(t *testing.T) {
	h, err := NewHasher(testArgon)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := h.Hash("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(enc, "$argon2id$v=19$m=1024,t=1,p=1$") {
		t.Fatalf("unexpected PHC string %q", enc)
	}
	if ok, rehash, err := h.Verify("correct horse battery", enc); !ok || rehash || err != nil {
		t.Fatalf("verify good password: ok=%v rehash=%v err=%v", ok, rehash, err)
	}
	if ok, _, _ := h.Verify("wrong password!!", enc); ok {
		t.Fatal("wrong password accepted")
	}
	stronger, _ := NewHasher(Argon2Params{MemoryKiB: 2048, Time: 1, Threads: 1, KeyLen: 32, SaltLen: 16})
	if ok, rehash, _ := stronger.Verify("correct horse battery", enc); !ok || !rehash {
		t.Fatal("weaker hash should verify and ask for rehash")
	}
	enc2, _ := h.Hash("correct horse battery")
	if enc == enc2 {
		t.Fatal("salts must differ")
	}
	for _, bad := range []string{"", "$2a$10$abc", "$argon2id$v=19$m=0,t=1,p=1$AAAA$AAAA"} {
		if _, _, err := h.Verify("x", bad); err == nil {
			t.Errorf("malformed hash %q accepted", bad)
		}
	}
	if ValidatePassword("short") == nil || ValidatePassword(strings.Repeat("x", 300)) == nil {
		t.Fatal("password length rules not enforced")
	}
}

func BenchmarkArgon2Default(b *testing.B) {
	h := &Hasher{Params: DefaultArgon2}
	for i := 0; i < b.N; i++ {
		_, _ = h.Hash("benchmark-password")
	}
}

func TestRoleScopes(t *testing.T) {
	for _, r := range []Role{RoleViewer, RoleMember, RoleAdmin, RoleOwner} {
		scopes := ScopesForRole(r)
		if len(scopes) == 0 {
			t.Fatalf("role %s has no scopes", r)
		}
		for _, s := range scopes {
			if !EngineScopes[s] {
				t.Errorf("role %s maps to %q, not an engine scope", r, s)
			}
			if NeverHumanScopes[s] {
				t.Errorf("role %s maps to forbidden human scope %q", r, s)
			}
		}
	}
	if HasScope(ScopesForRole(RoleViewer), ScopePlanningWrite) {
		t.Error("viewer must not write")
	}
	if !HasScope(ScopesForRole(RoleMember), ScopePlanningWrite) || HasScope(ScopesForRole(RoleMember), ScopeIdentityWrite) {
		t.Error("member: planning:write yes, identity:write no")
	}
	if !HasScope(ScopesForRole(RoleAdmin), ScopeIdentityWrite) {
		t.Error("admin needs identity:write")
	}
	if ScopesForRole(Role("superuser")) != nil {
		t.Error("unknown role must get no scopes")
	}
	if _, ok := ParseRole("superuser"); ok {
		t.Error("unknown role parsed")
	}
	if Role("superuser").AtLeast(RoleViewer) {
		t.Error("unknown role must not rank")
	}
	got := Intersect(ScopesForRole(RoleAdmin), ScopesForRole(RoleViewer))
	if JoinScopes(got) != JoinScopes(ScopesForRole(RoleViewer)) {
		t.Errorf("demotion intersect = %v", got)
	}
}

func newTestTokens(t *testing.T, now time.Time) *TokenManager {
	t.Helper()
	m, err := NewTokenManager(TokenConfig{
		Issuer: "flwn-backend", Audience: "flwn-backend",
		Keys:      map[string][]byte{"k1": []byte(strings.Repeat("s", 32)), "k0": []byte(strings.Repeat("o", 32))},
		ActiveKID: "k1", TTL: 15 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	m.now = func() time.Time { return now }
	return m
}

// forge signs arbitrary claims with key k1 (or the given method/kid).
func forge(t *testing.T, claims jwt.MapClaims, kid string, key []byte) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	if kid != "" {
		tok.Header["kid"] = kid
	}
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func baseClaims(now time.Time) jwt.MapClaims {
	return jwt.MapClaims{
		"iss": "flwn-backend", "aud": []string{"flwn-backend"}, "sub": "m1", "mem": "m1",
		"ws": "w1", "typ": "human", "scope": "planning:read", "jti": "j1",
		"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(10 * time.Minute).Unix(),
	}
}

func TestTokenIssueVerify(t *testing.T) {
	now := time.Now()
	m := newTestTokens(t, now)
	tok, err := m.IssueHuman("m1", "w1", ScopesForRole(RoleMember))
	if err != nil {
		t.Fatal(err)
	}
	c, err := m.Verify(tok.Token)
	if err != nil {
		t.Fatal(err)
	}
	if c.Subject != "m1" || c.MemberID != "m1" || c.WorkspaceID != "w1" || c.Type != TypeHuman || c.ID != tok.JTI {
		t.Fatalf("claims = %+v", c)
	}
	// Wire format: scope is a string.
	payload, _ := base64.RawURLEncoding.DecodeString(strings.Split(tok.Token, ".")[1])
	var raw map[string]any
	_ = json.Unmarshal(payload, &raw)
	if _, ok := raw["scope"].(string); !ok {
		t.Fatalf("scope not a string: %T", raw["scope"])
	}
	if _, err := m.IssueHuman("m1", "w1", []string{"admin"}); err == nil {
		t.Fatal("issued admin scope to a human")
	}
}

func TestTokenVerifyRejects(t *testing.T) {
	now := time.Now()
	m := newTestTokens(t, now)
	key := []byte(strings.Repeat("s", 32))
	mut := func(f func(jwt.MapClaims)) string {
		c := baseClaims(now)
		f(c)
		return forge(t, c, "k1", key)
	}
	cases := map[string]string{
		"good-control":  "",
		"wrong iss":     mut(func(c jwt.MapClaims) { c["iss"] = "evil" }),
		"wrong aud":     mut(func(c jwt.MapClaims) { c["aud"] = []string{"data-engine"} }),
		"expired":       mut(func(c jwt.MapClaims) { c["exp"] = now.Add(-time.Minute).Unix() }),
		"future iat":    mut(func(c jwt.MapClaims) { c["iat"] = now.Add(5 * time.Minute).Unix() }),
		"future nbf":    mut(func(c jwt.MapClaims) { c["nbf"] = now.Add(5 * time.Minute).Unix() }),
		"too long":      mut(func(c jwt.MapClaims) { c["exp"] = now.Add(time.Hour).Unix() }),
		"no exp":        mut(func(c jwt.MapClaims) { delete(c, "exp") }),
		"no iat":        mut(func(c jwt.MapClaims) { delete(c, "iat") }),
		"no nbf":        mut(func(c jwt.MapClaims) { delete(c, "nbf") }),
		"no jti":        mut(func(c jwt.MapClaims) { delete(c, "jti") }),
		"no ws":         mut(func(c jwt.MapClaims) { delete(c, "ws") }),
		"mem != sub":    mut(func(c jwt.MapClaims) { c["mem"] = "m2" }),
		"scope array":   mut(func(c jwt.MapClaims) { c["scope"] = []string{"planning:read"} }),
		"admin scope":   mut(func(c jwt.MapClaims) { c["scope"] = "planning:read admin" }),
		"unknown scope": mut(func(c jwt.MapClaims) { c["scope"] = "profile:read" }),
		"obo on human":  mut(func(c jwt.MapClaims) { c["obo"] = "m9" }),
		"run on human":  mut(func(c jwt.MapClaims) { c["run"] = "r1" }),
		"agent typ":     mut(func(c jwt.MapClaims) { c["typ"] = "agent" }),
		"unknown typ":   mut(func(c jwt.MapClaims) { c["typ"] = "root" }),
		"sub number":    mut(func(c jwt.MapClaims) { c["sub"] = 5 }),
		"unknown kid":   forge(t, baseClaims(now), "k9", key),
		"missing kid":   forge(t, baseClaims(now), "", key),
		"wrong key":     forge(t, baseClaims(now), "k1", []byte(strings.Repeat("x", 32))),
		"garbage":       "not.a.jwt",
	}
	// alg=none
	none := jwt.NewWithClaims(jwt.SigningMethodNone, baseClaims(now))
	none.Header["kid"] = "k1"
	cases["alg none"], _ = none.SignedString(jwt.UnsafeAllowNoneSignatureType)

	for name, tok := range cases {
		if name == "good-control" {
			if _, err := m.Verify(forge(t, baseClaims(now), "k1", key)); err != nil {
				t.Fatalf("control token rejected: %v", err)
			}
			continue
		}
		if _, err := m.Verify(tok); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Old key still verifies (rotation).
	if _, err := m.Verify(forge(t, baseClaims(now), "k0", []byte(strings.Repeat("o", 32)))); err != nil {
		t.Errorf("rotated key rejected: %v", err)
	}
}
