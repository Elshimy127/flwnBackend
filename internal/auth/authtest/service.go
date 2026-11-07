package authtest

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Hesham127/flwnBackend/internal/auth"
)

// Clock is a settable test clock.
type Clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *Clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *Clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// Env bundles a Service with its fakes.
type Env struct {
	Svc    *auth.Service
	Store  *Store
	Engine *Engine
	Mailer *Mailer
	Clock  *Clock
	Tokens *auth.TokenManager
}

// CheapArgon keeps tests fast.
var CheapArgon = auth.Argon2Params{MemoryKiB: 1024, Time: 1, Threads: 1, KeyLen: 32, SaltLen: 16}

func NewEnv(t testing.TB) *Env {
	t.Helper()
	clock := &Clock{t: time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)}
	tokens, err := auth.NewTokenManager(auth.TokenConfig{
		Issuer: "flwn-backend", Audience: "flwn-backend",
		Keys: map[string][]byte{"k1": []byte(strings.Repeat("k", 32))}, ActiveKID: "k1", TTL: 15 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	tokens.SetClock(clock.Now)
	hasher, err := auth.NewHasher(CheapArgon)
	if err != nil {
		t.Fatal(err)
	}
	st, eng, mail := NewStore(), NewEngine(), NewMailer()
	svc := auth.NewService(auth.Config{}, st, eng, tokens, hasher, mail)
	svc.Now = clock.Now
	return &Env{Svc: svc, Store: st, Engine: eng, Mailer: mail, Clock: clock, Tokens: tokens}
}
