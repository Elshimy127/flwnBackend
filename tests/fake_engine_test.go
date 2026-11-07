package tests

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/Hesham127/flwnBackend/internal/auth"
	"github.com/Hesham127/flwnBackend/internal/auth/authtest"
	"github.com/Hesham127/flwnBackend/internal/platform/dataengine"
	"github.com/Hesham127/flwnBackend/internal/platform/secure"
	"github.com/Hesham127/flwnBackend/internal/server"
)

const (
	testAPIKey = "test-service-key"
	testOrigin = "https://app.flwn.test"
	testPW     = "correct horse battery"
)

// recorded is what the fake engine saw.
type recorded struct {
	Method string
	Path   string
	Query  string
	Header http.Header
	Body   string
}

// fakeEngine answers every data request with one canned response and records the last request.
// Identity lookups made by the auth service go to an in-memory engine (env.Engine) instead.
type fakeEngine struct {
	*httptest.Server
	mu     sync.Mutex
	last   recorded
	status int
	body   string
	env    *authtest.Env
	r      *gin.Engine
	reg    *secure.Registry
}

func newFakeEngine(t *testing.T) *fakeEngine {
	t.Helper()
	f := &fakeEngine{status: http.StatusOK, body: `{}`}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.last = recorded{r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Clone(), string(body)}
		status, resp := f.status, f.body
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, resp)
	}))
	t.Cleanup(f.Close)
	f.env = authtest.NewEnv(t)
	gin.SetMode(gin.TestMode)
	f.r, f.reg = server.NewRouter(server.Deps{
		Engine: f.client(t), System: f.env.Engine, Auth: f.env.Svc,
		Origins: []string{testOrigin}, CookieSecure: true, CSRFKey: []byte(strings.Repeat("c", 32)),
	})
	return f
}

func (f *fakeEngine) respond(status int, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status, f.body = status, body
}

func (f *fakeEngine) lastRequest() recorded {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.last
}

func (f *fakeEngine) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.last = recorded{}
}

func (f *fakeEngine) client(t *testing.T) *dataengine.Client {
	t.Helper()
	c, err := dataengine.New(f.URL, testAPIKey)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (f *fakeEngine) router(t *testing.T) *gin.Engine { return f.r }

// caller is a signed-in member of one workspace.
type caller struct {
	user, ws, member uuid.UUID
	email            string
	pair             auth.TokenPair
}

func (c caller) bearer() map[string]string {
	return map[string]string{"Authorization": "Bearer " + c.pair.AccessToken}
}

// signIn registers + verifies an account, adds it to ws with role, logs in and opens a session.
func (f *fakeEngine) signIn(t *testing.T, ws uuid.UUID, role string) caller {
	t.Helper()
	ctx := t.Context()
	email := "u-" + uuid.NewString()[:8] + "@example.com"
	if err := f.env.Svc.Register(ctx, email, testPW, "Test"); err != nil {
		t.Fatal(err)
	}
	if err := f.env.Svc.VerifyEmail(ctx, f.env.Mailer.Token("verify", email)); err != nil {
		t.Fatal(err)
	}
	user, _, _ := f.env.Engine.FindUserByEmail(ctx, email)
	member := f.env.Engine.AddMember(ws, user, role, auth.MemberTypeHuman)
	res, err := f.env.Svc.Login(ctx, email, testPW)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := f.env.Svc.CreateSession(ctx, res.Ticket, ws)
	if err != nil {
		t.Fatal(err)
	}
	return caller{user: user, ws: ws, member: member, email: email, pair: pair}
}
