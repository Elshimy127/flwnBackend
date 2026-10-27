package tests

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/Hesham127/flwnBackend/internal/platform/dataengine"
	"github.com/Hesham127/flwnBackend/internal/server"
)

const testAPIKey = "test-service-key"

// recorded is what the fake engine saw.
type recorded struct {
	Method string
	Path   string
	Query  string
	Header http.Header
	Body   string
}

// fakeEngine answers every request with one canned response and records the last request.
type fakeEngine struct {
	*httptest.Server
	mu     sync.Mutex
	last   recorded
	status int
	body   string
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

func (f *fakeEngine) client(t *testing.T) *dataengine.Client {
	t.Helper()
	c, err := dataengine.New(f.URL, testAPIKey)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (f *fakeEngine) router(t *testing.T) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	return server.NewRouter(f.client(t))
}
