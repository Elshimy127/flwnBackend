package secure

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
	"math"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/Hesham127/flwnBackend/internal/auth"
)

// StripInternalHeaders drops headers only the backend may set towards the engine, so a client
// can never inject an acting member or a service key (docs/AUTH.md §3, §14).
func StripInternalHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		for _, h := range []string{"X-Acting-Member-Id", "X-Data-API-Key", "X-Member-Id"} {
			c.Request.Header.Del(h)
		}
		c.Next()
	}
}

// Logger logs method, route, status, latency and client IP. It never logs headers, query strings
// or bodies, so tokens, cookies and passwords cannot reach the logs.
func Logger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		path := c.FullPath()
		if path == "" {
			path = "(unmatched)"
		}
		log.Printf("http %s %s %d %s ip=%s", c.Request.Method, path, c.Writer.Status(),
			time.Since(start).Round(time.Millisecond), c.ClientIP())
	}
}

// NoStore marks responses as uncacheable (every auth response).
func NoStore() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		c.Header("Pragma", "no-cache")
		c.Next()
	}
}

// SecurityHeaders sets baseline headers; HSTS only when hsts is true (production, HTTPS).
func SecurityHeaders(hsts bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("Referrer-Policy", "no-referrer")
		c.Header("X-Frame-Options", "DENY")
		if hsts {
			c.Header("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}
		c.Next()
	}
}

// CORS allows exactly the configured origins. Credentials are allowed only on browser auth
// routes (cookie-carrying); native auth routes send no CORS headers at all.
func CORS(origins []string, authPrefix, nativePrefix string) gin.HandlerFunc {
	allowed := map[string]bool{}
	for _, o := range origins {
		allowed[strings.TrimRight(o, "/")] = true
	}
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		path := c.Request.URL.Path
		if origin == "" || !allowed[origin] || strings.HasPrefix(path, nativePrefix) {
			if c.Request.Method == http.MethodOptions && origin != "" {
				c.AbortWithStatus(http.StatusForbidden)
				return
			}
			c.Next()
			return
		}
		h := c.Writer.Header()
		h.Set("Access-Control-Allow-Origin", origin)
		h.Add("Vary", "Origin")
		if strings.HasPrefix(path, authPrefix) {
			h.Set("Access-Control-Allow-Credentials", "true")
		}
		if c.Request.Method == http.MethodOptions {
			h.Set("Access-Control-Allow-Methods", "GET, POST, PATCH, PUT, DELETE")
			h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-CSRF-Token, Idempotency-Key, X-Workspace-Id")
			h.Set("Access-Control-Max-Age", "600")
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}

// RateLimiter is an in-memory token bucket per key. It sits behind this small type so a shared
// store (Redis) can replace it when the backend runs more than one instance.
type RateLimiter struct {
	mu      sync.Mutex
	rate    float64 // tokens per second
	burst   float64
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

func NewRateLimiter(perMinute, burst int) *RateLimiter {
	return &RateLimiter{rate: float64(perMinute) / 60, burst: float64(burst), buckets: map[string]*bucket{}}
}

// Allow takes one token for key.
func (l *RateLimiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if len(l.buckets) > 100000 {
		l.buckets = map[string]*bucket{}
	}
	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	b.tokens = math.Min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.rate)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// LimitByIP rejects requests over the per-IP rate with 429.
func LimitByIP(l *RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !l.Allow(c.ClientIP()) {
			c.Header("Retry-After", "60")
			abortStatus(c, http.StatusTooManyRequests, "too_many_requests")
			return
		}
		c.Next()
	}
}

// Idempotent replays the stored response for a repeated Idempotency-Key (same caller, route and
// request body), and answers 409 when the key is reused with a different body. Requires Access.
func Idempotent(store auth.Store, now func() time.Time) gin.HandlerFunc {
	return func(c *gin.Context) {
		key := c.GetHeader("Idempotency-Key")
		if key == "" {
			c.Next()
			return
		}
		if len(key) > 200 {
			abortStatus(c, http.StatusBadRequest, "idempotency_key_too_long")
			return
		}
		p := PrincipalFrom(c)
		body, _ := c.GetRawData()
		c.Request.Body = nopCloser{bytes.NewReader(body)}
		sum := sha256.Sum256(body)
		route := c.Request.Method + " " + c.FullPath()
		ctx := c.Request.Context()
		// Reserve first, so a concurrent duplicate cannot run the handler a second time.
		err := store.ReserveIdempotency(ctx, auth.IdempotencyRecord{
			Key: key, UserID: p.UserID, Route: route, RequestHash: sum[:], CreatedAt: now(),
		})
		if errors.Is(err, auth.ErrIdempotencyHit) {
			rec, gerr := store.GetIdempotency(ctx, p.UserID, route, key)
			switch {
			case gerr == nil && !bytes.Equal(rec.RequestHash, sum[:]):
				abortStatus(c, http.StatusConflict, "idempotency_key_reused")
			case gerr != nil || rec.StatusCode == 0:
				c.Header("Retry-After", "1")
				abortStatus(c, http.StatusConflict, "request_in_progress")
			default:
				c.Data(rec.StatusCode, "application/json", rec.ResponseJSON)
				c.Abort()
			}
			return
		}
		if err != nil {
			abort(c, fmt.Errorf("%w: %v", auth.ErrUnavailable, err))
			return
		}
		done := false
		defer func() {
			if !done { // handler failed or panicked: free the key for a retry
				_ = store.ReleaseIdempotency(context.WithoutCancel(ctx), p.UserID, route, key)
			}
		}()
		rw := &captureWriter{ResponseWriter: c.Writer}
		c.Writer = rw
		c.Next()
		if rw.Status() >= 200 && rw.Status() < 300 {
			if err := store.CompleteIdempotency(context.WithoutCancel(ctx), p.UserID, route, key, rw.Status(), rw.buf.Bytes()); err == nil {
				done = true
			}
		}
	}
}

type nopCloser struct{ *bytes.Reader }

func (nopCloser) Close() error { return nil }

type captureWriter struct {
	gin.ResponseWriter
	buf bytes.Buffer
}

func (w *captureWriter) Write(b []byte) (int, error) {
	w.buf.Write(b)
	return w.ResponseWriter.Write(b)
}

// ParseUUIDParam is a helper for handlers.
func ParseUUIDParam(c *gin.Context, name string) (uuid.UUID, bool) {
	id, err := uuid.Parse(c.Param(name))
	if err != nil {
		abortStatus(c, http.StatusBadRequest, name+"_must_be_uuid")
		return uuid.Nil, false
	}
	return id, true
}
