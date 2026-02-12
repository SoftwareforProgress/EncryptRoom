package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRateLimiterBlocksAfterLimit(t *testing.T) {
	limiter := newRateLimiter(time.Minute, 1)
	now := time.Unix(1000, 0)

	ok, retry := limiter.allow("1.2.3.4", now)
	if !ok {
		t.Fatal("expected first request to pass")
	}
	if retry != 0 {
		t.Fatalf("expected zero retry on first request, got %s", retry)
	}

	ok, retry = limiter.allow("1.2.3.4", now.Add(10*time.Second))
	if ok {
		t.Fatal("expected second request to be rate limited")
	}
	if retry <= 0 {
		t.Fatalf("expected positive retry-after, got %s", retry)
	}

	ok, _ = limiter.allow("1.2.3.4", now.Add(time.Minute+time.Second))
	if !ok {
		t.Fatal("expected request after window to pass")
	}
}

func TestClientAddressPrefersForwardedHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "http://api.test/api/v1/bundles", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.8, 10.0.0.1")

	if got := clientAddress(req); got != "203.0.113.8" {
		t.Fatalf("unexpected client address: got %q", got)
	}

	req2 := httptest.NewRequest(http.MethodPost, "http://api.test/api/v1/bundles", nil)
	req2.RemoteAddr = "127.0.0.1:12345"
	req2.Header.Set("X-Real-Ip", "198.51.100.10")
	if got := clientAddress(req2); got != "198.51.100.10" {
		t.Fatalf("unexpected X-Real-Ip fallback: got %q", got)
	}
}

func TestHandleCreateBundleRateLimitedBeforeBuild(t *testing.T) {
	srv := &apiServer{
		rateLimiter: newRateLimiter(time.Minute, 1),
	}

	req1 := httptest.NewRequest(http.MethodPost, "/api/v1/bundles", strings.NewReader("{}"))
	req1.RemoteAddr = "198.51.100.4:9999"
	w1 := httptest.NewRecorder()
	srv.handleCreateBundle(w1, req1)
	if w1.Code != http.StatusBadRequest {
		t.Fatalf("first request should parse and fail as bad request, got %d", w1.Code)
	}

	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/bundles", strings.NewReader("{}"))
	req2.RemoteAddr = "198.51.100.4:9999"
	w2 := httptest.NewRecorder()
	srv.handleCreateBundle(w2, req2)
	if w2.Code != http.StatusTooManyRequests {
		t.Fatalf("expected second request to be rate limited, got %d", w2.Code)
	}
	if w2.Header().Get("Retry-After") == "" {
		t.Fatal("expected Retry-After header on rate limit response")
	}
}
