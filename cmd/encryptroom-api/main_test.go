package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func mustCIDR(t *testing.T, cidr string) *net.IPNet {
	t.Helper()
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("parse cidr: %v", err)
	}
	return network
}

func TestRateLimiterBlocksAfterLimit(t *testing.T) {
	limiter := newRateLimiter(time.Minute, 1, 100)
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

func TestRateLimiterBoundsTrackedKeys(t *testing.T) {
	limiter := newRateLimiter(time.Minute, 1, 2)
	now := time.Unix(1000, 0)

	if ok, _ := limiter.allow("1.1.1.1", now); !ok {
		t.Fatal("first key should pass")
	}
	if ok, _ := limiter.allow("2.2.2.2", now); !ok {
		t.Fatal("second key should pass")
	}
	if len(limiter.entries) != 2 {
		t.Fatalf("expected 2 tracked keys, got %d", len(limiter.entries))
	}
	if ok, _ := limiter.allow("3.3.3.3", now); !ok {
		t.Fatal("third key should pass via eviction")
	}
	if len(limiter.entries) != 2 {
		t.Fatalf("expected bounded key count of 2, got %d", len(limiter.entries))
	}
}

func TestClientAddressUsesTrustedForwardedHeadersOnly(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "http://api.test/api/v1/bundles", nil)
	req.RemoteAddr = "198.51.100.4:9999"
	req.Header.Set("X-Forwarded-For", "203.0.113.8")

	trusted := []*net.IPNet{mustCIDR(t, "127.0.0.0/8")}
	if got := clientAddress(req, trusted); got != "198.51.100.4" {
		t.Fatalf("untrusted source should ignore xff; got %q", got)
	}

	req2 := httptest.NewRequest(http.MethodPost, "http://api.test/api/v1/bundles", nil)
	req2.RemoteAddr = "127.0.0.1:12345"
	req2.Header.Set("X-Forwarded-For", "203.0.113.8, 10.0.0.1")
	if got := clientAddress(req2, trusted); got != "203.0.113.8" {
		t.Fatalf("trusted source should use xff first hop; got %q", got)
	}
}

func TestParseTrustedProxyCIDRs(t *testing.T) {
	cidrs, err := parseTrustedProxyCIDRs("127.0.0.0/8, ::1/128")
	if err != nil {
		t.Fatalf("parseTrustedProxyCIDRs: %v", err)
	}
	if len(cidrs) != 2 {
		t.Fatalf("expected 2 cidrs, got %d", len(cidrs))
	}
	if _, err := parseTrustedProxyCIDRs("bad-cidr"); err == nil {
		t.Fatal("expected parse error for bad cidr")
	}
}

func TestHandleCreateBundleRateLimitedBeforeBuild(t *testing.T) {
	srv := &apiServer{
		rateLimiter:    newRateLimiter(time.Minute, 1, 100),
		trustedProxies: []*net.IPNet{},
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
