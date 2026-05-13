package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewRejectsBadURLs(t *testing.T) {
	cases := []struct {
		name string
		url  string
	}{
		{"empty", ""},
		{"missing scheme", "postvale.app"},
		{"ftp scheme", "ftp://postvale.app"},
		{"javascript scheme", "javascript:alert(1)"},
		{"file scheme", "file:///etc/passwd"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(tc.url, "", 5*time.Second)
			if err == nil {
				t.Fatalf("expected error for %q", tc.url)
			}
		})
	}
}

func TestNewAcceptsValidURLs(t *testing.T) {
	for _, u := range []string{"http://localhost:3000", "https://postvale.app", "https://api.example.com:8443"} {
		if _, err := New(u, "", 5*time.Second); err != nil {
			t.Fatalf("unexpected error for %q: %v", u, err)
		}
	}
}

func TestHTTPErrorParsesJSONShape(t *testing.T) {
	body, _ := json.Marshal(map[string]string{"error": "rate_limited", "message": "Too many requests."})
	e := &HTTPError{StatusCode: 429, Status: "429 Too Many Requests", URL: "x", Body: body}
	if got := e.Error(); !strings.Contains(got, "Too many requests.") {
		t.Fatalf("Error() = %q, want it to contain message", got)
	}
}

func TestHTTPErrorFallsBackToBodyPreview(t *testing.T) {
	e := &HTTPError{StatusCode: 500, Status: "500", URL: "x", Body: []byte("internal stack trace\nmore lines")}
	got := e.Error()
	if !strings.Contains(got, "internal stack trace") {
		t.Fatalf("Error() = %q, want it to include body preview", got)
	}
}

func TestHTTPErrorTruncatesLongBody(t *testing.T) {
	longBody := strings.Repeat("x", 1000)
	e := &HTTPError{StatusCode: 500, Status: "500", URL: "x", Body: []byte(longBody)}
	got := e.Error()
	if len(got) > 400 {
		t.Fatalf("Error() length %d, want truncation around ~200", len(got))
	}
	if !strings.HasSuffix(got, "...") {
		t.Fatalf("Error() = %q, want trailing ellipsis", got)
	}
}

func TestClientGetRoundTrip(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/me" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("missing or wrong Authorization header: %q", r.Header.Get("Authorization"))
		}
		if !strings.HasPrefix(r.Header.Get("User-Agent"), "postvale-cli/") {
			t.Errorf("unexpected User-Agent: %q", r.Header.Get("User-Agent"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"email":"user@example.com"}`))
	}))
	defer srv.Close()

	c, err := New(srv.URL, "test-token", 5*time.Second)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	var out struct{ Email string }
	if err := c.get("/api/v1/me", &out); err != nil {
		t.Fatalf("get: %v", err)
	}
	if out.Email != "user@example.com" {
		t.Fatalf("got %+v", out)
	}
}

func TestClientGetNon2xxReturnsHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"not_found","message":"no such tool"}`))
	}))
	defer srv.Close()

	c, _ := New(srv.URL, "", 5*time.Second)
	err := c.get("/x", nil)
	var he *HTTPError
	if !errors.As(err, &he) {
		t.Fatalf("expected *HTTPError, got %T (%v)", err, err)
	}
	if he.StatusCode != 404 {
		t.Fatalf("StatusCode = %d, want 404", he.StatusCode)
	}
	if !strings.Contains(he.Error(), "no such tool") {
		t.Fatalf("Error() should surface message: %q", he.Error())
	}
}

func TestClientGetEnforcesBodySizeCap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Just over the cap. Should be rejected with "exceeded N bytes".
		big := strings.Repeat("a", maxResponseBytes+100)
		_, _ = w.Write([]byte(big))
	}))
	defer srv.Close()

	c, _ := New(srv.URL, "", 5*time.Second)
	err := c.get("/big", nil)
	if err == nil || !strings.Contains(err.Error(), "exceeded") {
		t.Fatalf("expected size-cap error, got %v", err)
	}
}

func TestClientGetCtxNotLeaked(t *testing.T) {
	// Mostly a smoke test that the client cleans up after itself; we
	// don't expose context wiring yet but verify timeout fires.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(2 * time.Second):
			w.WriteHeader(http.StatusOK)
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()

	c, _ := New(srv.URL, "", 100*time.Millisecond)
	err := c.get("/slow", nil)
	if err == nil {
		t.Fatal("expected timeout error")
	}
}
