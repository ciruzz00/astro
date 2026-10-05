package httpx

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDoStatusHandling(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") != UserAgent {
			t.Errorf("User-Agent = %q", r.Header.Get("User-Agent"))
		}
		switch r.URL.Path {
		case "/missing":
			http.NotFound(w, r)
		case "/quota":
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte("slow down\x1b[31m"))
		case "/big":
			_, _ = w.Write([]byte(strings.Repeat("x", 100)))
		default:
			_, _ = w.Write([]byte(`{"ok":true}`))
		}
	}))
	defer srv.Close()
	c := NewClient(5 * time.Second)
	ctx := context.Background()

	var v struct{ OK bool }
	if err := GetJSON(ctx, c, srv.URL+"/ok", nil, &v); err != nil || !v.OK {
		t.Fatalf("GetJSON = %v, %+v", err, v)
	}
	if err := GetJSON(ctx, c, srv.URL+"/missing", nil, &v); !errors.Is(err, ErrNotFound) {
		t.Errorf("404: err = %v", err)
	}
	err := GetJSON(ctx, c, srv.URL+"/quota", nil, &v)
	var se *StatusError
	if !errors.As(err, &se) || se.Code != 429 || strings.ContainsRune(se.Body, 0x1b) {
		t.Errorf("429: err = %#v", err)
	}

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/big", nil)
	if _, err := Do(c, req, 10); err == nil {
		t.Error("oversized body must fail")
	}
}

func TestErrorsDoNotLeakQueryKeys(t *testing.T) {
	c := NewClient(time.Second)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://127.0.0.1:1/x?key=SECRET123", nil)
	_, err := Do(c, req, 10)
	if err == nil {
		t.Fatal("expected connection error")
	}
	if strings.Contains(err.Error(), "SECRET123") {
		t.Errorf("error leaks the key: %v", err)
	}
}

func TestNoHTTPSDowngrade(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer plain.Close()
	tls := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL, http.StatusFound)
	}))
	defer tls.Close()

	c := NewClient(5 * time.Second)
	c.Transport = tls.Client().Transport
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, tls.URL, nil)
	if _, err := Do(c, req, 1024); err == nil || !strings.Contains(err.Error(), "refusing redirect") {
		t.Errorf("https->http redirect must be refused, err = %v", err)
	}
}
