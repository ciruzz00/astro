// Package httpx provides a hardened HTTP client for calls to external providers.
package httpx

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// UserAgent is sent with every request. It is set by main at startup.
var UserAgent = "astro/dev (+https://github.com/ciruzz00/astro)"

// MaxBody is the default cap on response bodies read into memory.
const MaxBody = 16 << 20

// ErrNotFound is returned when the provider has no data for the indicator.
var ErrNotFound = errors.New("not found")

// StatusError is returned for unexpected HTTP status codes.
type StatusError struct {
	Code int
	Body string
}

func (e *StatusError) Error() string {
	var msg string
	switch e.Code {
	case http.StatusUnauthorized, http.StatusForbidden:
		msg = fmt.Sprintf("authentication failed (HTTP %d): check the API key", e.Code)
	case http.StatusTooManyRequests:
		msg = "rate limit or quota exceeded (HTTP 429)"
	default:
		msg = fmt.Sprintf("unexpected HTTP status %d", e.Code)
	}
	if e.Body != "" {
		msg += ": " + e.Body
	}
	return msg
}

// NewClient returns a client with TLS 1.2+, bounded timeouts and a redirect
// policy that never downgrades to plain HTTP.
func NewClient(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	tr := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: timeout,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConnsPerHost:   4,
		ForceAttemptHTTP2:     true,
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("too many redirects")
			}
			if via[0].URL.Scheme == "https" && req.URL.Scheme != "https" {
				return errors.New("refusing redirect from https to " + req.URL.Scheme)
			}
			return nil
		},
	}
}

// Do sends req and returns the body, capped at limit bytes.
// 404 maps to ErrNotFound; other non-2xx codes to *StatusError.
func Do(c *http.Client, req *http.Request, limit int64) ([]byte, error) {
	req.Header.Set("User-Agent", UserAgent)
	resp, err := c.Do(req) // #nosec G704 -- callers only build requests for fixed provider hosts
	if err != nil {
		// Some providers take the API key as a query parameter: never let it
		// reach error messages or logs.
		var ue *url.Error
		if errors.As(err, &ue) {
			ue.URL = redactURL(ue.URL)
		}
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("response larger than %d bytes", limit)
	}
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, ErrNotFound
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		return nil, &StatusError{Code: resp.StatusCode, Body: snippet(body)}
	}
	return body, nil
}

// GetJSON performs a GET and decodes the JSON response into v.
func GetJSON(ctx context.Context, c *http.Client, url string, header http.Header, v any) error {
	return doJSON(ctx, c, http.MethodGet, url, header, nil, "", v)
}

// PostForm sends form values and decodes the JSON response into v.
func PostForm(ctx context.Context, c *http.Client, endpoint string, header http.Header, form url.Values, v any) error {
	return doJSON(ctx, c, http.MethodPost, endpoint, header,
		strings.NewReader(form.Encode()), "application/x-www-form-urlencoded", v)
}

// PostJSON sends payload as JSON and decodes the JSON response into v.
func PostJSON(ctx context.Context, c *http.Client, endpoint string, header http.Header, payload, v any) error {
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return doJSON(ctx, c, http.MethodPost, endpoint, header, bytes.NewReader(b), "application/json", v)
}

func doJSON(ctx context.Context, c *http.Client, method, endpoint string, header http.Header, body io.Reader, contentType string, v any) error {
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return err
	}
	for k, vals := range header {
		for _, val := range vals {
			req.Header.Add(k, val)
		}
	}
	req.Header.Set("Accept", "application/json")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := Do(c, req, MaxBody)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(resp, v); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "[unparsable url]"
	}
	u.RawQuery, u.User = "", nil
	return u.String()
}

func snippet(b []byte) string {
	const n = 200
	s := []rune(string(b))
	for i, r := range s {
		if r < 0x20 && r != ' ' {
			s[i] = ' '
		}
	}
	if len(s) > n {
		return string(s[:n]) + "..."
	}
	return string(s)
}
