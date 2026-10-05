package web

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"sync"
	"time"
)

const (
	cookieName = "astro_session"
	sessionTTL = 12 * time.Hour
)

// flash is a one-shot message shown on the next page.
type flash struct {
	Kind    string // "ok" or "error"
	Message string
}

type session struct {
	tokenID   int64
	tokenName string
	expires   time.Time
	flash     *flash
}

// sessions keeps web sessions in memory: they end when the server stops.
type sessions struct {
	mu sync.Mutex
	m  map[string]*session
}

func newSessions() *sessions { return &sessions{m: map[string]*session{}} }

func (s *sessions) create(tokenID int64, tokenName string, now time.Time) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	id := base64.RawURLEncoding.EncodeToString(b)
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.m { // opportunistic cleanup
		if now.After(v.expires) {
			delete(s.m, k)
		}
	}
	s.m[id] = &session{tokenID: tokenID, tokenName: tokenName, expires: now.Add(sessionTTL)}
	return id, nil
}

func (s *sessions) get(id string, now time.Time) (*session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.m[id]
	if !ok || now.After(sess.expires) {
		delete(s.m, id)
		return nil, false
	}
	return sess, true
}

func (s *sessions) delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, id)
}

func (s *sessions) setFlash(id string, f flash) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess, ok := s.m[id]; ok {
		sess.flash = &f
	}
}

func (s *sessions) takeFlash(id string) *flash {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.m[id]
	if !ok {
		return nil
	}
	f := sess.flash
	sess.flash = nil
	return f
}

// sessionCookie is HttpOnly and SameSite=Strict. Secure is set when serving
// over TLS: forcing it on plain http://127.0.0.1 would break sign-in in
// browsers that refuse Secure cookies without HTTPS.
func sessionCookie(value string, secure bool, maxAge int) *http.Cookie {
	return &http.Cookie{ // #nosec G124 -- Secure follows TLS, see above
		Name:     cookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
	}
}
