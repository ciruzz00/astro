package web

import (
	"fmt"
	"net/http"
	"strings"
)

// --- provider API keys ---

type settingsData struct {
	Keys    []KeyStatus
	Tests   []KeyTest
	Tested  string
	Enabled int
	Total   int
}

func (s *server) settingsPage(w http.ResponseWriter, r *http.Request) {
	s.renderSettings(w, r, http.StatusOK, settingsData{})
}

func (s *server) renderSettings(w http.ResponseWriter, r *http.Request, status int, d settingsData) {
	keys, err := s.Keys.KeyStatuses(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d.Keys = keys
	for _, src := range s.Sources() {
		d.Total++
		if src.Enabled {
			d.Enabled++
		}
	}
	s.render(w, r, status, "settings", "API keys", "settings", d)
}

func (s *server) saveKey(w http.ResponseWriter, r *http.Request) {
	if err := parseForm(w, r); err != nil {
		s.flashRedirect(w, r, "/settings", "error", "Invalid form")
		return
	}
	name := r.FormValue("name")
	if err := s.Keys.SetKey(r.Context(), name, r.FormValue("value")); err != nil {
		s.flashRedirect(w, r, "/settings#key-"+name, "error", err.Error())
		return
	}
	// Never log the value: only the fact that it changed.
	s.Logger.Info("provider key updated", "key", name, "by", info(r).tokenName)
	s.flashRedirect(w, r, "/settings#key-"+name, "ok", "Key saved: the sources using it are active now. Use Test to check it.")
}

func (s *server) deleteKey(w http.ResponseWriter, r *http.Request) {
	if err := parseForm(w, r); err != nil {
		s.flashRedirect(w, r, "/settings", "error", "Invalid form")
		return
	}
	name := r.FormValue("name")
	if err := s.Keys.DeleteKey(r.Context(), name); err != nil {
		s.flashRedirect(w, r, "/settings#key-"+name, "error", err.Error())
		return
	}
	s.Logger.Info("provider key removed", "key", name, "by", info(r).tokenName)
	s.flashRedirect(w, r, "/settings#key-"+name, "ok", "Key removed.")
}

// testKey renders the results directly: they are not stored anywhere.
func (s *server) testKey(w http.ResponseWriter, r *http.Request) {
	if err := parseForm(w, r); err != nil {
		s.flashRedirect(w, r, "/settings", "error", "Invalid form")
		return
	}
	name := r.FormValue("name")
	tests, err := s.Keys.TestKey(r.Context(), name)
	if err != nil {
		s.flashRedirect(w, r, "/settings#key-"+name, "error", err.Error())
		return
	}
	s.renderSettings(w, r, http.StatusOK, settingsData{Tests: tests, Tested: name})
}

// --- guide ---

func (s *server) guidePage(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, http.StatusOK, "guide", "Guide", "guide", nil)
}

// --- language ---

const langCookie = "astro_lang"

var languages = []string{"en", "it"}

// langOf returns the user's language: the cookie, else the browser preference.
func langOf(r *http.Request) string {
	if c, err := r.Cookie(langCookie); err == nil && (c.Value == "it" || c.Value == "en") {
		return c.Value
	}
	for _, part := range strings.Split(r.Header.Get("Accept-Language"), ",") {
		tag := strings.ToLower(strings.TrimSpace(strings.SplitN(part, ";", 2)[0]))
		switch {
		case strings.HasPrefix(tag, "it"):
			return "it"
		case strings.HasPrefix(tag, "en"):
			return "en"
		}
	}
	return "en"
}

// setLanguage stores the chosen language and goes back to the page.
func (s *server) setLanguage(w http.ResponseWriter, r *http.Request) {
	lang := r.URL.Query().Get("l")
	if lang != "it" && lang != "en" {
		lang = "en"
	}
	http.SetCookie(w, &http.Cookie{
		Name: langCookie, Value: lang, Path: "/", MaxAge: 365 * 24 * 3600,
		HttpOnly: true, Secure: s.Secure, SameSite: http.SameSiteLaxMode,
	}) // #nosec G124 -- Secure follows TLS; the cookie only holds a language code
	redirect(w, r, r.URL.Query().Get("next"))
}

// tr translates a message (a format string) for the request's language.
func (s *server) tr(r *http.Request, format string, args ...any) string {
	return translate(langOf(r), format, args...)
}

// translate returns the translation of key (English text) in lang,
// formatted with args when given. Unknown keys are returned as they are.
func translate(lang, key string, args ...any) string {
	if lang == "it" {
		if v, ok := italian[key]; ok {
			key = v
		}
	}
	if len(args) > 0 {
		return fmt.Sprintf(key, args...)
	}
	return key
}
