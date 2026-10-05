package ioc

import (
	"regexp"
	"sort"
	"strings"
)

var (
	reDefangScheme = regexp.MustCompile(`(?i)\b(h[x*]{2}p|fxp)(s?)(\[://\]|\[:\]//|://)`)
	defangPairs    = strings.NewReplacer(
		"[.]", ".", "(.)", ".", "{.}", ".", "[dot]", ".", "(dot)", ".", "{dot}", ".", "[DOT]", ".", "(DOT)", ".",
		"[:]", ":", "[://]", "://",
		"[@]", "@", "[at]", "@", "(at)", "@", "[AT]", "@", "(AT)", "@",
		"[/]", "/",
	)
)

// Refang turns common defanged notations back into their original form,
// e.g. "hxxps://evil[.]com" becomes "https://evil.com".
func Refang(s string) string {
	s = reDefangScheme.ReplaceAllStringFunc(s, func(m string) string {
		sub := reDefangScheme.FindStringSubmatch(m)
		scheme := "http"
		if strings.EqualFold(sub[1], "fxp") {
			scheme = "ftp"
		}
		return scheme + strings.ToLower(sub[2]) + "://"
	})
	return defangPairs.Replace(s)
}

// Defang makes an indicator safe to share in reports and chats.
func Defang(i Indicator) string {
	v := i.Value
	switch i.Type {
	case URL:
		if p := strings.Index(v, "://"); p > 0 {
			v = strings.Replace(v[:p], "http", "hxxp", 1) + "[://]" + v[p+3:]
		}
		return strings.ReplaceAll(v, ".", "[.]")
	case Domain, IPv4:
		return strings.ReplaceAll(v, ".", "[.]")
	case Email:
		return strings.ReplaceAll(strings.Replace(v, "@", "[@]", 1), ".", "[.]")
	}
	return v
}

// DefangText defangs every URL, domain, IP and email found in free text, so
// notes written by analysts are as safe to share as indicator lists.
func DefangText(text string) string {
	inds := Extract(text)
	// Longest first, so a URL is replaced before the domain inside it.
	sort.Slice(inds, func(a, b int) bool { return len(inds[a].Value) > len(inds[b].Value) })
	for _, i := range inds {
		switch i.Type {
		case URL, Domain, IPv4, Email:
			text = strings.ReplaceAll(text, i.Value, Defang(i))
		}
	}
	return text
}

// MaxExtract caps the number of indicators returned by Extract.
const MaxExtract = 5000

const wordSeparators = " \t\r\n,;\"'<>(){}|`\\^"

// Extract finds every strict indicator (not keywords) in free text such as
// logs or reports. Results are de-duplicated and kept in order of appearance.
func Extract(text string) []Indicator {
	text = Refang(text)
	seen := make(map[Indicator]struct{})
	var out []Indicator
	for _, tok := range strings.FieldsFunc(text, func(r rune) bool { return strings.ContainsRune(wordSeparators, r) }) {
		for _, cand := range candidates(tok) {
			if len(cand) > MaxLen {
				continue
			}
			i, ok := detect(cand)
			if !ok {
				continue
			}
			if _, dup := seen[i]; dup {
				break
			}
			seen[i] = struct{}{}
			out = append(out, i)
			if len(out) >= MaxExtract {
				return out
			}
			break
		}
	}
	return out
}

// candidates returns the token and progressively trimmed variants of it,
// to cope with punctuation glued to indicators in prose ("see 1.2.3.4.").
func candidates(tok string) []string {
	trimmed := strings.TrimLeft(strings.TrimRight(tok, ".,:;!?]"), "[")
	if trimmed == "" {
		return nil
	}
	c := []string{trimmed}
	if trimmed != tok {
		c = append(c, tok)
	}
	// "key=value" and "key:value" pairs common in logs.
	for _, sep := range []string{"=", ":"} {
		if k, v, ok := strings.Cut(trimmed, sep); ok && k != "" && v != "" && !strings.Contains(trimmed, "://") {
			c = append(c, v)
		}
	}
	return c
}
