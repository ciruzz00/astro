package detect

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ciruzz00/astro/internal/logs"
	"github.com/ciruzz00/astro/internal/logs/access"
	"github.com/ciruzz00/astro/internal/logs/syslog"
	"github.com/ciruzz00/astro/internal/logs/utmp"
)

// Thresholds of the correlations.
const (
	bruteWindow     = 10 * time.Minute
	bruteThreshold  = 10 // failures from one source in bruteWindow
	sprayAccounts   = 5  // distinct accounts from one source in bruteWindow
	successLookback = time.Hour
	successMinFails = 5 // failures before a success that make it suspicious
	roastWindow     = 10 * time.Minute
	roastServices   = 3
	burstWindow     = 5 * time.Minute
	burstThreshold  = 100 // HTTP 4xx answers to one client in burstWindow
)

var (
	ruleBrute   = Rule{"auth-brute-force", "Brute force of logins", logs.High, "T1110"}
	ruleSpray   = Rule{"auth-password-spray", "Password spraying across accounts", logs.High, "T1110.003"}
	ruleSuccess = Rule{"auth-success-after-brute-force", "Successful login after a brute force", logs.Critical, "T1078"}
	ruleRoast   = Rule{"win-kerberoasting", "Kerberoasting: RC4 service tickets for several services", logs.High, "T1558.003"}
	ruleBurst   = Rule{"web-content-discovery", "Burst of failed web requests (content discovery)", logs.Medium, "T1595.003"}
)

func newCorrelations() []stateful {
	return []stateful{&authCorrelation{sources: map[string]*authSource{}}, &kerberoast{accounts: map[string]*roastState{}},
		&webBurst{clients: map[string]*burstState{}}}
}

// authCorrelation follows failed and successful logins per source.
type authCorrelation struct {
	sources map[string]*authSource
}

type authSource struct {
	recent   window // failures in bruteWindow
	hour     window // failures in successLookback
	accounts map[string]time.Time
	pending  []logs.Event // failures before the threshold was reached
	brute    *builder
	spray    *builder
	total    int
}

// failure reports a failed login: its source key, the account and how
// many attempts the event stands for.
func failure(e *logs.Event) (string, int, bool) {
	n := 1
	if r, err := strconv.Atoi(field(e, "repeated")); err == nil && r > 1 {
		n = r
	}
	switch {
	case e.Kind == syslog.KindSSHFailed, e.Kind == utmp.KindLoginFailed:
	case e.Kind == syslog.KindAuthFailure && field(e, "service") != "sshd": // sshd failures are counted on their own line
	case security(e, 4625, 4771):
		if strings.HasSuffix(e.User, "$") { // computer accounts with a stale password: routine in a domain
			return "", 0, false
		}
	default:
		return "", 0, false
	}
	return sourceKey(e), n, true
}

// success reports an interactive or network login that worked.
func success(e *logs.Event) bool {
	switch {
	case e.Kind == syslog.KindSSHAccepted:
		return true
	case e.Kind == utmp.KindLogin:
		return e.SrcIP != ""
	case security(e, 4624):
		switch field(e, "LogonType") {
		case "2", "3", "7", "8", "10", "11":
			return e.SrcIP != "" && e.SrcIP != "127.0.0.1" && e.SrcIP != "::1"
		}
	}
	return false
}

// sourceKey is the address of the attempts, or the target host when the
// logs carry none (console or local attempts).
func sourceKey(e *logs.Event) string {
	if e.SrcIP != "" {
		return e.SrcIP
	}
	return "@" + strings.ToLower(e.Host)
}

func (a *authCorrelation) observe(e *logs.Event, en *Engine) {
	if key, n, ok := failure(e); ok {
		s := a.sources[key]
		if s == nil {
			s = &authSource{recent: window{span: bruteWindow}, hour: window{span: successLookback}, accounts: map[string]time.Time{}}
			a.sources[key] = s
		}
		s.total += n
		s.hour.add(e.Time, n)
		count := s.recent.add(e.Time, n)
		if e.User != "" {
			s.accounts[strings.ToLower(e.User)] = e.Time
		}
		switch {
		case s.brute != nil:
			en.hit(ruleBrute, key, e, "")
		case count >= bruteThreshold:
			for i := range s.pending {
				s.brute = en.hit(ruleBrute, key, &s.pending[i], "")
			}
			s.pending = nil
			s.brute = en.hit(ruleBrute, key, e, "")
			s.brute.detail = func(b *builder) string { return a.bruteSummary(b, key) }
		default:
			if len(s.pending) < bruteThreshold {
				s.pending = append(s.pending, *e)
			}
		}
		if active := recentAccounts(s.accounts, e.Time); active >= sprayAccounts {
			if s.spray == nil {
				s.spray = en.hit(ruleSpray, key, e, "")
				s.spray.detail = func(b *builder) string { return a.bruteSummary(b, key) }
			} else {
				en.hit(ruleSpray, key, e, "")
			}
		}
		return
	}
	if success(e) {
		s := a.sources[sourceKey(e)]
		if s == nil {
			return
		}
		fails := s.hour.count(e.Time)
		if fails < successMinFails {
			return
		}
		b := en.hit(ruleSuccess, sourceKey(e)+"|"+strings.ToLower(e.User), e, "")
		b.detail = func(b *builder) string {
			return fmt.Sprintf("%s logged in from %s after %d failed attempts from that address in the previous hour (%s).",
				orUnknown(b.f.User), orUnknown(b.f.SrcIP), fails, logs.Truncate(firstLine(e.Message), 160))
		}
	}
}

func (a *authCorrelation) bruteSummary(b *builder, key string) string {
	s := a.sources[key]
	accounts := make([]string, 0, len(s.accounts))
	for u := range s.accounts {
		accounts = append(accounts, u)
	}
	sort.Strings(accounts)
	from := key
	if strings.HasPrefix(key, "@") {
		from = "no source address, target " + key[1:]
	}
	return fmt.Sprintf("%d failed logins from %s between %s and %s, against %d account(s): %s.",
		s.total, from, b.f.First.Format(time.DateTime), b.f.Last.Format(time.DateTime), len(accounts),
		logs.Truncate(strings.Join(accounts, ", "), 300))
}

// recentAccounts counts the accounts tried within bruteWindow before t.
func recentAccounts(seen map[string]time.Time, t time.Time) int {
	n := 0
	for _, at := range seen {
		if t.Sub(at) <= bruteWindow {
			n++
		}
	}
	return n
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return s
}

func orUnknown(s string) string {
	if s == "" {
		return "an unknown account"
	}
	return s
}

// kerberoast follows RC4 service ticket requests per account.
type kerberoast struct {
	accounts map[string]*roastState
}

type roastState struct {
	services map[string]time.Time
	pending  []logs.Event
	b        *builder
}

func (k *kerberoast) observe(e *logs.Event, en *Engine) {
	if !security(e, 4769) || !strings.EqualFold(field(e, "TicketEncryptionType"), "0x17") {
		return
	}
	svc := strings.ToLower(field(e, "ServiceName"))
	if svc == "" || strings.HasSuffix(svc, "$") || strings.HasPrefix(svc, "krbtgt") {
		return
	}
	acct := strings.ToLower(e.User)
	s := k.accounts[acct]
	if s == nil {
		s = &roastState{services: map[string]time.Time{}}
		k.accounts[acct] = s
	}
	s.services[svc] = e.Time
	if s.b != nil {
		en.hit(ruleRoast, acct, e, field(e, "ServiceName"))
		return
	}
	s.pending = append(s.pending, *e)
	n := 0
	for _, at := range s.services {
		if e.Time.Sub(at) <= roastWindow {
			n++
		}
	}
	if n >= roastServices {
		for i := range s.pending {
			s.b = en.hit(ruleRoast, acct, &s.pending[i], field(&s.pending[i], "ServiceName"))
		}
		s.pending = nil
	} else if len(s.pending) > 64 {
		s.pending = s.pending[1:]
	}
}

// webBurst follows HTTP client errors per client.
type webBurst struct {
	clients map[string]*burstState
}

type burstState struct {
	w       window
	pending []logs.Event
	b       *builder
}

func (w *webBurst) observe(e *logs.Event, en *Engine) {
	if e.Kind != access.KindRequest {
		return
	}
	status := number(e, "status")
	if status < 400 || status > 499 {
		return
	}
	key := webGroup(e)
	s := w.clients[key]
	if s == nil {
		s = &burstState{w: window{span: burstWindow}}
		w.clients[key] = s
	}
	count := s.w.add(e.Time, 1)
	if s.b != nil {
		en.hit(ruleBurst, key, e, "")
		return
	}
	s.pending = append(s.pending, *e)
	if len(s.pending) > burstThreshold {
		s.pending = s.pending[1:]
	}
	if count >= burstThreshold {
		for i := range s.pending {
			s.b = en.hit(ruleBurst, key, &s.pending[i], "")
		}
		s.pending = nil
		client := e.SrcIP
		s.b.detail = func(b *builder) string {
			return fmt.Sprintf("%d requests from %s answered with 4xx between %s and %s: typical of directory or file brute forcing.",
				b.f.Count, client, b.f.First.Format(time.DateTime), b.f.Last.Format(time.DateTime))
		}
	}
}
