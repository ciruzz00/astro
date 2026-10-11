//go:build private

package evidence

import (
	"context"
	"os"
	"testing"

	"github.com/ciruzz00/astro/internal/store"
)

// TestPrivateCorpus imports the local evidence corpus named by
// $ASTRO_PRIVATE_CORPUS (challenge data that must never enter the
// repository) and prints what was recognized. Run with -tags private -v.
func TestPrivateCorpus(t *testing.T) {
	dir := os.Getenv("ASTRO_PRIVATE_CORPUS")
	if dir == "" {
		t.Skip("ASTRO_PRIVATE_CORPUS not set")
	}
	s, _, _ := setup(t)
	im := New(s, DefaultParsers()...)
	res, err := im.Import(context.Background(), "inc-1", dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range res.Files {
		t.Logf("%-14s %7d events %5d errors  %s %s%s", f.Kind, f.Events, f.Errors, f.Path, f.Skipped, f.Warning)
	}
	imported, skipped, events := res.Counts()
	t.Logf("imported %d, skipped %d, events %d", imported, skipped, events)
	ev, err := s.CaseEvidence(context.Background(), "inc-1")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ev {
		if err := s.VerifyCustody(context.Background(), e.ID); err != nil {
			t.Errorf("%s: %v", e.Name, err)
		}
	}
	// What was recognized: kinds, and programs left as generic syslog.
	evs, total, err := s.Events(context.Background(), "inc-1", store.EventFilter{Limit: store.MaxEventPage})
	if err != nil {
		t.Fatal(err)
	}
	kinds, generic, clients := map[string]int{}, map[string]int{}, map[string]int{}
	for off := 0; off < total; off += store.MaxEventPage {
		page, _, err := s.Events(context.Background(), "inc-1", store.EventFilter{Limit: store.MaxEventPage, Offset: off})
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range page {
			kinds[e.Source+" "+e.Kind]++
			if e.Kind == "http-request" {
				clients[e.SrcIP+" "+e.Fields["user_agent"]]++
			}
			if e.Source == "wtmp" {
				t.Logf("wtmp %s %-8s user=%s tty=%s ip=%s host=%s", e.Time.Format("2006-01-02 15:04:05Z"), e.Kind, e.User, e.Fields["tty"], e.SrcIP, e.Fields["remote_host"])
			}
			if e.Kind == "syslog" && e.Source == "auth.log" {
				generic[e.Provider]++
			}
		}
	}
	_ = evs
	for k, n := range kinds {
		t.Logf("kind %-40s %d", k, n)
	}
	for c, n := range clients {
		t.Logf("http client %-60s %d", c, n)
	}
	for p, n := range generic {
		t.Logf("generic auth.log program %-24s %d", p, n)
	}
}
