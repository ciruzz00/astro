//go:build private

package detect

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ciruzz00/astro/internal/evidence"
	"github.com/ciruzz00/astro/internal/logs"
	"github.com/ciruzz00/astro/internal/store"
)

// TestPrivateCorpus imports $ASTRO_PRIVATE_CORPUS (data that never enters
// the repository), runs the rules and prints the findings. Run with
// -tags private -v.
func TestPrivateCorpus(t *testing.T) {
	dir := os.Getenv("ASTRO_PRIVATE_CORPUS")
	if dir == "" {
		t.Skip("ASTRO_PRIVATE_CORPUS not set")
	}
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "astro.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.CreateCase(ctx, store.Case{Name: "corpus", TLP: "RED"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	res, err := evidence.New(st, evidence.DefaultParsers()...).Import(ctx, "corpus", dir, evidence.Options{})
	if err != nil {
		t.Fatal(err)
	}
	_, _, events := res.Counts()
	start := time.Now()
	out, err := Analyze(ctx, st, "corpus", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d events, %d findings in %v", events, len(out.Findings), time.Since(start).Round(time.Millisecond))
	for _, f := range out.Findings {
		t.Logf("%-8s %-32s %-10s n=%-5d %s→%s host=%s user=%s ip=%s\n        %s", f.Severity, f.RuleID, f.Technique, f.Count,
			f.First.Format(time.DateTime), f.Last.Format(time.TimeOnly), f.Host, f.User, f.SrcIP, logs.Truncate(f.Summary, 240))
	}
}
