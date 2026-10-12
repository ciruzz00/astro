//go:build private

package evtx

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ciruzz00/astro/internal/logs"
)

// TestPrivateSamples parses every .evtx file under $ASTRO_EVTX_SAMPLES
// (real event logs that never enter the repository) and prints what was
// read. Run with -tags private -v.
func TestPrivateSamples(t *testing.T) {
	dir := os.Getenv("ASTRO_EVTX_SAMPLES")
	if dir == "" {
		t.Skip("ASTRO_EVTX_SAMPLES not set")
	}
	if os.Getenv("ASTRO_EVTX_DEBUG") != "" {
		debugf = t.Logf
		defer func() { debugf = nil }()
	}
	files, _ := filepath.Glob(filepath.Join(dir, os.Getenv("ASTRO_EVTX_GLOB")+"*.evtx"))
	sort.Strings(files)
	for _, path := range files {
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		show := map[int]int{}
		for _, id := range strings.Split(os.Getenv("ASTRO_EVTX_SHOW"), ",") {
			if n, err := strconv.Atoi(id); err == nil {
				show[n] = 1
			}
		}
		ids := map[int]int{}
		recs := map[string]int{}
		dups := 0

		var first *logs.Event
		noTime, noID := 0, 0
		start := time.Now()
		st, err := New().Parse(context.Background(), f, logs.Options{Source: filepath.Base(path)}, func(e *logs.Event) error {
			if first == nil {
				first = e
			}
			if show[e.EventID] > 0 {
				show[e.EventID]--
				t.Logf("  %s %d [%s] host=%s user=%q src=%q dst=%q proc=%q parent=%q cmd=%q sev=%s\n     msg=%s",
					e.Time.Format(time.RFC3339), e.EventID, e.Provider, e.Host, e.User, e.SrcIP, e.DstIP, e.Process, e.Parent,
					logs.Truncate(e.CommandLine, 100), e.Severity, logs.Truncate(e.Message, 220))
			}
			ids[e.EventID]++
			if recs[e.Fields["record_id"]]++; recs[e.Fields["record_id"]] > 1 {
				dups++
			}
			if e.Time.Year() < 2000 {
				noTime++
			}
			if e.EventID == 0 && e.Provider == "" {
				noID++
			}
			return nil
		})
		_ = f.Close()
		t.Logf("%-90s events %6d errors %3d ids %4d bad-time %d no-id %d dup-records %d %v err=%v",
			filepath.Base(path), st.Events, st.Errors, len(ids), noTime, noID, dups, time.Since(start).Round(time.Millisecond), err)
		if first != nil && os.Getenv("ASTRO_EVTX_VERBOSE") != "" {
			t.Logf("  first: %s %d %s host=%s user=%s ip=%s msg=%s", first.Time.Format(time.RFC3339), first.EventID, first.Provider,
				first.Host, first.User, first.SrcIP, strings.ReplaceAll(logs.Truncate(first.Message, 160), "\n", " "))
		}
	}
}
