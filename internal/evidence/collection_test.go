package evidence

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
	_ "time/tzdata" // the zone database may be missing in minimal images

	"github.com/ciruzz00/astro/internal/logs/syslog"
	"github.com/ciruzz00/astro/internal/store"
)

func TestCollectionTimeZone(t *testing.T) {
	st, _, dir := setup(t)
	im := New(st, syslog.New())
	ctx := context.Background()
	col := filepath.Join(dir, "uac-web01")
	write(t, filepath.Join(col, "[root]", "etc", "timezone"), []byte("Asia/Tokyo\n"))
	auth := filepath.Join(col, "[root]", "var", "log", "auth.log")
	write(t, auth, []byte("Apr  7 21:15:40 web01 login[5]: ROOT LOGIN  on '/dev/pts/7' from '203.0.113.9'\n"))
	mtime := time.Date(2026, 4, 8, 0, 0, 0, 0, time.UTC)
	if err := os.Chtimes(auth, mtime, mtime); err != nil {
		t.Fatal(err)
	}

	res, err := im.Import(ctx, "inc-1", col, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.TimeZone != "Asia/Tokyo" || filepath.Base(res.TimeZoneFrom) != "timezone" {
		t.Fatalf("zone = %q from %q", res.TimeZone, res.TimeZoneFrom)
	}
	evs, _, err := st.Events(ctx, "inc-1", store.EventFilter{})
	if err != nil || len(evs) != 1 {
		t.Fatalf("events: %v %v", evs, err)
	}
	// 21:15:40 in Tokyo (UTC+9) is 12:15:40 UTC.
	if want := time.Date(2026, 4, 7, 12, 15, 40, 0, time.UTC); !evs[0].Time.Equal(want) {
		t.Errorf("event time %v, want %v", evs[0].Time, want)
	}

	// A file inside the collection finds the zone too; an explicit zone wins.
	write(t, filepath.Join(col, "[root]", "var", "log", "syslog"), []byte("Apr  7 21:16:00 web01 cron[6]: (root) CMD (true)\n"))
	res, err = im.Import(ctx, "inc-1", filepath.Join(col, "[root]", "var", "log", "syslog"), Options{})
	if err != nil || res.TimeZone != "Asia/Tokyo" {
		t.Errorf("single file: %q %v", res.TimeZone, err)
	}
	res, err = im.Import(ctx, "inc-1", col, Options{Location: time.UTC})
	if err != nil || res.TimeZone != "" {
		t.Errorf("explicit zone overridden: %q %v", res.TimeZone, err)
	}
}

func TestCollectionTimeZoneIgnoresBadFiles(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		"garbage":  "../../etc/passwd\n",
		"unknown":  "Mars/Olympus_Mons\n",
		"empty":    "",
		"tooLong:": "Europe/" + string(make([]byte, 300)),
	} {
		col := filepath.Join(dir, name)
		write(t, filepath.Join(col, "etc", "timezone"), []byte(content))
		if loc, _ := collectionZone(col, true); loc != nil {
			t.Errorf("%s: zone %v accepted", name, loc)
		}
	}
	// A symbolic link is not followed.
	target := filepath.Join(dir, "real")
	write(t, target, []byte("Europe/Rome\n"))
	col := filepath.Join(dir, "linked")
	if err := os.MkdirAll(filepath.Join(col, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(col, "etc", "timezone")); err != nil {
		t.Skip("symbolic links not supported:", err)
	}
	if loc, _ := collectionZone(col, true); loc != nil {
		t.Errorf("zone read through a symbolic link: %v", loc)
	}
}
