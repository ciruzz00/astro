package evidence

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// reZoneName accepts IANA zone names (UTC, Europe/Rome, America/Argentina/Salta).
var reZoneName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_+-]{0,40}(/[A-Za-z0-9_+-]{1,40}){0,3}$`)

// collectionZone finds the time zone of the host a triage collection comes
// from, so syslog times without an offset are read correctly: etc/timezone
// under the imported folder, or under the "[root]" folder of a UAC
// collection when a folder or file inside it is imported. Links are not
// followed.
func collectionZone(abs string, isDir bool) (*time.Location, string) {
	var candidates []string
	if isDir {
		candidates = append(candidates, filepath.Join(abs, "[root]", "etc", "timezone"), filepath.Join(abs, "etc", "timezone"))
	}
	sep := string(filepath.Separator)
	if i := strings.LastIndex(abs+sep, sep+"[root]"+sep); i >= 0 {
		candidates = append(candidates, filepath.Join(abs[:i], "[root]", "etc", "timezone"))
	}
	for _, c := range candidates {
		if loc := readZone(c); loc != nil {
			return loc, c
		}
	}
	return nil, ""
}

func readZone(path string) *time.Location {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil
	}
	f, err := os.Open(path) // #nosec G304 -- a fixed name inside the folder the analyst chose to import
	if err != nil {
		return nil
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 256))
	if err != nil {
		return nil
	}
	if i := bytes.IndexByte(b, '\n'); i >= 0 {
		b = b[:i]
	}
	name := strings.TrimSpace(string(b))
	if !reZoneName.MatchString(name) {
		return nil
	}
	loc, err := time.LoadLocation(name)
	if err != nil {
		return nil
	}
	return loc
}
