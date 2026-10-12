package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Limits on what the browser may upload in one import.
const (
	maxUploadBytes = 8 << 30
	maxUploadFiles = 100000
	maxFieldBytes  = 4 << 10
	maxDatesBytes  = 16 << 20 // JSON of the file dates of a large folder
	uploadDeadline = time.Hour
)

type upload struct {
	dir    string
	files  int
	fields map[string]string
}

// receiveUpload streams the files of a multipart import to a new folder
// under the upload directory, keeping the relative paths a folder upload
// sends. Names come from the browser and are untrusted: they are cleaned
// so nothing is written outside that folder, and nothing is overwritten.
func (s *server) receiveUpload(w http.ResponseWriter, r *http.Request, caseName string) (up upload, err error) {
	if s.UploadDir == "" {
		return up, errors.New("uploads are not enabled")
	}
	// The server timeouts suit forms, not gigabytes of logs.
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Now().Add(uploadDeadline))
	_ = rc.SetWriteDeadline(time.Now().Add(uploadDeadline))
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes)
	mr, err := r.MultipartReader()
	if err != nil {
		return up, err
	}
	// Every write goes through os.Root: nothing can land outside the upload
	// folder, whatever the names (cleaned below) or symbolic links say.
	if err := os.MkdirAll(s.UploadDir, 0o700); err != nil {
		return up, err
	}
	base, err := os.OpenRoot(s.UploadDir)
	if err != nil {
		return up, err
	}
	defer base.Close()
	sub := filepath.Join(caseName, s.now().UTC().Format("20060102T150405.000Z"))
	if err := base.MkdirAll(sub, 0o700); err != nil {
		return up, err
	}
	root, err := base.OpenRoot(sub)
	if err != nil {
		return up, err
	}
	defer root.Close()
	up.dir = filepath.Join(s.UploadDir, sub)
	defer func() {
		if err != nil || up.files == 0 {
			_ = base.RemoveAll(sub)
			up.dir = ""
		}
	}()
	up.fields = map[string]string{}
	var saved []string
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			applyDates(root, saved, up.fields["dates"])
			return up, nil
		}
		if err != nil {
			var tooBig *http.MaxBytesError
			if errors.As(err, &tooBig) {
				return up, fmt.Errorf("more than %d GiB", maxUploadBytes>>30)
			}
			return up, err
		}
		if part.FileName() == "" {
			limit := int64(maxFieldBytes)
			if part.FormName() == "dates" {
				limit = maxDatesBytes
			}
			b, err := io.ReadAll(io.LimitReader(part, limit))
			if err != nil {
				return up, err
			}
			up.fields[part.FormName()] = string(b)
			continue
		}
		rel := uploadPath(part.Header.Get("Content-Disposition"))
		if rel == "" {
			continue
		}
		if up.files >= maxUploadFiles {
			return up, fmt.Errorf("more than %d files", maxUploadFiles)
		}
		if err := saveUpload(root, rel, part); err != nil {
			return up, err
		}
		saved = append(saved, rel)
		up.files++
	}
}

// applyDates gives the saved copies the modification times the browser
// reported (JSON: relative name → milliseconds since 1970), so the year of
// syslog lines is inferred from the original dates, not the upload time.
func applyDates(root *os.Root, saved []string, raw string) {
	if raw == "" {
		return
	}
	var dates map[string]int64
	if json.Unmarshal([]byte(raw), &dates) != nil {
		return
	}
	byPath := make(map[string]time.Time, len(dates))
	for name, ms := range dates {
		if rel := cleanUploadName(name); rel != "" && ms > 0 {
			byPath[rel] = time.UnixMilli(ms)
		}
	}
	for _, rel := range saved {
		if t, ok := byPath[rel]; ok {
			_ = root.Chtimes(rel, t, t)
		}
	}
}

// uploadPath extracts the file name a browser sent (with its folders for
// folder uploads) and cleans it into a relative path, or "" if nothing
// usable is left. Go's Part.FileName drops the folders, hence the parsing.
func uploadPath(disposition string) string {
	_, params, err := mime.ParseMediaType(disposition)
	if err != nil {
		return ""
	}
	return cleanUploadName(params["filename"])
}

// cleanUploadName turns a name sent by a browser into a safe relative path.
func cleanUploadName(name string) string {
	var parts []string
	for _, p := range strings.FieldsFunc(name, func(r rune) bool { return r == '/' || r == '\\' }) {
		p = strings.TrimSpace(p)
		if p == "" || p == "." || p == ".." || strings.ContainsRune(p, 0) || strings.Contains(p, ":") {
			continue
		}
		parts = append(parts, p)
	}
	if len(parts) == 0 || len(parts) > 64 {
		return ""
	}
	rel := filepath.Join(parts...)
	if len(rel) > 1024 || !filepath.IsLocal(rel) {
		return ""
	}
	return rel
}

func saveUpload(root *os.Root, rel string, src io.Reader) error {
	if dir := filepath.Dir(rel); dir != "." {
		if err := root.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	f, err := root.OpenFile(rel, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, src); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
