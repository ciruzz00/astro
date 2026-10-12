// Package evidence imports log files into a case: it reads them where they
// are (never copies or modifies them), hashes them, records the chain of
// custody and stores the events parsed from them.
package evidence

import (
	"compress/gzip"
	"context"
	"crypto/md5"  // #nosec G501 -- evidence inventories list MD5 next to SHA-256 for tool compatibility, not for security
	"crypto/sha1" // #nosec G505 -- as above
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ciruzz00/astro/internal/logs"
	"github.com/ciruzz00/astro/internal/store"
)

// Defaults for the import limits.
const (
	DefaultMaxFileSize = 8 << 30   // 8 GiB
	DefaultMaxFiles    = 100000    // triage collections (UAC, KAPE) hold tens of thousands of files
	DefaultMaxEvents   = 5_000_000 // per file
	batchSize          = 1000
	// gzip streams may expand at most this much (and at least to minExpand),
	// so a decompression bomb cannot exhaust the disk or the time budget.
	maxExpansion = 100
	minExpand    = 1 << 30
)

// Importer reads evidence files into a case.
type Importer struct {
	store   *store.Store
	parsers map[logs.Kind]logs.Parser

	// Actor is recorded in the chain of custody.
	Actor       string
	MaxFileSize int64
	MaxFiles    int
	MaxEvents   int
	now         func() time.Time
}

// New returns an importer that uses the given parsers.
func New(s *store.Store, parsers ...logs.Parser) *Importer {
	im := &Importer{store: s, parsers: map[logs.Kind]logs.Parser{}, Actor: "analyst",
		MaxFileSize: DefaultMaxFileSize, MaxFiles: DefaultMaxFiles, MaxEvents: DefaultMaxEvents, now: time.Now}
	for _, p := range parsers {
		im.parsers[p.Kind()] = p
	}
	return im
}

// Options tune an import.
type Options struct {
	// Year and Location apply to timestamps without year or offset (syslog).
	Year     int
	Location *time.Location
	// Host overrides the host name of every event.
	Host string
	// Note is added to the first chain of custody entry of every file
	// (e.g. that it is a copy uploaded through the web interface).
	Note string
}

// FileResult is the outcome for one file.
type FileResult struct {
	Path       string        `json:"path"`
	Kind       logs.Kind     `json:"kind,omitempty"`
	EvidenceID int64         `json:"evidence_id,omitempty"`
	SHA256     string        `json:"sha256,omitempty"`
	Events     int           `json:"events"`
	Errors     int           `json:"parse_errors,omitempty"`
	Truncated  bool          `json:"truncated,omitempty"`
	Duplicate  bool          `json:"duplicate,omitempty"`
	Skipped    string        `json:"skipped,omitempty"` // reason the file was not imported
	Warning    string        `json:"warning,omitempty"`
	Duration   time.Duration `json:"duration_ns"`
}

// Imported reports whether the file was added to the case.
func (r FileResult) Imported() bool { return r.EvidenceID != 0 }

// Result lists the files met by an import, in walk order.
type Result struct {
	Files []FileResult `json:"files"`
	// Truncated reports that MaxFiles stopped the walk.
	Truncated bool `json:"truncated,omitempty"`
	// TimeZone is the zone read from the collection (etc/timezone) when
	// none was given, and TimeZoneFrom the file it was read from.
	TimeZone     string `json:"time_zone,omitempty"`
	TimeZoneFrom string `json:"time_zone_from,omitempty"`
}

// Counts returns how many files were imported and skipped, and the events stored.
func (r *Result) Counts() (imported, skipped, events int) {
	for _, f := range r.Files {
		if f.Imported() {
			imported++
			events += f.Events
		} else {
			skipped++
		}
	}
	return
}

// Import adds a file, or every recognized log file under a directory, to a
// case. Symbolic links are never followed. A file given explicitly is
// imported even if its format is unknown (it is inventoried and hashed);
// inside directories unknown files are skipped.
func (im *Importer) Import(ctx context.Context, caseName, root string, opts Options) (*Result, error) {
	caseID, err := im.store.CaseID(ctx, caseName)
	if err != nil {
		return nil, err
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return nil, err
	}
	res := &Result{}
	if opts.Location == nil {
		if loc, from := collectionZone(abs, info.IsDir()); loc != nil {
			opts.Location, res.TimeZone, res.TimeZoneFrom = loc, loc.String(), from
		}
	}
	switch {
	case info.Mode()&fs.ModeSymlink != 0:
		return nil, fmt.Errorf("%s is a symbolic link: give the path of the file it points to", root)
	case info.Mode().IsRegular():
		res.Files = append(res.Files, im.importFile(ctx, caseID, caseName, abs, info, true, opts))
		return res, nil
	case !info.IsDir():
		return nil, fmt.Errorf("%s is not a regular file or a directory", root)
	}

	files := 0
	err = filepath.WalkDir(abs, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			res.Files = append(res.Files, FileResult{Path: path, Skipped: cleanErr(err)})
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		switch {
		case d.Type()&fs.ModeSymlink != 0:
			res.Files = append(res.Files, FileResult{Path: path, Skipped: "symbolic link not followed"})
			return nil
		case d.IsDir():
			return nil
		case !d.Type().IsRegular():
			return nil // devices, sockets, pipes
		}
		if files >= im.MaxFiles {
			res.Truncated = true
			return fs.SkipAll
		}
		files++
		info, err := d.Info()
		if err != nil {
			res.Files = append(res.Files, FileResult{Path: path, Skipped: cleanErr(err)})
			return nil
		}
		res.Files = append(res.Files, im.importFile(ctx, caseID, caseName, path, info, false, opts))
		return nil
	})
	return res, err
}

func (im *Importer) importFile(ctx context.Context, caseID int64, caseName, path string, info fs.FileInfo, explicit bool, opts Options) (r FileResult) {
	start := im.now()
	r.Path = path
	defer func() { r.Duration = im.now().Sub(start) }()

	if info.Size() > im.MaxFileSize {
		r.Skipped = fmt.Sprintf("larger than the %d MiB limit", im.MaxFileSize>>20)
		return r
	}
	f, err := os.Open(path) // #nosec G304 -- the analyst chooses which evidence to read; it is opened read-only
	if err != nil {
		r.Skipped = cleanErr(err)
		return r
	}
	defer f.Close()
	// The file must still be the one met during the walk (no swap for a link).
	if cur, err := f.Stat(); err != nil || !os.SameFile(info, cur) || !cur.Mode().IsRegular() {
		r.Skipped = "file changed while importing"
		return r
	}

	head, compressed, err := readHead(f)
	if err != nil {
		r.Skipped = cleanErr(err)
		return r
	}
	r.Kind = logs.Detect(path, head)
	if r.Kind == logs.KindUnknown && !explicit {
		r.Skipped = "not a recognized log format"
		return r
	}

	sums, err := hashFile(f, im.MaxFileSize)
	if err != nil {
		r.Skipped = cleanErr(err)
		return r
	}
	r.SHA256 = sums.sha256
	ev := store.Evidence{Path: path, Name: filepath.Base(path), Kind: r.Kind, Compressed: compressed,
		Size: sums.size, ModTime: info.ModTime().UTC(), SHA256: sums.sha256, SHA1: sums.sha1, MD5: sums.md5, Host: opts.Host}
	detail := fmt.Sprintf("read in place; size %d; sha256 %s; sha1 %s; md5 %s; mtime %s",
		sums.size, sums.sha256, sums.sha1, sums.md5, info.ModTime().UTC().Format(time.RFC3339))
	if opts.Note != "" {
		detail += "; " + opts.Note
	}
	id, err := im.store.AddEvidence(ctx, caseName, ev, im.Actor, detail, im.now().UTC())
	if errors.Is(err, store.ErrExists) {
		r.Duplicate, r.Skipped = true, "already in the case (same SHA-256)"
		return r
	}
	if err != nil {
		r.Skipped = err.Error()
		return r
	}
	r.EvidenceID = id

	p := im.parsers[r.Kind]
	if p == nil {
		r.Warning = "inventoried and hashed only: no parser for this format"
		return r
	}
	host, err := im.parse(ctx, p, f, compressed, caseID, id, sums, info, opts, &r)
	if err != nil {
		r.Warning = "parsing stopped: " + cleanErr(err)
	}
	if err := im.store.FinishEvidence(ctx, id, host, r.Errors, r.Truncated); err != nil && r.Warning == "" {
		r.Warning = err.Error()
	}
	action, note := store.CustodyParsed, fmt.Sprintf("parser %s: %d events, %d unparsable entries", r.Kind, r.Events, r.Errors)
	if r.Truncated {
		note += ", stopped at the event limit"
	}
	if strings.HasPrefix(r.Warning, "content changed") {
		action, note = store.CustodyChanged, r.Warning
	}
	if err := im.store.AppendCustody(ctx, id, action, im.Actor, note, im.now().UTC()); err != nil && r.Warning == "" {
		r.Warning = err.Error()
	}
	return r
}

// parse streams the file through the parser in batches while hashing it
// again, to prove the parsed content is the hashed one.
func (im *Importer) parse(ctx context.Context, p logs.Parser, f *os.File, compressed bool, caseID, evidenceID int64,
	sums sums, info fs.FileInfo, opts Options, r *FileResult) (string, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	check := sha256.New()
	var in io.Reader = io.TeeReader(io.LimitReader(f, im.MaxFileSize), check)
	if compressed {
		gz, err := gzip.NewReader(in)
		if err != nil {
			return "", err
		}
		defer gz.Close()
		in = io.LimitReader(gz, max(sums.size*maxExpansion, minExpand))
	}

	source := strings.TrimSuffix(filepath.Base(f.Name()), ".gz")
	popts := logs.Options{Year: opts.Year, Location: opts.Location, Host: opts.Host, Source: source, Path: f.Name(),
		ModTime: info.ModTime(), MaxEvents: im.MaxEvents}
	ref := logs.EvidenceRef{EvidenceID: evidenceID, Path: f.Name(), SHA256: sums.sha256}
	host := opts.Host
	var batch []*logs.Event
	var seq int64
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		err := im.store.InsertEvents(ctx, caseID, evidenceID, batch)
		batch = batch[:0]
		return err
	}
	emit := func(e *logs.Event) error {
		if im.MaxEvents > 0 && r.Events >= im.MaxEvents {
			r.Truncated = true
			return logs.ErrLimit
		}
		seq++
		e.Seq, e.Time = seq, e.Time.UTC()
		e.Ref.EvidenceID, e.Ref.Path, e.Ref.SHA256 = ref.EvidenceID, ref.Path, ref.SHA256
		if e.Source == "" {
			e.Source = source
		}
		if opts.Host != "" {
			e.Host = opts.Host
		} else if host == "" {
			host = e.Host
		}
		batch = append(batch, e)
		r.Events++
		if len(batch) >= batchSize {
			return flush()
		}
		return nil
	}
	st, err := p.Parse(ctx, in, popts, emit)
	r.Errors = st.Errors
	if st.Truncated || errors.Is(err, logs.ErrLimit) {
		r.Truncated, err = true, nil
	}
	if ferr := flush(); err == nil {
		err = ferr
	}
	if err != nil {
		return host, err
	}
	// Hash whatever the parser did not read, then compare.
	if _, err := io.Copy(check, io.LimitReader(f, im.MaxFileSize)); err != nil {
		return host, err
	}
	if got := hex.EncodeToString(check.Sum(nil)); got != sums.sha256 {
		r.Warning = "content changed during the import: sha256 now " + got
	}
	return host, nil
}

// readHead returns the first bytes of the file, decompressed if it is gzip.
func readHead(f *os.File) ([]byte, bool, error) {
	head := make([]byte, logs.HeadSize)
	n, err := io.ReadFull(f, head)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return nil, false, err
	}
	head = head[:n]
	if !logs.IsGzip(head) {
		return head, false, nil
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, false, err
	}
	gz, err := gzip.NewReader(f)
	if err != nil {
		return head, false, nil // not really gzip: detect on the raw bytes
	}
	defer gz.Close()
	dec := make([]byte, logs.HeadSize)
	n, err = io.ReadFull(gz, dec)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return nil, true, fmt.Errorf("corrupt gzip stream: %w", err)
	}
	return dec[:n], true, nil
}

type sums struct {
	size              int64
	sha256, sha1, md5 string
}

func hashFile(f *os.File, limit int64) (sums, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return sums{}, err
	}
	h256, h1, h5 := sha256.New(), sha1.New(), md5.New() // #nosec G401 -- see the imports
	n, err := io.Copy(io.MultiWriter(h256, h1, h5), io.LimitReader(f, limit+1))
	if err != nil {
		return sums{}, err
	}
	if n > limit {
		return sums{}, fmt.Errorf("larger than the %d MiB limit", limit>>20)
	}
	hx := func(h hash.Hash) string { return hex.EncodeToString(h.Sum(nil)) }
	return sums{size: n, sha256: hx(h256), sha1: hx(h1), md5: hx(h5)}, nil
}

// cleanErr drops the path that os errors repeat (it is already in the result).
func cleanErr(err error) string {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Op + ": " + pe.Err.Error()
	}
	return err.Error()
}
