package detect

import (
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ciruzz00/astro/internal/logs"
	"github.com/ciruzz00/astro/internal/logs/bodyfile"
)

// Rules on filesystem timelines (bodyfile events).
const (
	// installGrace is the time after the root folder was created during
	// which setup and first-boot changes to persistence places are expected.
	installGrace = time.Hour
	// stagingWindow links an archive tool to a transfer tool used after it.
	stagingWindow = 30 * time.Minute
	// bulkWindow and bulkThreshold define many user files read at once.
	bulkWindow    = 10 * time.Second
	bulkThreshold = 100
)

var (
	ruleHiddenExec = Rule{"fs-exec-hidden", "Executable file created in a temporary or hidden folder", logs.Medium, "T1564.001"}
	ruleStaging    = Rule{"fs-archive-then-transfer", "Archive tool followed by a transfer tool (staging and exfiltration)", logs.High, "T1560.001"}
	ruleBulkRead   = Rule{"fs-bulk-read", "Many user files read at once (archiving or copying)", logs.Medium, "T1119"}

	// persistencePlaces are files that make code run later: changing one
	// after the system was installed deserves a look.
	persistencePlaces = []struct {
		re   *regexp.Regexp
		rule Rule
	}{
		{regexp.MustCompile(`^/etc/apt/apt\.conf\.d/`), Rule{"fs-apt-config", "APT configuration added or changed (package manager hooks)", logs.Medium, "T1546.016"}},
		{regexp.MustCompile(`^/etc/(crontab$|cron\.(d|hourly|daily|weekly|monthly)/)|^/var/spool/cron/`), Rule{"fs-cron", "Scheduled job file added or changed", logs.Medium, "T1053.003"}},
		{regexp.MustCompile(`^/(etc|lib|usr/lib)/systemd/(system|user)/[^/.][^/]*\.(service|timer|socket|path)$|/\.config/systemd/user/`), Rule{"fs-systemd-unit", "Systemd unit added or changed", logs.Medium, "T1543.002"}},
		{regexp.MustCompile(`/\.ssh/authorized_keys2?$`), Rule{"fs-ssh-keys", "SSH authorized keys added or changed", logs.Medium, "T1098.004"}},
		{regexp.MustCompile(`^/etc/ld\.so\.preload$`), Rule{"fs-ld-preload", "Library preload file changed", logs.High, "T1574.006"}},
		{regexp.MustCompile(`^/etc/(profile\.d/|profile$|bash\.bashrc$|zsh/zshrc$)|^/(root|home/[^/]+)/\.(bashrc|profile|bash_profile|bash_login|zshrc|zprofile)$`), Rule{"fs-shell-startup", "Shell start-up file changed", logs.Low, "T1546.004"}},
		{regexp.MustCompile(`^/etc/(rc\.local$|init\.d/)`), Rule{"fs-init-script", "Start-up script added or changed", logs.Medium, "T1037.004"}},
		{regexp.MustCompile(`^/(etc|lib|usr/lib)/udev/rules\.d/`), Rule{"fs-udev-rule", "Udev rule added or changed", logs.Medium, "T1546.017"}},
		{regexp.MustCompile(`^/etc/sudoers(\.d/|$)`), Rule{"fs-sudoers", "Sudo rules changed", logs.High, "T1548.003"}},
		{regexp.MustCompile(`^/etc/pam\.d/|/security/pam_[^/]+\.so$`), Rule{"fs-pam", "PAM configuration or module changed", logs.High, "T1556.003"}},
		// Packages keep their old dates, so a new date here is a file put in
		// place by hand, often under a name that looks like a system tool.
		{regexp.MustCompile(`^/(usr/)?s?bin/[^/]+$`), Rule{"fs-system-binary", "File added to a system binary folder outside the package manager", logs.High, "T1036.005"}},
	}

	reArchiveTool  = regexp.MustCompile(`^/(usr/)?(local/)?bin/(zip|7z|7za|7zr|rar|tar)$`)
	reTransferTool = regexp.MustCompile(`^/(usr/)?(local/)?bin/(curl|wget|scp|sftp|nc|ncat|netcat|socat|rsync|rclone|ftp|lftp|smbclient)$`)
	reTempPlace    = regexp.MustCompile(`^/(tmp|var/tmp|dev/shm)/`)
	reUserData     = regexp.MustCompile(`^/(home/[^/]+|root|srv|var/www)/`)
)

// systemRoots are created when the system is installed.
var systemRoots = map[string]bool{"/": true, "/etc": true, "/usr": true, "/var": true}

// usualHidden are hidden folders of tools and projects that hold
// executables on purpose.
var usualHidden = map[string]bool{
	".git": true, ".venv": true, ".bin": true, ".github": true, ".husky": true, ".idea": true, ".vscode": true,
	".tox": true, ".nox": true, ".mypy_cache": true, ".pytest_cache": true, ".terraform": true, ".next": true,
	".nuxt": true, ".svelte-kit": true, ".angular": true, ".yarn": true, ".pnpm-store": true, ".cargo": true,
	".rustup": true, ".nvm": true, ".pyenv": true, ".rbenv": true, ".local": true, ".npm": true, ".gradle": true,
	".m2": true, ".conda": true, ".deno": true, ".bun": true, ".gem": true, ".dotnet": true, ".vscode-server": true,
	".cursor-server": true, ".mozilla": true, ".steam": true, ".var": true, ".config": true,
}

// fileRules follow filesystem events.
type fileRules struct {
	installed   time.Time // birth of the root folders (zero until seen)
	archive     *logs.Event
	staging     *builder
	bulk        map[string]*bulkState
	persistence map[string]bool
}

type bulkState struct {
	win     window
	pending []logs.Event
	b       *builder
}

func newFileRules() *fileRules { return &fileRules{bulk: map[string]*bulkState{}} }

func isFileEvent(e *logs.Event) bool {
	switch e.Kind {
	case bodyfile.KindCreated, bodyfile.KindModified, bodyfile.KindChanged, bodyfile.KindAccessed:
		return e.Fields["path"] != ""
	}
	return false
}

func (r *fileRules) observe(e *logs.Event, en *Engine) {
	if !isFileEvent(e) {
		return
	}
	p, mode := e.Fields["path"], e.Fields["mode"]
	if r.installed.IsZero() && e.Kind == bodyfile.KindCreated && systemRoots[p] {
		r.installed = e.Time
	}
	dir := strings.HasPrefix(mode, "d")

	if e.Kind == bodyfile.KindCreated && !dir && executable(mode) && hiddenOrTemp(p) {
		en.hit(ruleHiddenExec, strings.ToLower(e.Host)+"|"+path.Dir(p), e, p)
	}
	// Package files keep the dates of the package, older than the system:
	// only changes after the installation count.
	if !dir && e.Kind != bodyfile.KindAccessed && !r.installed.IsZero() && e.Time.After(r.installed.Add(installGrace)) &&
		!r.packaged(e) {
		for _, pp := range persistencePlaces {
			if pp.re.MatchString(p) {
				en.hit(pp.rule, strings.ToLower(e.Host)+"|"+p, e, e.Fields["macb"]+" "+p)
				break
			}
		}
	}
	// An access time is the first use of the day (relatime): installing a
	// tool is not using it.
	if e.Kind == bodyfile.KindAccessed && !dir {
		r.tools(e, en)
		r.bulkRead(e, en)
	}
}

// packaged reports a file whose content is older than the system: written
// by a package install or upgrade, which keeps the dates of the package.
// Units that snapd generates for its snaps are skipped as well.
func (r *fileRules) packaged(e *logs.Event) bool {
	if strings.HasPrefix(path.Base(e.Fields["path"]), "snap.") && strings.Contains(e.Fields["path"], "/systemd/") {
		return true
	}
	m, err := strconv.ParseInt(e.Fields["mtime"], 10, 64)
	return err == nil && m > 0 && time.Unix(m, 0).Before(r.installed)
}

// tools links the use of an archive tool to a transfer tool soon after.
func (r *fileRules) tools(e *logs.Event, en *Engine) {
	p := e.Fields["path"]
	switch {
	case reArchiveTool.MatchString(p):
		ev := *e
		r.archive = &ev
	case reTransferTool.MatchString(p) && r.archive != nil && e.Time.Sub(r.archive.Time) <= stagingWindow:
		archive, transfer := *r.archive, *e
		if r.staging == nil {
			r.staging = en.hit(ruleStaging, strings.ToLower(e.Host), &archive, "")
			r.staging.detail = func(b *builder) string {
				return fmt.Sprintf("%s was first used at %s and %s %s later: data is often packed and then sent out this way.",
					path.Base(archive.Fields["path"]), archive.Time.Format(time.DateTime), path.Base(transfer.Fields["path"]), transfer.Time.Sub(archive.Time).Round(time.Second))
			}
		}
		en.hit(ruleStaging, strings.ToLower(e.Host), e, "")
	}
}

// bulkRead flags many files of one user folder read within seconds.
func (r *fileRules) bulkRead(e *logs.Event, en *Engine) {
	p := e.Fields["path"]
	m := reUserData.FindString(p)
	if m == "" {
		return
	}
	// Group by the folder below the home: /home/alice/Documents.
	key := m
	if rest := strings.TrimPrefix(p, m); strings.Contains(rest, "/") {
		key += rest[:strings.IndexByte(rest, '/')]
	}
	s := r.bulk[key]
	if s == nil {
		s = &bulkState{win: window{span: bulkWindow}}
		r.bulk[key] = s
	}
	n := s.win.add(e.Time, 1)
	switch {
	case s.b != nil && n > 1:
		en.hit(ruleBulkRead, strings.ToLower(e.Host)+"|"+key, e, "")
	case n >= bulkThreshold:
		for i := range s.pending {
			s.b = en.hit(ruleBulkRead, strings.ToLower(e.Host)+"|"+key, &s.pending[i], "")
		}
		s.pending = nil
		s.b = en.hit(ruleBulkRead, strings.ToLower(e.Host)+"|"+key, e, "")
		folder := key
		s.b.detail = func(b *builder) string {
			return fmt.Sprintf("%d files under %s read between %s and %s, as when a folder is archived or copied.",
				b.f.Count, folder, b.f.First.Format(time.DateTime), b.f.Last.Format(time.DateTime))
		}
	default:
		if n == 1 {
			s.b = nil
		}
		// Keep only the reads still inside the window.
		cut := 0
		for cut < len(s.pending) && e.Time.Sub(s.pending[cut].Time) > bulkWindow {
			cut++
		}
		s.pending = s.pending[cut:]
		if len(s.pending) < bulkThreshold {
			s.pending = append(s.pending, *e)
		}
	}
}

// executable reports an execute bit in a mode string (-rwxr-xr-x).
func executable(mode string) bool {
	if len(mode) < 10 || mode[0] != '-' {
		return false
	}
	return strings.ContainsAny(mode[1:10], "xst")
}

// hiddenOrTemp reports files in temporary folders, files with a hidden
// name, and files in hidden folders nested inside a home or project tree.
func hiddenOrTemp(p string) bool {
	if reTempPlace.MatchString(p) || strings.HasPrefix(path.Base(p), ".") {
		return true
	}
	parts := strings.Split(strings.Trim(path.Dir(p), "/"), "/")
	for i, c := range parts {
		if !strings.HasPrefix(c, ".") || usualHidden[c] {
			continue
		}
		// The hidden folders right in a home are the user's settings.
		if (i == 2 && parts[0] == "home") || (i == 1 && parts[0] == "root") {
			continue
		}
		return true
	}
	return false
}
