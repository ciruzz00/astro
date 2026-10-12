package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
	_ "time/tzdata" // --tz works on systems without a zone database (Windows, minimal images)

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/ciruzz00/astro/internal/detect"
	"github.com/ciruzz00/astro/internal/evidence"
	"github.com/ciruzz00/astro/internal/logs"
	"github.com/ciruzz00/astro/internal/render"
	"github.com/ciruzz00/astro/internal/store"
)

func newLogsCmd(g *globalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "logs",
		Short: "Analyze log files: evidence, timeline and findings",
		Long: `Import logs into a case, read the timeline and the findings of the detection
rules. Files are read where they are and never modified: each one is hashed
(SHA-256, SHA-1, MD5) and gets a chain of custody.

Supported: Windows event logs (.evtx), auth.log/secure/syslog, wtmp/btmp/utmp,
bash and zsh history, web access logs and Docker container logs, also
compressed (.gz). Times are shown in UTC; "~" marks a guessed year and "?" a
command without a timestamp.

Analysis is local: nothing is sent to online sources. Indicators found in the
findings can be added to the case with --add-indicators and searched later.`,
		Example: `  astro case new sherlock-1
  astro logs import sherlock-1 ./triage/ --tz Europe/Rome
  astro logs findings sherlock-1 --events
  astro logs timeline sherlock-1 --severity high
  astro logs timeline sherlock-1 --ip 203.0.113.9 --csv > timeline.csv
  astro logs evidence sherlock-1 --custody`,
	}
	cmd.AddCommand(logsImportCmd(g), logsAnalyzeCmd(g), logsTimelineCmd(g), logsFindingsCmd(g), logsEvidenceCmd(g))
	return cmd
}

// actor is recorded in the chain of custody: --actor, $ASTRO_ANALYST or
// "analyst" (never the system user name, which would end up in reports).
func actor(flag string) string {
	for _, v := range []string{flag, os.Getenv("ASTRO_ANALYST")} {
		if v = strings.TrimSpace(v); v != "" {
			return logs.Truncate(v, 100)
		}
	}
	return "analyst"
}

// requireCase fails early, with a hint, when the case does not exist.
func requireCase(cmd *cobra.Command, a *app, name string) error {
	if _, err := a.store.CaseID(cmd.Context(), name); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("no case named %q: create it with 'astro case new %s'", name, name)
		}
		return err
	}
	return nil
}

func logsImportCmd(g *globalFlags) *cobra.Command {
	var (
		year                int
		tz, host, who       string
		noAnalyze, addIOCs  bool
		showSkipped, asJSON bool
	)
	cmd := &cobra.Command{
		Use:   "import <case> <file|dir>...",
		Short: "Import log files or folders into a case and analyze them",
		Long: `Import log files, or every recognized log under folders, into a case. Symbolic
links are not followed and files already in the case (same SHA-256) are
skipped. The detection rules run afterwards unless --no-analyze is given.

Syslog lines carry no year and often no time zone: the year is inferred from
the file modification time (use --year to force it) and times are read as UTC
unless --tz names the zone of the host (e.g. Europe/Rome).`,
		Args: cobra.MinimumNArgs(2),
		RunE: withApp(g, func(cmd *cobra.Command, a *app, args []string) error {
			ctx, name := cmd.Context(), args[0]
			if err := requireCase(cmd, a, name); err != nil {
				return err
			}
			opts := evidence.Options{Year: year, Host: host}
			if tz != "" {
				loc, err := time.LoadLocation(tz)
				if err != nil {
					return fmt.Errorf("--tz: unknown time zone %q (use names like UTC or Europe/Rome)", tz)
				}
				opts.Location = loc
			}
			if year != 0 && (year < 1970 || year > 2200) {
				return fmt.Errorf("--year: %d is not a plausible year", year)
			}
			im := evidence.New(a.store, evidence.DefaultParsers()...)
			im.Actor = actor(who)
			out, st := cmd.OutOrStdout(), style(cmd.OutOrStdout(), g)
			var all []evidence.FileResult
			for _, path := range args[1:] {
				res, err := im.Import(ctx, name, path, opts)
				if err != nil {
					return fmt.Errorf("%s: %w", path, err)
				}
				all = append(all, res.Files...)
				if res.Truncated {
					fmt.Fprintf(cmd.ErrOrStderr(), "%s: stopped at %d files\n", path, im.MaxFiles)
				}
			}
			var findings []logs.Finding
			if !noAnalyze {
				res, err := detect.Analyze(ctx, a.store, name, time.Now().UTC())
				if err != nil {
					return fmt.Errorf("analysis: %w", err)
				}
				findings = res.Findings
			}
			added := 0
			if addIOCs && len(findings) > 0 {
				n, err := a.cases.Add(ctx, name, detect.Indicators(findings), "from log analysis")
				if err != nil {
					return caseError(name, err)
				}
				added = n
			}
			if asJSON {
				return render.JSON(out, map[string]any{"files": all, "findings": findings, "indicators_added": added})
			}
			printImport(out, all, showSkipped, st)
			if !noAnalyze {
				printFindingCounts(out, name, findings, st)
			}
			if addIOCs {
				fmt.Fprintf(out, "%d new indicators added to the case (search them with 'astro case search %s')\n", added, name)
			}
			return nil
		}),
	}
	f := cmd.Flags()
	f.IntVar(&year, "year", 0, "year of syslog lines without one (default: from the file modification time)")
	f.StringVar(&tz, "tz", "", "time zone of timestamps without an offset (default UTC)")
	f.StringVar(&host, "host", "", "host name for every event (overrides the one in the logs)")
	f.StringVar(&who, "actor", "", `name recorded in the chain of custody (default $ASTRO_ANALYST or "analyst")`)
	f.BoolVar(&noAnalyze, "no-analyze", false, "import only, without running the detection rules")
	f.BoolVar(&addIOCs, "add-indicators", false, "add the indicators found in the findings to the case")
	f.BoolVar(&showSkipped, "skipped", false, "list every skipped file, including unrecognized ones")
	f.BoolVar(&asJSON, "json", false, "print the result as JSON")
	return cmd
}

func printImport(w io.Writer, files []evidence.FileResult, showSkipped bool, st render.Style) {
	imported, events, quiet := 0, 0, 0
	for _, f := range files {
		switch {
		case f.Imported():
			imported++
			events += f.Events
			line := fmt.Sprintf("%-12s %8d events  %s", f.Kind, f.Events, render.Sanitize(f.Path))
			if f.Errors > 0 {
				line += st.Severity(logs.Medium, fmt.Sprintf("  (%d unparsable)", f.Errors))
			}
			fmt.Fprintf(w, "  + %s\n", line)
			if f.Warning != "" {
				fmt.Fprintf(w, "    %s\n", st.Severity(logs.Medium, render.Sanitize(f.Warning)))
			}
		case showSkipped || (f.Skipped != "not a recognized log format" && f.Skipped != "symbolic link not followed"):
			fmt.Fprintf(w, "  - %-12s %s  %s\n", "skipped", render.Sanitize(f.Path), st.Severity(logs.Info, render.Sanitize(f.Skipped)))
		default:
			quiet++
		}
	}
	fmt.Fprintf(w, "%d files imported, %d events", imported, events)
	if quiet > 0 {
		fmt.Fprintf(w, "; %d other files skipped (not logs or symbolic links: --skipped lists them)", quiet)
	}
	fmt.Fprintln(w)
}

func printFindingCounts(w io.Writer, name string, fs []logs.Finding, st render.Style) {
	counts := map[logs.Severity]int{}
	for _, f := range fs {
		counts[f.Severity]++
	}
	var parts []string
	for sev := logs.Critical; sev >= logs.Info; sev-- {
		if counts[sev] > 0 {
			parts = append(parts, st.Severity(sev, fmt.Sprintf("%d %s", counts[sev], sev)))
		}
	}
	if len(fs) == 0 {
		fmt.Fprintln(w, "no findings")
		return
	}
	fmt.Fprintf(w, "%d findings: %s\n", len(fs), strings.Join(parts, ", "))
	shown := min(len(fs), 10)
	for _, f := range fs[:shown] {
		fmt.Fprintf(w, "  %s %s  %s\n", st.Severity(f.Severity, render.SeverityLabel(f.Severity)), render.Sanitize(f.Title),
			render.Sanitize(strings.Join(nonEmpty(f.Host, f.User, f.SrcIP), " ")))
	}
	if shown < len(fs) {
		fmt.Fprintf(w, "  … and %d more\n", len(fs)-shown)
	}
	fmt.Fprintf(w, "details: astro logs findings %s --events\n", name)
}

func nonEmpty(s ...string) []string {
	var out []string
	for _, v := range s {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

func logsAnalyzeCmd(g *globalFlags) *cobra.Command {
	var addIOCs bool
	cmd := &cobra.Command{
		Use:   "analyze <case>",
		Short: "Run the detection rules again over the whole timeline",
		Args:  cobra.ExactArgs(1),
		RunE: withApp(g, func(cmd *cobra.Command, a *app, args []string) error {
			ctx, name := cmd.Context(), args[0]
			if err := requireCase(cmd, a, name); err != nil {
				return err
			}
			res, err := detect.Analyze(ctx, a.store, name, time.Now().UTC())
			if err != nil {
				return err
			}
			out, st := cmd.OutOrStdout(), style(cmd.OutOrStdout(), g)
			printFindingCounts(out, name, res.Findings, st)
			if addIOCs {
				n, err := a.cases.Add(ctx, name, detect.Indicators(res.Findings), "from log analysis")
				if err != nil {
					return caseError(name, err)
				}
				fmt.Fprintf(out, "%d new indicators added to the case\n", n)
			}
			return nil
		}),
	}
	cmd.Flags().BoolVar(&addIOCs, "add-indicators", false, "add the indicators found in the findings to the case")
	return cmd
}

// timeFlag parses --from/--to: RFC 3339, "YYYY-MM-DD hh:mm:ss" or a date, in UTC.
func timeFlag(name, v string) (time.Time, error) {
	if v == "" {
		return time.Time{}, nil
	}
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04:05", "2006-01-02T15:04:05", "2006-01-02 15:04", "2006-01-02"} {
		if t, err := time.Parse(layout, v); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("--%s: use 2026-10-11, \"2026-10-11 21:00:00\" or RFC 3339 (times are UTC)", name)
}

func logsTimelineCmd(g *globalFlags) *cobra.Command {
	var (
		sev, from, to          string
		f                      store.EventFilter
		asJSON, asCSV, noTrunc bool
	)
	cmd := &cobra.Command{
		Use:   "timeline <case>",
		Short: "Show the events of a case in time order",
		Long: `Show the events of a case in time order, in UTC. Critical events are red,
high orange, medium yellow, low blue. Filters combine; --limit and --offset page
through long timelines (--csv and --json export them).`,
		Args: cobra.ExactArgs(1),
		RunE: withApp(g, func(cmd *cobra.Command, a *app, args []string) error {
			ctx, name := cmd.Context(), args[0]
			if err := requireCase(cmd, a, name); err != nil {
				return err
			}
			var err error
			if sev != "" {
				if f.MinSeverity, err = logs.ParseSeverity(sev); err != nil {
					return fmt.Errorf("--severity: %w", err)
				}
			}
			if f.From, err = timeFlag("from", from); err != nil {
				return err
			}
			if f.To, err = timeFlag("to", to); err != nil {
				return err
			}
			if f.Limit <= 0 || f.Limit > store.MaxEventPage {
				return fmt.Errorf("--limit must be between 1 and %d", store.MaxEventPage)
			}
			out := cmd.OutOrStdout()
			if asCSV || asJSON {
				// Exports page through everything that matches.
				var all []logs.Event
				for off := f.Offset; ; off += store.MaxEventPage {
					page := f
					page.Limit, page.Offset = store.MaxEventPage, off
					evs, _, err := a.store.Events(ctx, name, page)
					if err != nil {
						return err
					}
					all = append(all, evs...)
					if len(evs) < store.MaxEventPage {
						break
					}
				}
				if asCSV {
					return render.TimelineCSV(out, all)
				}
				return render.JSON(out, all)
			}
			evs, total, err := a.store.Events(ctx, name, f)
			if err != nil {
				return err
			}
			width := 0
			if file, ok := out.(*os.File); ok && isTerminal(out) && !noTrunc {
				if w, _, err := term.GetSize(int(file.Fd())); err == nil { // #nosec G115 -- a file descriptor fits in int
					width = w
				}
			}
			if err := render.Timeline(out, evs, style(out, g), width); err != nil {
				return err
			}
			if total == 0 {
				fmt.Fprintln(out, "no events match (import logs with 'astro logs import')")
			} else if len(evs) < total {
				fmt.Fprintf(cmd.ErrOrStderr(), "showing %d-%d of %d events (use --offset %d for more)\n",
					f.Offset+1, f.Offset+len(evs), total, f.Offset+len(evs))
			}
			return nil
		}),
	}
	fl := cmd.Flags()
	fl.StringVar(&sev, "severity", "", "minimum severity: info, low, medium, high or critical")
	fl.StringVar(&f.Host, "host", "", "only this host")
	fl.StringVar(&f.User, "user", "", "only this user")
	fl.StringVar(&f.IP, "ip", "", "only events from or to this address")
	fl.StringVar(&f.Source, "source", "", `only this log (e.g. "auth.log", "Security.evtx")`)
	fl.StringVar(&f.Kind, "kind", "", `only this kind of event (e.g. ssh-failed, windows-event)`)
	fl.IntVar(&f.EventID, "event-id", 0, "only this Windows event ID")
	fl.StringVar(&f.Text, "grep", "", "only events whose message or command line contains this text")
	fl.StringVar(&from, "from", "", "from this time (UTC)")
	fl.StringVar(&to, "to", "", "up to this time (UTC)")
	fl.IntVar(&f.Limit, "limit", 500, "events per page")
	fl.IntVar(&f.Offset, "offset", 0, "skip this many events")
	fl.BoolVar(&asJSON, "json", false, "export every matching event as JSON")
	fl.BoolVar(&asCSV, "csv", false, "export every matching event as CSV")
	fl.BoolVar(&noTrunc, "no-truncate", false, "do not cut long lines to the terminal width")
	cmd.MarkFlagsMutuallyExclusive("json", "csv")
	return cmd
}

func logsFindingsCmd(g *globalFlags) *cobra.Command {
	var (
		sev            string
		events, asJSON bool
	)
	cmd := &cobra.Command{
		Use:   "findings <case>",
		Short: "Show what the detection rules found, most severe first",
		Args:  cobra.ExactArgs(1),
		RunE: withApp(g, func(cmd *cobra.Command, a *app, args []string) error {
			ctx, name := cmd.Context(), args[0]
			if err := requireCase(cmd, a, name); err != nil {
				return err
			}
			minSev := logs.Info
			if sev != "" {
				var err error
				if minSev, err = logs.ParseSeverity(sev); err != nil {
					return fmt.Errorf("--severity: %w", err)
				}
			}
			all, err := a.store.Findings(ctx, name)
			if err != nil {
				return err
			}
			var fs []logs.Finding
			for _, f := range all {
				if f.Severity >= minSev {
					fs = append(fs, f)
				}
			}
			out := cmd.OutOrStdout()
			if asJSON {
				return render.JSON(out, fs)
			}
			var cited func(f *logs.Finding) []logs.Event
			if events {
				cited = func(f *logs.Finding) []logs.Event {
					evs, err := a.store.EventsByID(ctx, name, f.EventIDs[:min(len(f.EventIDs), 5)])
					if err != nil {
						return nil
					}
					return evs
				}
			}
			return render.Findings(out, fs, style(out, g), cited)
		}),
	}
	cmd.Flags().StringVar(&sev, "severity", "", "minimum severity: info, low, medium, high or critical")
	cmd.Flags().BoolVar(&events, "events", false, "show the first events that prove each finding, with their evidence")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print as JSON")
	return cmd
}

func logsEvidenceCmd(g *globalFlags) *cobra.Command {
	var custody, asJSON bool
	cmd := &cobra.Command{
		Use:   "evidence <case>",
		Short: "List the evidence of a case: hashes, time range and chain of custody",
		Args:  cobra.ExactArgs(1),
		RunE: withApp(g, func(cmd *cobra.Command, a *app, args []string) error {
			ctx, name := cmd.Context(), args[0]
			if err := requireCase(cmd, a, name); err != nil {
				return err
			}
			list, err := a.store.CaseEvidence(ctx, name)
			if err != nil {
				return err
			}
			out, st := cmd.OutOrStdout(), style(cmd.OutOrStdout(), g)
			if asJSON {
				type item struct {
					store.Evidence
					Custody  []store.CustodyEntry `json:"custody,omitempty"`
					Verified bool                 `json:"custody_verified"`
				}
				items := make([]item, 0, len(list))
				for _, e := range list {
					it := item{Evidence: e}
					if it.Custody, err = a.store.Custody(ctx, e.ID); err != nil {
						return err
					}
					it.Verified = a.store.VerifyCustody(ctx, e.ID) == nil
					items = append(items, it)
				}
				return render.JSON(out, items)
			}
			if !custody {
				return render.Evidence(out, list, st)
			}
			for _, e := range list {
				if err := render.Evidence(out, []store.Evidence{e}, st); err != nil {
					return err
				}
				entries, err := a.store.Custody(ctx, e.ID)
				if err != nil {
					return err
				}
				if err := render.Custody(out, entries, a.store.VerifyCustody(ctx, e.ID), st); err != nil {
					return err
				}
			}
			return nil
		}),
	}
	cmd.Flags().BoolVar(&custody, "custody", false, "show and verify the chain of custody of each file")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print as JSON (always with the chain of custody)")
	return cmd
}
