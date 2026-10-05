package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/ciruzz00/astro/internal/cases"
	"github.com/ciruzz00/astro/internal/ioc"
	"github.com/ciruzz00/astro/internal/render"
	"github.com/ciruzz00/astro/internal/report"
)

func newCaseCmd(g *globalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "case",
		Short: "Manage investigations (cases)",
		Long: `A case collects indicators, their latest search results, notes and tags,
marked with a TLP level (clear, green, amber, amber+strict, red; default amber).
Cases can be resumed at any time and exported as Markdown, JSON, STIX 2.1 or
an ATT&CK Navigator layer.`,
		Example: `  astro case new sherlock-brutus --title "HTB Sherlock: Brutus" --tag htb
  astro case add sherlock-brutus -f auth.log --search
  astro case note sherlock-brutus "Initial access via SSH brute force"
  astro case show sherlock-brutus
  astro case export sherlock-brutus --format pdf -o brutus.pdf`,
	}
	cmd.AddCommand(
		caseNewCmd(g), caseListCmd(g), caseShowCmd(g), caseAddCmd(g), caseSearchCmd(g),
		caseNoteCmd(g), caseTagCmd(g), caseRemoveCmd(g), caseEditCmd(g),
		caseStatusCmd(g, "close", "closed"), caseStatusCmd(g, "reopen", "open"),
		caseDeleteCmd(g), caseExportCmd(g),
	)
	return cmd
}

// withApp opens the app for a subcommand and closes it afterwards.
func withApp(g *globalFlags, fn func(cmd *cobra.Command, a *app, args []string) error) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		a, err := openApp(cmd.Context(), g)
		if err != nil {
			return err
		}
		defer a.Close()
		return fn(cmd, a, args)
	}
}

// caseError turns "not found" into a message naming the case.
func caseError(name string, err error) error {
	if errors.Is(err, cases.ErrNotFound) {
		return fmt.Errorf("no case named %q (see 'astro case list')", name)
	}
	return err
}

func caseNewCmd(g *globalFlags) *cobra.Command {
	var title, tlp string
	var tags []string
	cmd := &cobra.Command{
		Use:   "new <name>",
		Short: "Create a case",
		Args:  cobra.ExactArgs(1),
		RunE: withApp(g, func(cmd *cobra.Command, a *app, args []string) error {
			if err := a.cases.Create(cmd.Context(), args[0], title, tlp, tags); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "case %s created\n", args[0])
			return nil
		}),
	}
	cmd.Flags().StringVar(&title, "title", "", "human-readable title")
	cmd.Flags().StringVar(&tlp, "tlp", cases.TLPAmber, "TLP marking: clear, green, amber, amber+strict, red")
	cmd.Flags().StringSliceVar(&tags, "tag", nil, "tags (repeatable or comma-separated)")
	return cmd
}

func caseListCmd(g *globalFlags) *cobra.Command {
	var all, asJSON bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List cases (open ones unless --all)",
		Args:  cobra.NoArgs,
		RunE: withApp(g, func(cmd *cobra.Command, a *app, _ []string) error {
			list, err := a.cases.List(cmd.Context(), all)
			if err != nil {
				return err
			}
			if asJSON {
				return render.JSON(cmd.OutOrStdout(), list)
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "NAME\tTLP\tSTATUS\tIOCS\tMALICIOUS\tSUSPICIOUS\tUPDATED\tTITLE")
			for _, c := range list {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%d\t%d\t%s\t%s\n", c.Name, c.TLP, c.Status, c.Indicators,
					c.Malicious, c.Suspicious, c.UpdatedAt.Local().Format("2006-01-02 15:04"), render.Sanitize(c.Title))
			}
			return tw.Flush()
		}),
	}
	cmd.Flags().BoolVar(&all, "all", false, "include closed cases")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print as JSON")
	return cmd
}

func caseShowCmd(g *globalFlags) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "show <name>",
		Short: "Show a case with its indicators and notes",
		Args:  cobra.ExactArgs(1),
		RunE: withApp(g, func(cmd *cobra.Command, a *app, args []string) error {
			v, err := a.cases.Load(cmd.Context(), args[0])
			if err != nil {
				return caseError(args[0], err)
			}
			out := cmd.OutOrStdout()
			if asJSON {
				return render.JSON(out, v)
			}
			return printCase(out, v)
		}),
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print as JSON with full search results")
	return cmd
}

func printCase(w io.Writer, v *cases.View) error {
	c := v.Case
	fmt.Fprintf(w, "%s  TLP:%s  %s\n", render.Sanitize(c.Name), c.TLP, c.Status)
	if c.Title != "" {
		fmt.Fprintf(w, "%s\n", render.Sanitize(c.Title))
	}
	if c.Description != "" {
		fmt.Fprintf(w, "%s\n", render.Sanitize(c.Description))
	}
	if len(c.Tags) > 0 {
		fmt.Fprintf(w, "tags: %s\n", render.Sanitize(strings.Join(c.Tags, ", ")))
	}
	fmt.Fprintf(w, "created %s, updated %s\n", c.CreatedAt.Local().Format("2006-01-02 15:04"), c.UpdatedAt.Local().Format("2006-01-02 15:04"))
	mal, sus, clean, pending := v.Counts()
	fmt.Fprintf(w, "\n%d indicators: %d malicious, %d suspicious, %d clean, %d not searched\n\n", len(v.Items), mal, sus, clean, pending)

	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "VERDICT\tTYPE\tINDICATOR\tFLAGGED BY\tNOTE")
	for _, it := range v.Items {
		verdict := string(it.Verdict)
		switch {
		case it.SearchedAt == nil:
			verdict = "-"
		case verdict == "":
			verdict = "none"
		}
		var flagged []string
		if it.Report != nil {
			for _, r := range it.Report.Results {
				if r.Verdict.Rank() >= 2 {
					flagged = append(flagged, r.Provider)
				}
			}
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", verdict, it.Indicator.Type, render.Sanitize(ioc.Defang(it.Indicator)),
			strings.Join(flagged, ","), render.Sanitize(strings.ReplaceAll(it.Note, "\n", " ")))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if len(c.Notes) > 0 {
		fmt.Fprintln(w, "\nNotes:")
		for _, n := range c.Notes {
			fmt.Fprintf(w, "\n  [%s]\n  %s\n", n.CreatedAt.Local().Format("2006-01-02 15:04"),
				strings.ReplaceAll(render.Sanitize(n.Body), "\n", "\n  "))
		}
	}
	return nil
}

func caseAddCmd(g *globalFlags) *cobra.Command {
	var (
		file, note string
		search     bool
		sf         searchFlags
	)
	cmd := &cobra.Command{
		Use:   "add <name> [indicator...]",
		Short: "Add indicators to a case (from arguments and/or a file)",
		Args:  cobra.MinimumNArgs(1),
		RunE: withApp(g, func(cmd *cobra.Command, a *app, args []string) error {
			name := args[0]
			inds, err := collectIndicators(cmd, args[1:], file)
			if err != nil {
				return err
			}
			n, err := a.cases.Add(cmd.Context(), name, inds, note)
			if err != nil {
				return caseError(name, err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%d new indicators added to %s (%d given)\n", n, name, len(inds))
			if !search {
				return nil
			}
			opts, err := a.searchOptions(sf)
			if err != nil {
				return err
			}
			reports, err := a.cases.Search(cmd.Context(), name, opts, true)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%d indicators searched\n", len(reports))
			return nil
		}),
	}
	cmd.Flags().StringVarP(&file, "file", "f", "", `extract indicators from a file ("-" for stdin)`)
	cmd.Flags().StringVar(&note, "note", "", "note attached to the added indicators")
	cmd.Flags().BoolVar(&search, "search", false, "search the indicators not searched yet")
	sf.register(cmd)
	return cmd
}

func caseSearchCmd(g *globalFlags) *cobra.Command {
	var (
		all bool
		sf  searchFlags
	)
	cmd := &cobra.Command{
		Use:   "search <name>",
		Short: "Search the case indicators and save the results",
		Long:  "Search the indicators never searched, or all of them with --all, and save the results in the case.",
		Args:  cobra.ExactArgs(1),
		RunE: withApp(g, func(cmd *cobra.Command, a *app, args []string) error {
			opts, err := a.searchOptions(sf)
			if err != nil {
				return err
			}
			reports, err := a.cases.Search(cmd.Context(), args[0], opts, !all)
			if err != nil {
				return caseError(args[0], err)
			}
			if len(reports) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "nothing to search (use --all to search everything again)")
				return nil
			}
			out := cmd.OutOrStdout()
			st := style(out, g)
			for _, rep := range reports {
				if err := render.Text(out, rep, st); err != nil {
					return err
				}
			}
			return nil
		}),
	}
	cmd.Flags().BoolVar(&all, "all", false, "search every indicator again, not only new ones")
	sf.register(cmd)
	return cmd
}

func caseNoteCmd(g *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "note <name> <text...|->",
		Short: `Add a Markdown note ("-" reads it from stdin)`,
		Args:  cobra.MinimumNArgs(2),
		RunE: withApp(g, func(cmd *cobra.Command, a *app, args []string) error {
			body := strings.Join(args[1:], " ")
			if body == "-" {
				text, err := readInput(cmd, "-")
				if err != nil {
					return err
				}
				body = text
			}
			if err := a.cases.Note(cmd.Context(), args[0], body); err != nil {
				return caseError(args[0], err)
			}
			fmt.Fprintln(cmd.OutOrStdout(), "note added")
			return nil
		}),
	}
}

func caseTagCmd(g *globalFlags) *cobra.Command {
	var remove bool
	cmd := &cobra.Command{
		Use:   "tag <name> <tag...>",
		Short: "Add (or with --remove, remove) tags",
		Args:  cobra.MinimumNArgs(2),
		RunE: withApp(g, func(cmd *cobra.Command, a *app, args []string) error {
			add, del := args[1:], []string(nil)
			if remove {
				add, del = nil, args[1:]
			}
			return caseError(args[0], a.cases.Tag(cmd.Context(), args[0], add, del))
		}),
	}
	cmd.Flags().BoolVar(&remove, "remove", false, "remove the tags instead of adding them")
	return cmd
}

func caseRemoveCmd(g *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "remove <name> <indicator>",
		Short: "Remove an indicator from a case",
		Args:  cobra.ExactArgs(2),
		RunE: withApp(g, func(cmd *cobra.Command, a *app, args []string) error {
			i, err := ioc.Parse(args[1])
			if err != nil {
				return err
			}
			err = a.cases.Remove(cmd.Context(), args[0], i)
			if errors.Is(err, cases.ErrNotFound) {
				return fmt.Errorf("%s is not in case %s (or the case does not exist)", ioc.Defang(i), args[0])
			}
			return err
		}),
	}
}

func caseEditCmd(g *globalFlags) *cobra.Command {
	var title, description, tlp string
	cmd := &cobra.Command{
		Use:   "edit <name>",
		Short: "Change title, description or TLP",
		Args:  cobra.ExactArgs(1),
		RunE: withApp(g, func(cmd *cobra.Command, a *app, args []string) error {
			ptr := func(flag, v string) *string {
				if cmd.Flags().Changed(flag) {
					return &v
				}
				return nil
			}
			t, d, l := ptr("title", title), ptr("description", description), ptr("tlp", tlp)
			if t == nil && d == nil && l == nil {
				return errors.New("nothing to change: use --title, --description or --tlp")
			}
			return caseError(args[0], a.cases.Update(cmd.Context(), args[0], t, d, l, nil))
		}),
	}
	cmd.Flags().StringVar(&title, "title", "", "new title")
	cmd.Flags().StringVar(&description, "description", "", "new description (Markdown)")
	cmd.Flags().StringVar(&tlp, "tlp", "", "new TLP marking")
	return cmd
}

func caseStatusCmd(g *globalFlags, verb, status string) *cobra.Command {
	return &cobra.Command{
		Use:   verb + " <name>",
		Short: strings.ToUpper(verb[:1]) + verb[1:] + " a case",
		Args:  cobra.ExactArgs(1),
		RunE: withApp(g, func(cmd *cobra.Command, a *app, args []string) error {
			s := status
			return caseError(args[0], a.cases.Update(cmd.Context(), args[0], nil, nil, nil, &s))
		}),
	}
}

func caseDeleteCmd(g *globalFlags) *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:   "delete <name>",
		Short: "Delete a case permanently",
		Args:  cobra.ExactArgs(1),
		RunE: withApp(g, func(cmd *cobra.Command, a *app, args []string) error {
			if !yes {
				return fmt.Errorf("this permanently deletes case %s and its notes: confirm with --yes (or close it instead)", args[0])
			}
			if err := a.cases.Delete(cmd.Context(), args[0]); err != nil {
				return caseError(args[0], err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "case %s deleted\n", args[0])
			return nil
		}),
	}
	cmd.Flags().BoolVar(&yes, "yes", false, "confirm the deletion")
	return cmd
}

func caseExportCmd(g *globalFlags) *cobra.Command {
	var format, output string
	var force bool
	cmd := &cobra.Command{
		Use:   "export <name>",
		Short: "Export a case (pdf, md, json, stix, navigator)",
		Long: `Export a case. pdf is a printable report with the TLP label on every page,
Markdown is a readable report with defanged indicators,
stix is a STIX 2.1 bundle marked with the case TLP, navigator is a MITRE
ATT&CK Navigator layer. Files are written with owner-only permissions.`,
		Args: cobra.ExactArgs(1),
		RunE: withApp(g, func(cmd *cobra.Command, a *app, args []string) error {
			v, err := a.cases.Load(cmd.Context(), args[0])
			if err != nil {
				return caseError(args[0], err)
			}
			opts := report.Options{Version: version, AttackVersion: a.attackVersion(cmd.Context())}
			if output == "" {
				if report.Extension(format) == ".pdf" && isTerminal(cmd.OutOrStdout()) {
					return errors.New("a PDF cannot be printed to the terminal: use -o <file>")
				}
				return report.Write(cmd.OutOrStdout(), format, v, opts)
			}
			if filepath.Ext(output) == "" {
				output += report.Extension(format)
			}
			flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
			if force {
				flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
			}
			f, err := os.OpenFile(output, flags, 0o600) // #nosec G304 -- the user chooses the output path
			if err != nil {
				if errors.Is(err, os.ErrExist) {
					return fmt.Errorf("%s exists: use --force to overwrite", output)
				}
				return err
			}
			if err := report.Write(f, format, v, opts); err != nil {
				_ = f.Close()
				return err
			}
			if err := f.Close(); err != nil {
				return err
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "exported %s (TLP:%s) to %s\n", args[0], v.Case.TLP, output)
			return nil
		}),
	}
	cmd.Flags().StringVar(&format, "format", "md", "pdf, md, json, stix or navigator")
	cmd.Flags().StringVarP(&output, "output", "o", "", "output file (default stdout)")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite the output file")
	return cmd
}
