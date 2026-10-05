package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/ciruzz00/astro/internal/engine"
	"github.com/ciruzz00/astro/internal/ioc"
	"github.com/ciruzz00/astro/internal/render"
)

// maxInput caps text read from files or stdin.
const maxInput = 32 << 20

func newSearchCmd(g *globalFlags) *cobra.Command {
	var (
		asJSON  bool
		noCache bool
		offline bool
		only    []string
		file    string
	)
	cmd := &cobra.Command{
		Use:   "search [indicator...]",
		Short: "Search indicators across every source",
		Long: `Search one or more indicators. The type is detected automatically and
defanged input (hxxps://evil[.]com) is accepted. Quote multi-word names.

With --file, every indicator found in the file (or stdin with "-") is searched.

Online sources receive the indicator you search: use --offline (or --only)
for sensitive indicators that must not leave this machine.`,
		Example: `  astro search 44d88612fea8a8f36de82e1278abb02f
  astro search CVE-2021-44228 T1059.001 "Lazarus Group"
  astro search 00:50:56:aa:bb:cc
  astro search --file incident.log --json
  astro search --offline 10.0.0.5
  astro search --only virustotal,malwarebazaar 44d88612fea8a8f36de82e1278abb02f`,
		RunE: func(cmd *cobra.Command, args []string) error {
			inds, err := collectIndicators(cmd, args, file)
			if err != nil {
				return err
			}
			a, err := openApp(cmd.Context(), g)
			if err != nil {
				return err
			}
			defer a.Close()

			opts := engine.SearchOptions{NoCache: noCache, Only: only}
			if offline {
				opts.Only = a.localNames()
			} else if err := checkOnly(a, only); err != nil {
				return err
			}
			reports := a.engine.SearchMany(cmd.Context(), inds, opts)
			out := cmd.OutOrStdout()
			if asJSON {
				return render.JSON(out, reports)
			}
			st := style(out, g)
			for _, rep := range reports {
				if err := render.Text(out, rep, st); err != nil {
					return err
				}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print results as JSON")
	cmd.Flags().BoolVar(&noCache, "no-cache", false, "ignore cached results and query the sources again")
	cmd.Flags().StringVarP(&file, "file", "f", "", `extract indicators from a file ("-" for stdin)`)
	cmd.Flags().BoolVar(&offline, "offline", false, "use only offline datasets: nothing leaves this machine")
	cmd.Flags().StringSliceVar(&only, "only", nil, "comma-separated sources to query (see 'astro providers')")
	cmd.MarkFlagsMutuallyExclusive("offline", "only")
	return cmd
}

// checkOnly validates --only against the known and enabled sources.
func checkOnly(a *app, only []string) error {
	for _, name := range only {
		found := false
		for _, s := range a.sources {
			if s.provider.Name() != name {
				continue
			}
			found = true
			if !s.enabled() {
				return fmt.Errorf("source %q is disabled: set %s", name, s.keyEnv)
			}
		}
		if !found {
			return fmt.Errorf("unknown source %q: run 'astro providers' for the list", name)
		}
	}
	return nil
}

func collectIndicators(cmd *cobra.Command, args []string, file string) ([]ioc.Indicator, error) {
	var inds []ioc.Indicator
	for _, a := range args {
		i, err := ioc.Parse(a)
		if err != nil {
			return nil, fmt.Errorf("%q: %w", a, err)
		}
		inds = append(inds, i)
	}
	if file != "" {
		text, err := readInput(cmd, file)
		if err != nil {
			return nil, err
		}
		found := ioc.Extract(text)
		if len(found) == 0 {
			return nil, fmt.Errorf("no indicators found in %s", file)
		}
		inds = append(inds, found...)
	}
	if len(inds) == 0 {
		return nil, errors.New("nothing to search: pass indicators or --file")
	}
	return inds, nil
}

// readInput reads a file, or stdin for "-", up to maxInput bytes.
func readInput(cmd *cobra.Command, path string) (string, error) {
	var r io.Reader
	if path == "-" {
		r = cmd.InOrStdin()
	} else {
		f, err := os.Open(path) // #nosec G304 -- the user chooses which local file to read
		if err != nil {
			return "", err
		}
		defer f.Close()
		r = f
	}
	b, err := io.ReadAll(io.LimitReader(r, maxInput+1))
	if err != nil {
		return "", err
	}
	if len(b) > maxInput {
		return "", fmt.Errorf("input larger than %d MB", maxInput>>20)
	}
	return string(b), nil
}

func newExtractCmd() *cobra.Command {
	var (
		asJSON bool
		defang bool
	)
	cmd := &cobra.Command{
		Use:   "extract [file|-]",
		Short: "Extract indicators from text (logs, reports, emails)",
		Long: `Extract, refang and de-duplicate every indicator found in a file or stdin,
without querying any source. Useful to triage a report before searching it.`,
		Example: `  astro extract report.txt
  pbpaste | astro extract --defang -`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := "-"
			if len(args) == 1 {
				path = args[0]
			}
			text, err := readInput(cmd, path)
			if err != nil {
				return err
			}
			inds := ioc.Extract(text)
			out := cmd.OutOrStdout()
			if asJSON {
				if inds == nil {
					inds = []ioc.Indicator{}
				}
				return render.JSON(out, inds)
			}
			for _, i := range inds {
				v := i.Value
				if defang {
					v = ioc.Defang(i)
				}
				if _, err := fmt.Fprintf(out, "%-18s %s\n", i.Type, render.Sanitize(v)); err != nil {
					return err
				}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print indicators as JSON")
	cmd.Flags().BoolVar(&defang, "defang", false, "defang URLs, domains, IPs and emails in the output")
	return cmd
}
