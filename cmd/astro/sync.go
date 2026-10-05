package main

import (
	"fmt"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/ciruzz00/astro/internal/datasets"
	"github.com/ciruzz00/astro/internal/httpx"
)

func newSyncCmd(g *globalFlags) *cobra.Command {
	var list bool
	cmd := &cobra.Command{
		Use:   "sync [dataset...]",
		Short: "Download or update the offline datasets",
		Long: `Download the offline datasets used without network access:
MITRE ATT&CK (enterprise, mobile, ics), CISA KEV and the IEEE MAC registry.
With no arguments every dataset is synced; "attack" selects all ATT&CK domains.`,
		Example: `  astro sync
  astro sync attack kev
  astro sync --list`,
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := openApp(cmd.Context(), g)
			if err != nil {
				return err
			}
			defer a.Close()
			out := cmd.OutOrStdout()

			if list {
				ds, err := a.store.Datasets(cmd.Context())
				if err != nil {
					return err
				}
				synced := map[string]bool{}
				tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
				fmt.Fprintln(tw, "DATASET\tRECORDS\tVERSION\tSYNCED")
				for _, d := range ds {
					synced[d.Name] = true
					fmt.Fprintf(tw, "%s\t%d\t%s\t%s\n", d.Name, d.Records, d.Version, d.SyncedAt.Local().Format("2006-01-02 15:04"))
				}
				for _, s := range datasets.Sources {
					if !synced[s.Name] {
						fmt.Fprintf(tw, "%s\t-\t-\tnever\n", s.Name)
					}
				}
				return tw.Flush()
			}

			srcs, err := datasets.Select(args)
			if err != nil {
				return err
			}
			// Datasets are large: allow more time than a single API call.
			fetch := datasets.HTTPFetcher(httpx.NewClient(5 * time.Minute))
			failed := 0
			for _, s := range srcs {
				fmt.Fprintf(out, "%-18s ", s.Name)
				start := time.Now()
				n, err := s.Sync(cmd.Context(), fetch, a.store)
				if err != nil {
					failed++
					fmt.Fprintf(out, "FAILED: %v\n", err)
					continue
				}
				fmt.Fprintf(out, "%7d records  %s\n", n, time.Since(start).Round(100*time.Millisecond))
			}
			if failed > 0 {
				return fmt.Errorf("%d of %d datasets failed", failed, len(srcs))
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&list, "list", false, "show the status of the local datasets")
	return cmd
}
