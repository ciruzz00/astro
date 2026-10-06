package main

import (
	"errors"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/ciruzz00/astro/internal/datasets"
	"github.com/ciruzz00/astro/internal/httpx"
	"github.com/ciruzz00/astro/internal/tui"
)

func newTUICmd(g *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "tui",
		Short: "Open the interactive terminal interface",
		Long: `Open the interactive terminal interface: search indicators, browse and
work on cases, export reports and sync datasets with the keyboard.
Press ? inside the interface for the keys.`,
		Args: cobra.NoArgs,
		RunE: withApp(g, func(cmd *cobra.Command, a *app, _ []string) error {
			if !isTerminal(os.Stdout) {
				return errors.New("the terminal interface needs an interactive terminal")
			}
			return tui.Run(tui.Config{
				Ctx:           cmd.Context(),
				Engine:        a.engine,
				Cases:         a.cases,
				Store:         a.store,
				Sources:       a.apiSources,
				Fetcher:       datasets.HTTPFetcher(httpx.NewClient(5 * time.Minute)),
				Version:       version,
				AttackVersion: func() string { return a.attackVersion(cmd.Context()) },
			})
		}),
	}
}
