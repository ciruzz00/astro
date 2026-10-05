// Command astro is a threat intelligence search engine.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/ciruzz00/astro/internal/httpx"
)

// Set at build time with -ldflags "-X main.version=... -X main.date=...".
var (
	version = "dev"
	date    = "unknown"
)

type globalFlags struct {
	dataDir string
	verbose bool
	noColor bool
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := newRootCmd().ExecuteContext(ctx)
	stop()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	httpx.UserAgent = fmt.Sprintf("astro/%s (+https://github.com/ciruzz00/astro)", version)
	g := &globalFlags{}
	root := &cobra.Command{
		Use:   "astro",
		Short: "Threat intelligence search engine",
		Long: `astro searches hashes, IPs, domains, URLs, CVEs, MITRE ATT&CK IDs,
MAC addresses and threat names across many intelligence sources at once.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRun: func(cmd *cobra.Command, _ []string) {
			level := slog.LevelWarn
			if g.verbose {
				level = slog.LevelDebug
			}
			slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))
		},
	}
	root.PersistentFlags().StringVar(&g.dataDir, "data-dir", "", "directory for config, database and datasets (default $ASTRO_DATA_DIR or the user config dir)")
	root.PersistentFlags().BoolVarP(&g.verbose, "verbose", "v", false, "debug logging on stderr")
	root.PersistentFlags().BoolVar(&g.noColor, "no-color", false, "disable colored output")

	root.AddCommand(
		newSearchCmd(g),
		newExtractCmd(),
		newSyncCmd(g),
		newProvidersCmd(g),
		newKeysCmd(g),
		newCaseCmd(g),
		newServeCmd(g),
		newTokenCmd(g),
		newVersionCmd(),
	)
	return root
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version and build date",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "astro %s (built %s, %s, %s/%s)\n",
				version, date, runtime.Version(), runtime.GOOS, runtime.GOARCH)
			return err
		},
	}
}
