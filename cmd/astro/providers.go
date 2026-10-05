package main

import (
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/ciruzz00/astro/internal/ioc"
)

func newProvidersCmd(g *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "providers",
		Short: "List intelligence sources and whether they are enabled",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			a, err := openApp(cmd.Context(), g)
			if err != nil {
				return err
			}
			defer a.Close()

			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "SOURCE\tSTATUS\tWHERE\tINDICATORS")
			for _, s := range a.currentSources() {
				status := "enabled"
				switch {
				case !s.enabled():
					status = "disabled: set " + s.keyEnv
				case s.need == keyOptional && !s.key.IsSet():
					status = "enabled (no key: limited)"
				}
				where := "online"
				if s.local {
					where = "offline"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", s.provider.Name(), status, where, supported(s))
			}
			return tw.Flush()
		},
	}
}

// supported summarizes the indicator types a source handles.
func supported(s source) string {
	var out []string
	seen := map[string]bool{}
	for _, t := range ioc.Types {
		if !s.provider.Supports(t) {
			continue
		}
		label := string(t)
		switch {
		case t.IsHash():
			label = "hash"
		case t.IsAttack():
			label = "att&ck"
		}
		if !seen[label] {
			seen[label] = true
			out = append(out, label)
		}
	}
	return strings.Join(out, ", ")
}
