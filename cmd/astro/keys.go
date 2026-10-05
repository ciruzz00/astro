package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/ciruzz00/astro/internal/config"
	"github.com/ciruzz00/astro/internal/engine"
	"github.com/ciruzz00/astro/internal/ioc"
	"github.com/ciruzz00/astro/internal/store"
	"github.com/ciruzz00/astro/internal/web"
)

// errKeyFromEnv is returned when changing a key set by an environment variable.
var errKeyFromEnv = errors.New("this key is set by an environment variable, which takes precedence: change or remove it there (e.g. in .env) and restart")

// KeyStatuses implements web.KeyManager.
func (a *app) KeyStatuses(ctx context.Context) ([]web.KeyStatus, error) {
	stored, err := a.store.ProviderKeys(ctx)
	if err != nil {
		return nil, err
	}
	a.mu.RLock()
	origin := a.keyOrigin
	a.mu.RUnlock()
	sources := a.currentSources()
	out := make([]web.KeyStatus, 0, len(config.KeyDefs))
	for _, d := range config.KeyDefs {
		ks := web.KeyStatus{Name: d.Name, Label: d.Label, Env: d.Env, URL: d.URL, Origin: origin[d.Name]}
		if k, ok := stored[d.Name]; ok && ks.Origin == config.OriginDatabase {
			t := k.UpdatedAt
			ks.UpdatedAt = &t
		}
		for _, s := range sources {
			if s.keyName == d.Name {
				ks.Providers = append(ks.Providers, s.provider.Name())
			}
		}
		out = append(out, ks)
	}
	return out, nil
}

func (a *app) keyDef(name string) (config.KeyDef, error) {
	d, ok := config.KeyDefByName(name)
	if !ok {
		return d, fmt.Errorf("unknown key %q (run 'astro keys list')", name)
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.keyOrigin[name] == config.OriginEnv {
		return d, errKeyFromEnv
	}
	return d, nil
}

// SetKey implements web.KeyManager: it stores the key and reloads the sources.
func (a *app) SetKey(ctx context.Context, name, value string) error {
	if _, err := a.keyDef(name); err != nil {
		return err
	}
	value = strings.TrimSpace(value)
	if err := config.ValidateKeyValue(value); err != nil {
		return err
	}
	if err := a.store.SetProviderKey(ctx, name, value, time.Now()); err != nil {
		return err
	}
	return a.reload(ctx)
}

// DeleteKey implements web.KeyManager.
func (a *app) DeleteKey(ctx context.Context, name string) error {
	if _, err := a.keyDef(name); err != nil {
		return err
	}
	if err := a.store.DeleteProviderKey(ctx, name); errors.Is(err, store.ErrNotFound) {
		return errors.New("this key is not stored by astro (it may come from config.toml)")
	} else if err != nil {
		return err
	}
	return a.reload(ctx)
}

// canaries are harmless, well-known indicators used to test keys.
var canaries = []ioc.Indicator{
	{Type: ioc.MD5, Value: "44d88612fea8a8f36de82e1278abb02f"}, // EICAR test file
	{Type: ioc.IPv4, Value: "8.8.8.8"},
	{Type: ioc.CVE, Value: "CVE-2021-44228"},
	{Type: ioc.Domain, Value: "example.com"},
}

// TestKey implements web.KeyManager: every provider using the key runs one
// fresh lookup of a harmless indicator.
func (a *app) TestKey(ctx context.Context, name string) ([]web.KeyTest, error) {
	if _, ok := config.KeyDefByName(name); !ok {
		return nil, fmt.Errorf("unknown key %q", name)
	}
	var out []web.KeyTest
	for _, s := range a.currentSources() {
		if s.keyName != name {
			continue
		}
		if !s.enabled() {
			return nil, errors.New("the key is not set")
		}
		var canary *ioc.Indicator
		for _, c := range canaries {
			if s.provider.Supports(c.Type) {
				canary = &c
				break
			}
		}
		if canary == nil {
			continue
		}
		rep := a.engine.Search(ctx, *canary, engine.SearchOptions{NoCache: true, Only: []string{s.provider.Name()}})
		t := web.KeyTest{Provider: s.provider.Name(), OK: true}
		switch {
		case len(rep.Results) == 0:
			t.OK, t.Message = false, "not queried"
		case rep.Results[0].Error != "":
			t.OK, t.Message = false, rep.Results[0].Error
		default:
			t.Message = "OK (" + ioc.Defang(*canary) + ")"
		}
		out = append(out, t)
	}
	return out, nil
}

func newKeysCmd(g *globalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "keys",
		Short: "Manage provider API keys",
		Long: `Manage the API keys of the intelligence providers. Keys set here (or in
the web interface) are stored in astro's database, which only its owner can
read. Environment variables take precedence over stored keys, and stored keys
over config.toml. Values are never printed.`,
	}
	cmd.AddCommand(
		&cobra.Command{
			Use: "list", Short: "Show which keys are set and where they come from", Args: cobra.NoArgs,
			RunE: withApp(g, func(cmd *cobra.Command, a *app, _ []string) error {
				list, err := a.KeyStatuses(cmd.Context())
				if err != nil {
					return err
				}
				tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
				fmt.Fprintln(tw, "KEY\tSTATUS\tPROVIDERS\tENV VARIABLE")
				for _, k := range list {
					status := "not set"
					if k.Origin != "" {
						status = "set (" + k.Origin + ")"
					}
					fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", k.Name, status, strings.Join(k.Providers, ","), k.Env)
				}
				return tw.Flush()
			}),
		},
		&cobra.Command{
			Use: "set <name>", Short: "Store a key (read from the terminal without echo, or from stdin)", Args: cobra.ExactArgs(1),
			RunE: withApp(g, func(cmd *cobra.Command, a *app, args []string) error {
				value, err := readSecret(cmd, "API key for "+args[0]+": ")
				if err != nil {
					return err
				}
				if err := a.SetKey(cmd.Context(), args[0], value); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "key %s stored\n", args[0])
				return nil
			}),
		},
		&cobra.Command{
			Use: "unset <name>", Short: "Remove a stored key", Args: cobra.ExactArgs(1),
			RunE: withApp(g, func(cmd *cobra.Command, a *app, args []string) error {
				if err := a.DeleteKey(cmd.Context(), args[0]); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "key %s removed\n", args[0])
				return nil
			}),
		},
		&cobra.Command{
			Use: "test <name>", Short: "Check a key with a harmless lookup on each provider using it", Args: cobra.ExactArgs(1),
			RunE: withApp(g, func(cmd *cobra.Command, a *app, args []string) error {
				results, err := a.TestKey(cmd.Context(), args[0])
				if err != nil {
					return err
				}
				failed := 0
				for _, r := range results {
					status := "ok"
					if !r.OK {
						status, failed = "FAILED", failed+1
					}
					fmt.Fprintf(cmd.OutOrStdout(), "%-15s %-7s %s\n", r.Provider, status, r.Message)
				}
				if failed > 0 {
					return fmt.Errorf("%d providers failed", failed)
				}
				return nil
			}),
		},
	)
	return cmd
}

// readSecret reads a value without echo from a terminal, or one line from stdin.
func readSecret(cmd *cobra.Command, prompt string) (string, error) {
	if f, ok := cmd.InOrStdin().(*os.File); ok && term.IsTerminal(int(f.Fd())) { // #nosec G115 -- file descriptors fit in int
		fmt.Fprint(cmd.ErrOrStderr(), prompt)
		b, err := term.ReadPassword(int(f.Fd())) // #nosec G115 -- file descriptors fit in int
		fmt.Fprintln(cmd.ErrOrStderr())
		return string(b), err
	}
	line, err := bufio.NewReader(cmd.InOrStdin()).ReadString('\n')
	if err != nil && line == "" {
		return "", errors.New("no key on stdin")
	}
	return strings.TrimSpace(line), nil
}
