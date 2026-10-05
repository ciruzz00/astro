package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/ciruzz00/astro/internal/api"
	"github.com/ciruzz00/astro/internal/auth"
	"github.com/ciruzz00/astro/internal/store"
)

func newServeCmd(g *globalFlags) *cobra.Command {
	var (
		addr        string
		allowRemote bool
		certFile    string
		keyFile     string
	)
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the REST API server",
		Long: `Start the REST API (OpenAPI spec at /api/v1/openapi.json).
Every endpoint except health and the spec requires a bearer token created
with 'astro token create'. The server listens on localhost only unless
--allow-remote is given; use TLS (or a TLS reverse proxy) in that case.`,
		Example: `  astro token create soar
  astro serve
  curl -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:8080/api/v1/search?q=8.8.8.8"`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := checkListenAddr(addr, allowRemote); err != nil {
				return err
			}
			if (certFile == "") != (keyFile == "") {
				return errors.New("--tls-cert and --tls-key must be used together")
			}
			a, err := openApp(cmd.Context(), g)
			if err != nil {
				return err
			}
			defer a.Close()

			logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
			if n, err := a.store.ActiveTokens(cmd.Context()); err == nil && n == 0 {
				logger.Warn("no API tokens yet: create one with 'astro token create <name>'")
			}
			if allowRemote && certFile == "" {
				logger.Warn("listening beyond localhost without TLS: make sure only trusted hosts can reach this port (in Docker, publish it on 127.0.0.1) or put a TLS proxy in front")
			}

			srv := api.NewHTTPServer(addr, api.NewHandler(api.Config{
				Engine:  a.engine,
				Sources: a.apiSources(),
				Tokens:  auth.NewManager(a.store),
				Version: version,
				Logger:  logger,
			}))
			srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
			return run(cmd.Context(), srv, certFile, keyFile, logger)
		},
	}
	cmd.Flags().StringVar(&addr, "addr", "127.0.0.1:8080", "listen address")
	cmd.Flags().BoolVar(&allowRemote, "allow-remote", false, "allow listening on non-loopback addresses")
	cmd.Flags().StringVar(&certFile, "tls-cert", "", "TLS certificate file (PEM)")
	cmd.Flags().StringVar(&keyFile, "tls-key", "", "TLS private key file (PEM)")
	return cmd
}

// checkListenAddr refuses non-loopback addresses unless explicitly allowed.
func checkListenAddr(addr string, allowRemote bool) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid --addr: %w", err)
	}
	if allowRemote || host == "localhost" {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	return fmt.Errorf("%s is not a loopback address: pass --allow-remote to expose the API", addr)
}

// run serves until ctx is canceled, then shuts down gracefully.
func run(ctx context.Context, srv *http.Server, certFile, keyFile string, logger *slog.Logger) error {
	ln, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return err
	}
	scheme := "http"
	if certFile != "" {
		scheme = "https"
	}
	logger.Info("astro API listening", "url", scheme+"://"+ln.Addr().String()+"/api/v1", "spec", "/api/v1/openapi.json")

	errc := make(chan error, 1)
	go func() {
		if certFile != "" {
			errc <- srv.ServeTLS(ln, certFile, keyFile)
		} else {
			errc <- srv.Serve(ln)
		}
	}()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	logger.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

func newTokenCmd(g *globalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "token",
		Short: "Manage REST API tokens",
	}
	cmd.AddCommand(
		&cobra.Command{
			Use:   "create <name>",
			Short: "Create a token (shown only once)",
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				a, err := openApp(cmd.Context(), g)
				if err != nil {
					return err
				}
				defer a.Close()
				secret, _, err := auth.NewManager(a.store).Create(cmd.Context(), args[0])
				if err != nil {
					return err
				}
				fmt.Fprintln(cmd.ErrOrStderr(), "Store this token now (e.g. in a password manager): it cannot be shown again.")
				_, err = fmt.Fprintln(cmd.OutOrStdout(), secret)
				return err
			},
		},
		&cobra.Command{
			Use:   "list",
			Short: "List tokens",
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				a, err := openApp(cmd.Context(), g)
				if err != nil {
					return err
				}
				defer a.Close()
				tokens, err := a.store.Tokens(cmd.Context())
				if err != nil {
					return err
				}
				tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
				fmt.Fprintln(tw, "NAME\tPREFIX\tCREATED\tLAST USED\tSTATUS")
				for _, t := range tokens {
					status := "active"
					if t.RevokedAt != nil {
						status = "revoked " + t.RevokedAt.Local().Format("2006-01-02")
					}
					fmt.Fprintf(tw, "%s\t%s...\t%s\t%s\t%s\n", t.Name, t.Prefix, t.CreatedAt.Local().Format("2006-01-02"), when(t.LastUsedAt), status)
				}
				return tw.Flush()
			},
		},
		&cobra.Command{
			Use:   "revoke <name>",
			Short: "Revoke a token",
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				a, err := openApp(cmd.Context(), g)
				if err != nil {
					return err
				}
				defer a.Close()
				err = a.store.RevokeToken(cmd.Context(), args[0], time.Now())
				if errors.Is(err, store.ErrNotFound) {
					return fmt.Errorf("no active token named %q", args[0])
				}
				if err == nil {
					fmt.Fprintf(cmd.OutOrStdout(), "token %s revoked\n", args[0])
				}
				return err
			},
		},
	)
	return cmd
}

func when(t *time.Time) string {
	if t == nil {
		return "never"
	}
	return t.Local().Format("2006-01-02 15:04")
}

// apiSources describes the sources for the API's /providers endpoint.
func (a *app) apiSources() []api.Source {
	out := make([]api.Source, 0, len(a.sources))
	for _, s := range a.sources {
		src := api.Source{
			Name:       s.provider.Name(),
			Enabled:    s.enabled(),
			Offline:    s.local,
			Indicators: strings.Split(supported(s), ", "),
		}
		if !src.Enabled {
			src.KeyEnv = s.keyEnv
		}
		out = append(out, src)
	}
	return out
}
