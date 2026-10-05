package main

import (
	"context"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/ciruzz00/astro/internal/config"
	"github.com/ciruzz00/astro/internal/engine"
	"github.com/ciruzz00/astro/internal/httpx"
	"github.com/ciruzz00/astro/internal/provider"
	"github.com/ciruzz00/astro/internal/provider/attack"
	"github.com/ciruzz00/astro/internal/provider/epss"
	"github.com/ciruzz00/astro/internal/provider/kev"
	"github.com/ciruzz00/astro/internal/provider/nvd"
	"github.com/ciruzz00/astro/internal/provider/oui"
	"github.com/ciruzz00/astro/internal/render"
	"github.com/ciruzz00/astro/internal/store"
)

// app holds the shared dependencies of the commands.
type app struct {
	cfg    *config.Config
	store  *store.Store
	client *http.Client
	engine *engine.Engine
}

func openApp(ctx context.Context, g *globalFlags) (*app, error) {
	dir := g.dataDir
	if dir == "" {
		var err error
		if dir, err = config.DefaultDataDir(); err != nil {
			return nil, err
		}
	}
	cfg, err := config.Load(dir)
	if err != nil {
		return nil, err
	}
	st, err := store.Open(ctx, cfg.DBPath())
	if err != nil {
		return nil, err
	}
	client := httpx.NewClient(cfg.HTTPTimeout)
	a := &app{cfg: cfg, store: st, client: client}
	a.engine = engine.New(a.providers(), engine.WithCache(st), engine.WithTimeout(cfg.HTTPTimeout+10*time.Second))
	return a, nil
}

// providers lists every source in display order.
func (a *app) providers() []provider.Provider {
	return []provider.Provider{
		attack.New(a.store),
		nvd.New(a.client, nvd.DefaultBase, a.cfg.Keys.NVD),
		kev.New(a.store),
		epss.New(a.client, epss.DefaultBase),
		oui.New(a.store),
	}
}

func (a *app) Close() error { return a.store.Close() }

// style enables colors only on an interactive terminal, honoring NO_COLOR.
func style(w io.Writer, g *globalFlags) render.Style {
	if g.noColor || os.Getenv("NO_COLOR") != "" {
		return render.Style{}
	}
	f, ok := w.(*os.File)
	if !ok {
		return render.Style{}
	}
	info, err := f.Stat()
	return render.Style{Color: err == nil && info.Mode()&os.ModeCharDevice != 0}
}
