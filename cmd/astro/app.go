package main

import (
	"context"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/ciruzz00/astro/internal/cases"
	"github.com/ciruzz00/astro/internal/config"
	"github.com/ciruzz00/astro/internal/engine"
	"github.com/ciruzz00/astro/internal/httpx"
	"github.com/ciruzz00/astro/internal/provider"
	"github.com/ciruzz00/astro/internal/provider/abusech"
	"github.com/ciruzz00/astro/internal/provider/abuseipdb"
	"github.com/ciruzz00/astro/internal/provider/attack"
	"github.com/ciruzz00/astro/internal/provider/epss"
	"github.com/ciruzz00/astro/internal/provider/greynoise"
	"github.com/ciruzz00/astro/internal/provider/kev"
	"github.com/ciruzz00/astro/internal/provider/nvd"
	"github.com/ciruzz00/astro/internal/provider/otx"
	"github.com/ciruzz00/astro/internal/provider/oui"
	"github.com/ciruzz00/astro/internal/provider/shodan"
	"github.com/ciruzz00/astro/internal/provider/virustotal"
	"github.com/ciruzz00/astro/internal/render"
	"github.com/ciruzz00/astro/internal/store"
)

// app holds the shared dependencies of the commands.
type app struct {
	cfg     *config.Config
	store   *store.Store
	client  *http.Client
	sources []source
	engine  *engine.Engine
	cases   *cases.Service
}

// keyNeed says whether a source needs an API key.
type keyNeed int

const (
	keyNone keyNeed = iota
	keyOptional
	keyRequired
)

// source is a provider plus what it needs to run.
type source struct {
	provider provider.Provider
	keyEnv   string
	key      config.Secret
	need     keyNeed
	// local sources read offline datasets and never send indicators out.
	local bool
}

func (s source) enabled() bool { return s.need != keyRequired || s.key.IsSet() }

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
	a := &app{cfg: cfg, store: st, client: httpx.NewClient(cfg.HTTPTimeout)}
	a.sources = a.allSources()

	var enabled []provider.Provider
	for _, s := range a.sources {
		if s.enabled() {
			enabled = append(enabled, s.provider)
		}
	}
	a.engine = engine.New(enabled, engine.WithCache(st), engine.WithTimeout(cfg.HTTPTimeout+10*time.Second))
	a.cases = cases.New(st, a.engine)
	return a, nil
}

// allSources lists every source in display order, enabled or not.
func (a *app) allSources() []source {
	c, k := a.client, a.cfg.Keys
	return []source{
		{provider: attack.New(a.store), local: true},
		{provider: virustotal.New(c, virustotal.DefaultBase, k.VirusTotal), keyEnv: "ASTRO_VIRUSTOTAL_KEY", key: k.VirusTotal, need: keyRequired},
		{provider: abusech.NewMalwareBazaar(c, abusech.MalwareBazaarBase, k.AbuseCH), keyEnv: "ASTRO_ABUSECH_KEY", key: k.AbuseCH, need: keyRequired},
		{provider: abusech.NewThreatFox(c, abusech.ThreatFoxBase, k.AbuseCH), keyEnv: "ASTRO_ABUSECH_KEY", key: k.AbuseCH, need: keyRequired},
		{provider: abusech.NewURLhaus(c, abusech.URLhausBase, k.AbuseCH), keyEnv: "ASTRO_ABUSECH_KEY", key: k.AbuseCH, need: keyRequired},
		{provider: abuseipdb.New(c, abuseipdb.DefaultBase, k.AbuseIPDB), keyEnv: "ASTRO_ABUSEIPDB_KEY", key: k.AbuseIPDB, need: keyRequired},
		{provider: otx.New(c, otx.DefaultBase, k.OTX), keyEnv: "ASTRO_OTX_KEY", key: k.OTX, need: keyRequired},
		{provider: greynoise.New(c, greynoise.DefaultBase, k.GreyNoise), keyEnv: "ASTRO_GREYNOISE_KEY", key: k.GreyNoise, need: keyOptional},
		{provider: shodan.New(c, shodan.DefaultBase, shodan.DefaultInternetDB, k.Shodan), keyEnv: "ASTRO_SHODAN_KEY", key: k.Shodan, need: keyOptional},
		{provider: nvd.New(c, nvd.DefaultBase, k.NVD), keyEnv: "ASTRO_NVD_KEY", key: k.NVD, need: keyOptional},
		{provider: kev.New(a.store), local: true},
		{provider: epss.New(c, epss.DefaultBase)},
		{provider: oui.New(a.store), local: true},
	}
}

// localNames returns the names of the sources that work offline.
func (a *app) localNames() []string {
	var out []string
	for _, s := range a.sources {
		if s.local {
			out = append(out, s.provider.Name())
		}
	}
	return out
}

func (a *app) Close() error { return a.store.Close() }

// attackVersion returns the synced ATT&CK enterprise version, if any.
func (a *app) attackVersion(ctx context.Context) string {
	ds, err := a.store.Datasets(ctx)
	if err != nil {
		return ""
	}
	for _, d := range ds {
		if d.Name == "attack-enterprise" {
			return d.Version
		}
	}
	return ""
}

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
