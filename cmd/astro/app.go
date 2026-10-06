package main

import (
	"context"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/ciruzz00/astro/internal/cases"
	"github.com/ciruzz00/astro/internal/config"
	"github.com/ciruzz00/astro/internal/engine"
	"github.com/ciruzz00/astro/internal/httpx"
	"github.com/ciruzz00/astro/internal/provider"
	"github.com/ciruzz00/astro/internal/provider/abusech"
	"github.com/ciruzz00/astro/internal/provider/abuseipdb"
	"github.com/ciruzz00/astro/internal/provider/attack"
	"github.com/ciruzz00/astro/internal/provider/dns"
	"github.com/ciruzz00/astro/internal/provider/epss"
	"github.com/ciruzz00/astro/internal/provider/greynoise"
	"github.com/ciruzz00/astro/internal/provider/hostinfo"
	"github.com/ciruzz00/astro/internal/provider/kev"
	"github.com/ciruzz00/astro/internal/provider/nvd"
	"github.com/ciruzz00/astro/internal/provider/otx"
	"github.com/ciruzz00/astro/internal/provider/oui"
	"github.com/ciruzz00/astro/internal/provider/rdap"
	"github.com/ciruzz00/astro/internal/provider/shodan"
	"github.com/ciruzz00/astro/internal/provider/virustotal"
	"github.com/ciruzz00/astro/internal/provider/wikipedia"
	"github.com/ciruzz00/astro/internal/render"
	"github.com/ciruzz00/astro/internal/store"
)

// app holds the shared dependencies of the commands.
type app struct {
	cfg    *config.Config
	store  *store.Store
	client *http.Client
	engine *engine.Engine
	cases  *cases.Service

	// mu guards the fields below, rebuilt by reload when API keys change.
	mu        sync.RWMutex
	sources   []source
	keys      config.Keys
	keyOrigin map[string]string
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
	keyName  string // config.KeyDef name
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
	a.engine = engine.New(nil, engine.WithCache(st), engine.WithTimeout(cfg.HTTPTimeout+10*time.Second))
	a.cases = cases.New(st, a.engine)
	if err := a.reload(ctx); err != nil {
		_ = st.Close()
		return nil, err
	}
	return a, nil
}

// reload resolves the API keys (environment, then database, then config
// file) and rebuilds the sources and the engine providers.
func (a *app) reload(ctx context.Context) error {
	stored, err := a.store.ProviderKeys(ctx)
	if err != nil {
		return err
	}
	keys := a.cfg.Keys
	origin := map[string]string{}
	for _, d := range config.KeyDefs {
		fileOrEnv := a.cfg.KeyOrigin[d.Name]
		switch k, inDB := stored[d.Name]; {
		case fileOrEnv == config.OriginEnv:
			origin[d.Name] = config.OriginEnv
		case inDB:
			*d.Field(&keys) = config.Secret(k.Value)
			origin[d.Name] = config.OriginDatabase
		case fileOrEnv == config.OriginFile:
			origin[d.Name] = config.OriginFile
		}
	}
	sources := a.allSources(keys)
	var enabled []provider.Provider
	for _, s := range sources {
		if s.enabled() {
			enabled = append(enabled, s.provider)
		}
	}
	a.mu.Lock()
	a.sources, a.keys, a.keyOrigin = sources, keys, origin
	a.mu.Unlock()
	a.engine.SetProviders(enabled)
	return nil
}

// currentSources returns a snapshot of the sources.
func (a *app) currentSources() []source {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return append([]source(nil), a.sources...)
}

// allSources lists every source in display order, enabled or not.
func (a *app) allSources(k config.Keys) []source {
	c := a.client
	out := []source{
		{provider: attack.New(a.store), local: true},
		{provider: wikipedia.New(c, wikipedia.DefaultBase)},
		{provider: virustotal.New(c, virustotal.DefaultBase, k.VirusTotal), keyEnv: "ASTRO_VIRUSTOTAL_KEY", key: k.VirusTotal, need: keyRequired},
		{provider: abusech.NewMalwareBazaar(c, abusech.MalwareBazaarBase, k.AbuseCH), keyEnv: "ASTRO_ABUSECH_KEY", key: k.AbuseCH, need: keyRequired},
		{provider: abusech.NewThreatFox(c, abusech.ThreatFoxBase, k.AbuseCH), keyEnv: "ASTRO_ABUSECH_KEY", key: k.AbuseCH, need: keyRequired},
		{provider: abusech.NewURLhaus(c, abusech.URLhausBase, k.AbuseCH), keyEnv: "ASTRO_ABUSECH_KEY", key: k.AbuseCH, need: keyRequired},
		{provider: abuseipdb.New(c, abuseipdb.DefaultBase, k.AbuseIPDB), keyEnv: "ASTRO_ABUSEIPDB_KEY", key: k.AbuseIPDB, need: keyRequired},
		{provider: otx.New(c, otx.DefaultBase, k.OTX), keyEnv: "ASTRO_OTX_KEY", key: k.OTX, need: keyRequired},
		{provider: greynoise.New(c, greynoise.DefaultBase, k.GreyNoise), keyEnv: "ASTRO_GREYNOISE_KEY", key: k.GreyNoise, need: keyOptional},
		{provider: shodan.New(c, shodan.DefaultBase, shodan.DefaultInternetDB, k.Shodan), keyEnv: "ASTRO_SHODAN_KEY", key: k.Shodan, need: keyOptional},
		{provider: rdap.New(c, rdap.DefaultBase)},
		{provider: dns.New(c, dns.DefaultBase)},
		{provider: hostinfo.New(), local: true},
		{provider: nvd.New(c, nvd.DefaultBase, k.NVD), keyEnv: "ASTRO_NVD_KEY", key: k.NVD, need: keyOptional},
		{provider: kev.New(a.store), local: true},
		{provider: epss.New(c, epss.DefaultBase)},
		{provider: oui.New(a.store), local: true},
	}
	// Record which configurable key each source uses.
	for i := range out {
		for _, d := range config.KeyDefs {
			if out[i].keyEnv == d.Env {
				out[i].keyName = d.Name
			}
		}
	}
	return out
}

// localNames returns the names of the sources that work offline.
func (a *app) localNames() []string {
	var out []string
	for _, s := range a.currentSources() {
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

// isTerminal reports whether w is an interactive terminal.
func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

// style enables colors only on an interactive terminal, honoring NO_COLOR.
func style(w io.Writer, g *globalFlags) render.Style {
	if g.noColor || os.Getenv("NO_COLOR") != "" {
		return render.Style{}
	}
	return render.Style{Color: isTerminal(w)}
}
