package evidence

import (
	"github.com/ciruzz00/astro/internal/logs"
	"github.com/ciruzz00/astro/internal/logs/access"
	"github.com/ciruzz00/astro/internal/logs/bodyfile"
	"github.com/ciruzz00/astro/internal/logs/config"
	"github.com/ciruzz00/astro/internal/logs/docker"
	"github.com/ciruzz00/astro/internal/logs/evtx"
	"github.com/ciruzz00/astro/internal/logs/history"
	"github.com/ciruzz00/astro/internal/logs/live"
	"github.com/ciruzz00/astro/internal/logs/syslog"
	"github.com/ciruzz00/astro/internal/logs/utmp"
)

// DefaultParsers returns a parser for every supported log format.
func DefaultParsers() []logs.Parser {
	return []logs.Parser{
		syslog.New(),
		utmp.New(logs.KindWtmp), utmp.New(logs.KindBtmp), utmp.New(logs.KindUtmp),
		history.New(logs.KindBashHistory), history.New(logs.KindZshHistory),
		access.New(), docker.New(), bodyfile.New(), live.NewProcesses(), live.NewSockets(), config.New(),
		evtx.New(),
	}
}
