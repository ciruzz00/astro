// Package docker parses the json-file logs Docker keeps for each container
// (/var/lib/docker/containers/<id>/<id>-json.log). HTTP requests written by
// the containerized service are recognized as access log lines.
package docker

import (
	"context"
	"encoding/json"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ciruzz00/astro/internal/logs"
	"github.com/ciruzz00/astro/internal/logs/access"
)

// KindOutput is container output that is not an HTTP request.
const KindOutput = "container-output"

var reContainerID = regexp.MustCompile(`[0-9a-f]{64}`)

// Parser reads Docker json-file logs.
type Parser struct{}

// New returns a Docker log parser.
func New() *Parser { return &Parser{} }

// Kind implements logs.Parser.
func (*Parser) Kind() logs.Kind { return logs.KindDocker }

type entry struct {
	Log    string `json:"log"`
	Stream string `json:"stream"`
	Time   string `json:"time"`
}

// Parse implements logs.Parser. Docker splits lines longer than 16 KiB into
// partial entries without the trailing newline: they are joined again.
func (*Parser) Parse(ctx context.Context, r io.Reader, opts logs.Options, emit func(*logs.Event) error) (logs.Stats, error) {
	var st logs.Stats
	container := ""
	if id := reContainerID.FindString(opts.Path); id != "" {
		container = id[:12]
	}
	var partial strings.Builder
	var first time.Time
	firstLine := 0
	long, err := logs.ScanLines(ctx, r, logs.MaxLine, func(n int, line string) error {
		line, _ = logs.StripNUL(line)
		if strings.TrimSpace(line) == "" {
			return nil
		}
		var en entry
		if err := json.Unmarshal([]byte(line), &en); err != nil {
			st.Errors++
			return nil
		}
		t, err := time.Parse(time.RFC3339Nano, en.Time)
		if err != nil {
			st.Errors++
			return nil
		}
		if partial.Len() == 0 {
			first, firstLine = t.UTC(), n
		}
		if partial.Len()+len(en.Log) <= logs.MaxLine {
			partial.WriteString(en.Log)
		}
		if !strings.HasSuffix(en.Log, "\n") && partial.Len() < logs.MaxLine {
			return nil // more fragments follow
		}
		text := strings.TrimRight(partial.String(), "\r\n")
		partial.Reset()

		e := &logs.Event{Time: first, Source: opts.Source, Raw: text, Message: text, Kind: KindOutput,
			Process: container, Ref: logs.EvidenceRef{Record: "line " + strconv.Itoa(firstLine)}}
		if req, ok := access.ParseLine(text); ok {
			req.Fill(e)
			if e.Fields == nil {
				e.Fields = map[string]string{}
			}
			e.Fields["logged_at"] = req.Time.Format(time.RFC3339)
		}
		if e.Fields == nil {
			e.Fields = map[string]string{}
		}
		e.Fields["stream"] = en.Stream
		if container != "" {
			e.Fields["container_id"] = container
		}
		if err := emit(e); err != nil {
			return err
		}
		st.Events++
		return nil
	})
	if err == nil && partial.Len() > 0 { // last entry without a newline
		st.Errors++
	}
	st.Errors += long
	return st, err
}
