// Package abusech queries the abuse.ch services: MalwareBazaar, ThreatFox and URLhaus.
// All of them share one Auth-Key from https://auth.abuse.ch/.
package abusech

import (
	"encoding/json"
	"net/http"
	"time"

	"golang.org/x/time/rate"

	"github.com/ciruzz00/astro/internal/config"
)

// Default API endpoints.
const (
	MalwareBazaarBase = "https://mb-api.abuse.ch/api/v1/"
	ThreatFoxBase     = "https://threatfox-api.abuse.ch/api/v1/"
	URLhausBase       = "https://urlhaus-api.abuse.ch/v1/"
)

// client is the part shared by the three services.
type client struct {
	http    *http.Client
	base    string
	key     config.Secret
	limiter *rate.Limiter
}

func newClient(c *http.Client, base string, key config.Secret) client {
	return client{http: c, base: base, key: key, limiter: rate.NewLimiter(rate.Every(time.Second), 5)}
}

func (c client) header() http.Header { return http.Header{"Auth-Key": {c.key.Reveal()}} }

// cacheTTL is short: abuse.ch feeds change quickly.
const cacheTTL = time.Hour

// status is the envelope common to abuse.ch responses. On "no result"
// some endpoints put a message string in data instead of a list.
type status struct {
	QueryStatus string          `json:"query_status"`
	Data        json.RawMessage `json:"data"`
}
