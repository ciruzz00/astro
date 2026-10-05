// Package report exports cases as JSON, Markdown, STIX 2.1 bundles and
// MITRE ATT&CK Navigator layers.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/ciruzz00/astro/internal/cases"
)

// Formats lists the supported export formats.
var Formats = []string{"pdf", "md", "json", "stix", "navigator"}

// Options tunes an export.
type Options struct {
	// Version is the astro version, recorded in generated documents.
	Version string
	// AttackVersion is the ATT&CK dataset version, used by Navigator layers.
	AttackVersion string
	// Now is the generation time (defaults to time.Now).
	Now time.Time
}

// Write exports v in the given format.
func Write(w io.Writer, format string, v *cases.View, o Options) error {
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	o.Now = o.Now.UTC()
	switch strings.ToLower(format) {
	case "json":
		return writeJSON(w, v)
	case "pdf":
		return PDF(w, v, o)
	case "md", "markdown":
		return Markdown(w, v, o)
	case "stix":
		return STIX(w, v, o)
	case "navigator":
		return Navigator(w, v, o)
	}
	return fmt.Errorf("unknown format %q (use %s)", format, strings.Join(Formats, ", "))
}

// Extension returns the usual file extension of a format.
func Extension(format string) string {
	switch strings.ToLower(format) {
	case "pdf":
		return ".pdf"
	case "md", "markdown":
		return ".md"
	case "stix":
		return ".stix.json"
	case "navigator":
		return ".layer.json"
	}
	return ".json"
}

// ContentType returns the MIME type of a format.
func ContentType(format string) string {
	switch Extension(format) {
	case ".pdf":
		return "application/pdf"
	case ".md":
		return "text/markdown; charset=utf-8"
	}
	return "application/json"
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
