package tui

import (
	"charm.land/lipgloss/v2"

	"github.com/ciruzz00/astro/internal/provider"
)

// ANSI palette indexes follow the user's terminal theme, so the interface is
// readable on light and dark backgrounds alike.
var (
	cAccent = lipgloss.Color("12")
	cMuted  = lipgloss.Color("8")
	cRed    = lipgloss.Color("9")
	cYellow = lipgloss.Color("11")
	cGreen  = lipgloss.Color("10")
	cBlue   = lipgloss.Color("14")

	sBrand    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("15")).Background(cAccent).Padding(0, 1)
	sTab      = lipgloss.NewStyle().Padding(0, 1).Foreground(cMuted)
	sTabOn    = lipgloss.NewStyle().Padding(0, 1).Bold(true).Underline(true)
	sMuted    = lipgloss.NewStyle().Foreground(cMuted)
	sBold     = lipgloss.NewStyle().Bold(true)
	sSelected = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("15")).Background(cAccent)
	sError    = lipgloss.NewStyle().Foreground(cRed)
	sOK       = lipgloss.NewStyle().Foreground(cGreen)
	sKey      = lipgloss.NewStyle().Bold(true).Foreground(cAccent)
	sPane     = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(cMuted).Padding(0, 1)
	sPaneOn   = sPane.BorderForeground(cAccent)
	sPrompt   = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(cYellow).Padding(0, 1)
)

func verdictStyle(v provider.Verdict) lipgloss.Style {
	switch v {
	case provider.VerdictMalicious:
		return lipgloss.NewStyle().Bold(true).Foreground(cRed)
	case provider.VerdictSuspicious:
		return lipgloss.NewStyle().Bold(true).Foreground(cYellow)
	case provider.VerdictClean:
		return lipgloss.NewStyle().Foreground(cGreen)
	case provider.VerdictInfo:
		return lipgloss.NewStyle().Foreground(cBlue)
	}
	return sMuted
}

func verdictLabel(v provider.Verdict) string {
	if v == "" {
		return "no verdict"
	}
	return string(v)
}

// tlpStyle uses the TLP 2.0 colors on a black background.
func tlpStyle(tlp string) lipgloss.Style {
	s := lipgloss.NewStyle().Bold(true).Background(lipgloss.Color("0"))
	switch tlp {
	case "RED":
		return s.Foreground(lipgloss.Color("#ff2b2b"))
	case "AMBER", "AMBER+STRICT":
		return s.Foreground(lipgloss.Color("#ffc000"))
	case "GREEN":
		return s.Foreground(lipgloss.Color("#33ff00"))
	}
	return s.Foreground(lipgloss.Color("#ffffff"))
}
