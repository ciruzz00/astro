package report

import (
	"embed"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/signintech/gopdf"
	"golang.org/x/image/font/sfnt"

	"github.com/ciruzz00/astro/internal/cases"
	"github.com/ciruzz00/astro/internal/ioc"
	"github.com/ciruzz00/astro/internal/provider"
	"github.com/ciruzz00/astro/internal/render"
)

// A4 portrait, in points.
const (
	pageW    = 595.28
	pageH    = 841.89
	margin   = 48.0
	contentW = pageW - 2*margin
	topY     = 66.0       // content start, below the running header
	bottomY  = pageH - 66 // content end, above the footer
)

// Fonts: IBM Plex Sans and Mono, SIL Open Font License 1.1 (fonts/OFL.txt).
// They cover Latin, Greek and Cyrillic; other runes are printed as '?'.
const (
	fSans   = "sans"
	fSansMd = "sans-medium"
	fSansSb = "sans-semibold"
	fMono   = "mono"
	fMonoMd = "mono-medium"
)

var fontFiles = []struct{ name, file string }{
	{fSans, "IBMPlexSans-Regular.ttf"},
	{fSansMd, "IBMPlexSans-Medium.ttf"},
	{fSansSb, "IBMPlexSans-SemiBold.ttf"},
	{fMono, "IBMPlexMono-Regular.ttf"},
	{fMonoMd, "IBMPlexMono-Medium.ttf"},
}

//go:embed fonts/*.ttf
var fontFS embed.FS

// loadFonts reads the embedded fonts once.
var loadFonts = sync.OnceValues(func() (map[string][]byte, error) {
	out := map[string][]byte{}
	for _, f := range fontFiles {
		b, err := fontFS.ReadFile("fonts/" + f.file)
		if err != nil {
			return nil, err
		}
		out[f.name] = b
	}
	return out, nil
})

type rgb struct{ r, g, b uint8 }

// tone is the text and background color of a label.
type tone struct{ fg, bg rgb }

var (
	colInk         = rgb{15, 23, 42}
	colText        = rgb{30, 41, 59}
	colMuted       = rgb{100, 116, 139}
	colFaint       = rgb{148, 163, 184}
	colBorder      = rgb{226, 232, 240}
	colSurface     = rgb{248, 250, 252}
	colBand        = rgb{11, 18, 32}
	colBandText    = rgb{148, 163, 184}
	colAccent      = rgb{59, 91, 255}
	colAccentLight = rgb{165, 180, 252}
	colWhite       = rgb{255, 255, 255}

	verdictTone = map[provider.Verdict]tone{
		provider.VerdictMalicious:  {rgb{185, 28, 28}, rgb{254, 226, 226}},
		provider.VerdictSuspicious: {rgb{161, 75, 7}, rgb{254, 243, 199}},
		provider.VerdictClean:      {rgb{21, 118, 61}, rgb{220, 252, 231}},
		provider.VerdictInfo:       {rgb{29, 78, 216}, rgb{219, 234, 254}},
	}
	toneNone = tone{rgb{71, 85, 105}, rgb{241, 245, 249}}
	// Solid colors for charts.
	verdictSolid = map[provider.Verdict]rgb{
		provider.VerdictMalicious:  {220, 38, 38},
		provider.VerdictSuspicious: {217, 119, 6},
		provider.VerdictClean:      {22, 163, 74},
		provider.VerdictInfo:       {37, 99, 235},
	}

	// TLP 2.0 colors defined by FIRST, printed on black.
	tlpCol = map[string]rgb{
		cases.TLPRed: {255, 43, 43}, cases.TLPAmber: {255, 192, 0}, cases.TLPAmberStrict: {255, 192, 0},
		cases.TLPGreen: {51, 255, 0}, cases.TLPClear: {255, 255, 255},
	}
	// TLP 2.0 definitions, from FIRST.
	tlpMeaning = map[string]string{
		cases.TLPClear:       "Recipients can spread this to the world: there is no limit on disclosure.",
		cases.TLPGreen:       "Limited disclosure: recipients can spread this within their community, but not via publicly accessible channels.",
		cases.TLPAmber:       "Limited disclosure: recipients can only spread this on a need-to-know basis within their organization and its clients.",
		cases.TLPAmberStrict: "Limited disclosure: recipients can only spread this on a need-to-know basis within their organization.",
		cases.TLPRed:         "For the eyes and ears of individual recipients only: no further disclosure.",
	}
)

// Limits that keep a report readable.
const (
	maxFindings = 15
	maxFields   = 8
)

type pdfDoc struct {
	gp     *gopdf.GoPdf
	glyphs *sfnt.Font
	buf    sfnt.Buffer
	v      *cases.View
	o      Options
	title  string
}

// PDF writes a case report as an A4 PDF. The TLP label is printed at the top
// and bottom of every page, as TLP 2.0 requires.
func PDF(w io.Writer, v *cases.View, o Options) error {
	fonts, err := loadFonts()
	if err != nil {
		return fmt.Errorf("load fonts: %w", err)
	}
	gp := &gopdf.GoPdf{}
	gp.Start(gopdf.Config{PageSize: *gopdf.PageSizeA4, Unit: gopdf.UnitPT})
	gp.SetCompressLevel(9)
	for _, f := range fontFiles {
		if err := gp.AddTTFFontData(f.name, fonts[f.name]); err != nil {
			return fmt.Errorf("load font: %w", err)
		}
	}
	glyphs, err := sfnt.Parse(fonts[fSans])
	if err != nil {
		return err
	}
	title := v.Case.Title
	if title == "" {
		title = v.Case.Name
	}
	gp.SetInfo(gopdf.PdfInfo{
		Title: "TLP:" + v.Case.TLP + " " + title, Subject: "astro case " + v.Case.Name,
		Creator: "astro " + o.Version, Producer: "astro", CreationDate: o.Now,
	})
	d := &pdfDoc{gp: gp, glyphs: glyphs, v: v, o: o, title: title}

	gp.AddPage()
	d.cover()
	d.executiveSummary()
	d.keyFindings()
	d.indicators()
	d.attack()
	d.details()
	d.notes()
	d.appendix()
	d.furniture()
	_, err = gp.WriteTo(w)
	return err
}

// --- page furniture ---

// furniture draws the running header and the footer once every page exists,
// so the footer can say "page X of Y".
func (d *pdfDoc) furniture() {
	n := d.gp.GetNumberOfPages()
	for p := 1; p <= n; p++ {
		if err := d.gp.SetPage(p); err != nil {
			return
		}
		if p > 1 {
			brand := d.width(fSansSb, 8, "astro")
			d.text(margin, 24, fSansSb, 8, colAccent, "astro")
			d.text(margin+brand+6, 24, fSans, 8, colMuted, d.fit(d.title, fSans, 8, contentW-brand-110))
			d.tlpBadge(pageW-margin-d.tlpWidth(), 21)
			d.hline(margin, pageW-margin, 42, colBorder, 0.6)
		}
		d.hline(margin, pageW-margin, pageH-48, colBorder, 0.6)
		left := d.v.Case.Name + " · " + d.o.Now.Format("2006-01-02 15:04 UTC")
		d.text(margin, pageH-38, fSans, 7.5, colMuted, d.fit(left, fSans, 7.5, contentW/2-60))
		d.tlpBadge(pageW/2-d.tlpWidth()/2, pageH-40)
		page := fmt.Sprintf("Page %d of %d", p, n)
		d.text(pageW-margin-d.width(fSans, 7.5, page), pageH-38, fSans, 7.5, colMuted, page)
	}
}

func (d *pdfDoc) tlpLabel() string { return "TLP:" + d.v.Case.TLP }

func (d *pdfDoc) tlpWidth() float64 { return d.width(fSansSb, 8, d.tlpLabel()) + 12 }

func (d *pdfDoc) tlpBadge(x, y float64) {
	d.fill(rgb{0, 0, 0})
	_ = d.gp.Rectangle(x, y, x+d.tlpWidth(), y+14, "F", 2, 4)
	d.text(x+6, y+2.5, fSansSb, 8, tlpCol[d.v.Case.TLP], d.tlpLabel())
}

// --- sections ---

func (d *pdfDoc) cover() {
	c := d.v.Case
	_ = d.gp.SetFont(fSansSb, "", 24)
	lines := d.wrap(d.title, contentW-20, false)
	if len(lines) > 3 {
		lines = lines[:3]
		lines[2] = d.fit(lines[2]+"…", fSansSb, 24, contentW-20)
	}
	bandH := 118 + 30*float64(len(lines))
	d.fill(colBand)
	d.gp.RectFromUpperLeftWithStyle(0, 0, pageW, bandH, "F")
	d.fill(colAccent)
	d.gp.RectFromUpperLeftWithStyle(0, bandH, pageW, 3, "F")

	d.text(margin, 30, fSansSb, 14, colWhite, "astro")
	brand := d.width(fSansSb, 14, "astro")
	d.spaced(margin+brand+12, 35, fSansMd, 7, colAccentLight, "THREAT INTELLIGENCE REPORT")
	d.tlpBadge(pageW-margin-d.tlpWidth(), 30)

	y := 78.0
	for _, l := range lines {
		d.text(margin, y, fSansSb, 24, colWhite, l)
		y += 30
	}
	d.text(margin, y+8, fSans, 9.5, colBandText, "Case "+c.Name+"  ·  generated "+d.o.Now.Format("2 January 2006, 15:04 UTC"))

	y = bandH + 24
	tags := strings.Join(c.Tags, ", ")
	if tags == "" {
		tags = "—"
	}
	meta := []struct{ k, v string }{
		{"Status", orDefault(c.Status, "—")},
		{"Created", c.CreatedAt.Format("2006-01-02 15:04 UTC")},
		{"Last updated", c.UpdatedAt.Format("2006-01-02 15:04 UTC")},
		{"Tags", tags},
	}
	colW := contentW / float64(len(meta))
	for k, m := range meta {
		x := margin + float64(k)*colW
		d.spaced(x, y, fSansMd, 6.8, colMuted, strings.ToUpper(m.k))
		d.text(x, y+12, fSans, 9.5, colText, d.fit(m.v, fSans, 9.5, colW-12))
	}
	d.gp.SetY(y + 34)
	if c.Description != "" {
		d.gp.SetY(d.gp.GetY() + 4)
		d.paragraph(margin, contentW, ioc.DefangText(c.Description), fSans, 10, colText, 14.5)
	}
}

func (d *pdfDoc) executiveSummary() {
	d.heading("Executive summary")
	mal, sus, clean, pending := d.v.Counts()
	total := len(d.v.Items)
	info := total - mal - sus - clean - pending
	overall := overallVerdict(d.v)

	label, t := "NOT ASSESSED", toneNone
	if vt, ok := verdictTone[overall]; ok {
		label, t = strings.ToUpper(string(overall)), vt
	}
	_ = d.gp.SetFont(fSans, "", 9.5)
	lines := d.wrap(assessment(total, mal, sus, clean, info, pending), contentW-48, false)
	y := d.gp.GetY()
	h := 54 + 13.5*float64(len(lines))
	d.panel(margin, y, contentW, h)
	bar := colFaint
	if c, ok := verdictSolid[overall]; ok {
		bar = c
	}
	d.fill(bar)
	_ = d.gp.Rectangle(margin+14, y+14, margin+17, y+h-14, "F", 1.5, 3)
	d.spaced(margin+30, y+14, fSansMd, 6.8, colMuted, "OVERALL ASSESSMENT")
	d.pill(margin+30, y+26, label, t, 8)
	d.lines(lines, margin+30, y+46, fSans, 9.5, colText, 13.5)
	y += h + 12

	tiles := []struct {
		label string
		n     int
		c     rgb
	}{
		{"Indicators", total, colInk},
		{"Malicious", mal, verdictSolid[provider.VerdictMalicious]},
		{"Suspicious", sus, verdictSolid[provider.VerdictSuspicious]},
		{"Clean", clean, verdictSolid[provider.VerdictClean]},
		{"Context only", info, verdictSolid[provider.VerdictInfo]},
		{"Not searched", pending, colFaint},
	}
	gap := 6.0
	w := (contentW - gap*float64(len(tiles)-1)) / float64(len(tiles))
	for k, s := range tiles {
		x := margin + float64(k)*(w+gap)
		d.fill(colWhite)
		d.stroke(colBorder)
		d.gp.SetLineWidth(0.7)
		_ = d.gp.Rectangle(x, y, x+w, y+50, "FD", 4, 6)
		c := s.c
		if s.n == 0 && k > 0 {
			c = colFaint
		}
		d.text(x+10, y+8, fSansSb, 18, c, fmt.Sprint(s.n))
		d.text(x+10, y+32, fSansMd, 7.5, colMuted, s.label)
	}
	y += 60

	// Distribution of the verdicts.
	if total > 0 {
		segs := []struct {
			n int
			c rgb
		}{
			{mal, verdictSolid[provider.VerdictMalicious]}, {sus, verdictSolid[provider.VerdictSuspicious]},
			{clean, verdictSolid[provider.VerdictClean]}, {info, verdictSolid[provider.VerdictInfo]},
			{pending, colBorder},
		}
		x := margin
		for _, s := range segs {
			if s.n == 0 {
				continue
			}
			sw := contentW * float64(s.n) / float64(total)
			d.fill(s.c)
			d.gp.RectFromUpperLeftWithStyle(x, y, max(sw-1.5, 1), 5, "F")
			x += sw
		}
		y += 14
	}
	d.gp.SetY(y)
}

// assessment is the one-paragraph conclusion of the executive summary.
func assessment(total, mal, sus, clean, info, pending int) string {
	switch {
	case total == 0:
		return "The case has no indicators yet."
	case pending == total:
		return fmt.Sprintf("None of the %s has been searched yet: run a search on the case to assess it.", plural(total, "indicator"))
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d of %d indicators were searched across the configured threat intelligence sources.", total-pending, total)
	switch {
	case mal > 0 && sus > 0:
		fmt.Fprintf(&b, " %d rated malicious and %d suspicious by at least one source: they are listed under Key findings.", mal, sus)
	case mal > 0:
		fmt.Fprintf(&b, " %d rated malicious by at least one source: listed under Key findings.", mal)
	case sus > 0:
		fmt.Fprintf(&b, " %d rated suspicious by at least one source: listed under Key findings.", sus)
	default:
		b.WriteString(" No source rated any of them malicious or suspicious.")
	}
	if clean > 0 {
		fmt.Fprintf(&b, " %d rated clean by reputation sources.", clean)
	}
	if info > 0 {
		fmt.Fprintf(&b, " %d with contextual data only (registration, DNS, ATT&CK, vulnerability data).", info)
	}
	if pending > 0 {
		fmt.Fprintf(&b, " %d not searched yet.", pending)
	}
	return b.String()
}

func (d *pdfDoc) keyFindings() {
	var flagged []cases.Item
	for _, it := range d.v.Items {
		if it.SearchedAt != nil && it.Verdict.Rank() >= 2 {
			flagged = append(flagged, it)
		}
	}
	sort.SliceStable(flagged, func(a, b int) bool { return flagged[a].Verdict.Rank() > flagged[b].Verdict.Rank() })

	d.heading("Key findings")
	if len(flagged) == 0 {
		d.paragraph(margin, contentW, "No indicator was rated malicious or suspicious by the consulted sources.", fSans, 9.5, colMuted, 13.5)
		return
	}
	const iocX, provX, sumX = margin + 88, margin + 88, margin + 178
	for k, it := range flagged {
		if k == maxFindings {
			d.paragraph(margin, contentW, fmt.Sprintf("…and %d more: see Indicators and Indicator details.", len(flagged)-maxFindings), fSans, 9, colMuted, 13)
			break
		}
		_ = d.gp.SetFont(fMonoMd, "", 9.5)
		iocLines := d.wrap(ioc.Defang(it.Indicator), margin+contentW-iocX-60, true)
		type reason struct {
			provider string
			lines    []string
		}
		var reasons []reason
		h := 13*float64(len(iocLines)) + 8
		_ = d.gp.SetFont(fSans, "", 8.6)
		for _, r := range resultsOf(it) {
			if r.Verdict.Rank() >= 2 {
				l := d.wrap(ioc.DefangText(orDefault(r.Summary, string(r.Verdict))), margin+contentW-sumX, false)
				reasons = append(reasons, reason{r.Provider, l})
				h += 11.5 * float64(len(l))
			}
		}
		h += 10
		d.ensure(h)
		y := d.gp.GetY()
		label, t := itemVerdict(it)
		d.pill(margin, y, label, t, 7)
		d.lines(iocLines, iocX, y, fMonoMd, 9.5, colInk, 13)
		typ := string(it.Indicator.Type)
		d.text(margin+contentW-d.width(fSans, 7.8, typ), y+1.5, fSans, 7.8, colMuted, typ)
		ry := y + 13*float64(len(iocLines)) + 5
		for _, r := range reasons {
			d.text(provX, ry, fSansSb, 8.6, colText, r.provider)
			d.lines(r.lines, sumX, ry, fSans, 8.6, colText, 11.5)
			ry += 11.5 * float64(len(r.lines))
		}
		d.hline(margin, margin+contentW, ry+5, colBorder, 0.5)
		d.gp.SetY(ry + 12)
	}
}

// Indicator table column widths.
var cols = []float64{84, 84, contentW - 84 - 84 - 112, 112}

func (d *pdfDoc) tableHeader(headers []string, widths []float64) {
	y := d.gp.GetY()
	x := margin
	for k, h := range headers {
		d.spaced(x+6, y, fSansMd, 6.8, colMuted, strings.ToUpper(h))
		x += widths[k]
	}
	d.hline(margin, margin+contentW, y+14, colBorder, 0.9)
	d.gp.SetY(y + 18)
}

func (d *pdfDoc) indicators() {
	if len(d.v.Items) == 0 {
		return
	}
	d.heading("Indicators")
	headers := []string{"Verdict", "Type", "Indicator (defanged)", "Flagged by"}
	d.tableHeader(headers, cols)
	for k, it := range d.v.Items {
		_ = d.gp.SetFont(fMono, "", 8.4)
		iocLines := d.wrap(ioc.Defang(it.Indicator), cols[2]-12, true)
		_ = d.gp.SetFont(fSans, "", 8)
		flagLines := d.wrap(strings.Join(flaggedBy(it), ", "), cols[3]-12, false)
		rowH := 10 + 11*float64(max(len(iocLines), len(flagLines), 1))
		if d.gp.GetY()+rowH > bottomY {
			d.newPage()
			d.tableHeader(headers, cols)
		}
		y := d.gp.GetY()
		if k%2 == 1 {
			d.fill(colSurface)
			d.gp.RectFromUpperLeftWithStyle(margin, y, contentW, rowH, "F")
		}
		label, t := itemVerdict(it)
		d.pill(margin+6, y+4, label, t, 6.6)
		d.text(margin+cols[0]+6, y+5, fSans, 8, colMuted, string(it.Indicator.Type))
		d.lines(iocLines, margin+cols[0]+cols[1]+6, y+5, fMono, 8.4, colInk, 11)
		d.lines(flagLines, margin+cols[0]+cols[1]+cols[2]+6, y+5.5, fSans, 8, colText, 11)
		d.gp.SetY(y + rowH)
	}
	d.hline(margin, margin+contentW, d.gp.GetY(), colBorder, 0.6)
	d.gp.SetY(d.gp.GetY() + 6)
}

var reAttackID = regexp.MustCompile(`^(T\d{4}(\.\d{3})?|TA\d{4}|G\d{4}|S\d{4}|M\d{4}|C\d{4})$`)

// attack lists the MITRE ATT&CK objects in the case: ATT&CK indicators,
// names resolved by the ATT&CK source and techniques cited by OTX pulses.
func (d *pdfDoc) attack() {
	type row struct{ id, name, context string }
	rows := map[string]*row{}
	for _, it := range d.v.Items {
		if it.Report == nil {
			continue
		}
		for _, r := range it.Report.Results {
			if r.Provider != "mitre-attack" || !r.Found {
				continue
			}
			id, name, _ := strings.Cut(r.Summary, " ")
			if !reAttackID.MatchString(id) {
				continue
			}
			context := "in the case"
			if !strings.EqualFold(id, it.Indicator.Value) {
				context = "matches " + ioc.Defang(it.Indicator)
			}
			if _, ok := rows[id]; !ok {
				rows[id] = &row{id, name, context}
			}
		}
		for _, id := range otxTechniques(it) {
			id = strings.ToUpper(id)
			if !reAttackID.MatchString(id) {
				continue
			}
			if _, ok := rows[id]; !ok {
				rows[id] = &row{id, "", "cited by OTX pulses on " + ioc.Defang(it.Indicator)}
			}
		}
	}
	if len(rows) == 0 {
		return
	}
	list := make([]*row, 0, len(rows))
	for _, r := range rows {
		list = append(list, r)
	}
	sort.Slice(list, func(a, b int) bool { return list[a].id < list[b].id })

	d.heading("MITRE ATT&CK")
	widths := []float64{78, 220, contentW - 78 - 220}
	headers := []string{"ID", "Name", "Context"}
	d.tableHeader(headers, widths)
	for _, r := range list {
		_ = d.gp.SetFont(fSans, "", 8.4)
		nameLines := d.wrap(orDefault(r.name, "—"), widths[1]-12, false)
		_ = d.gp.SetFont(fSans, "", 8)
		ctxLines := d.wrap(r.context, widths[2]-12, false)
		rowH := 9 + 11*float64(max(len(nameLines), len(ctxLines)))
		if d.gp.GetY()+rowH > bottomY {
			d.newPage()
			d.tableHeader(headers, widths)
		}
		y := d.gp.GetY()
		d.text(margin+6, y+5, fMonoMd, 8.4, colAccent, r.id)
		d.lines(nameLines, margin+widths[0]+6, y+5, fSans, 8.4, colInk, 11)
		d.lines(ctxLines, margin+widths[0]+widths[1]+6, y+5.4, fSans, 8, colMuted, 11)
		d.hline(margin, margin+contentW, y+rowH, colBorder, 0.4)
		d.gp.SetY(y + rowH)
	}
	d.gp.SetY(d.gp.GetY() + 6)
}

func (d *pdfDoc) details() {
	first := true
	for _, it := range d.v.Items {
		if it.Report == nil {
			continue
		}
		if first {
			d.heading("Indicator details")
			first = false
		}
		d.ensure(100)

		label, t := itemVerdict(it)
		pw := d.pillWidth(label, 7)
		_ = d.gp.SetFont(fMonoMd, "", 10)
		iocLines := d.wrap(ioc.Defang(it.Indicator), contentW-pw-40, true)
		meta := string(it.Indicator.Type)
		if it.SearchedAt != nil {
			meta += "  ·  searched " + it.SearchedAt.Format("2006-01-02 15:04 UTC")
		}
		if it.Note != "" {
			meta += "  ·  note: " + ioc.DefangText(it.Note)
		}
		_ = d.gp.SetFont(fSans, "", 7.8)
		metaLines := d.wrap(meta, contentW-pw-40, false)
		y := d.gp.GetY()
		h := 20 + 13*float64(len(iocLines)) + 10.5*float64(len(metaLines))
		d.panel(margin, y, contentW, h)
		d.lines(iocLines, margin+12, y+9, fMonoMd, 10, colInk, 13)
		d.lines(metaLines, margin+12, y+11+13*float64(len(iocLines)), fSans, 7.8, colMuted, 10.5)
		d.pill(margin+contentW-12-pw, y+9, label, t, 7)
		d.gp.SetY(y + h + 6)

		results := append([]*provider.Result(nil), it.Report.Results...)
		sort.SliceStable(results, func(a, b int) bool { return results[a].Verdict.Rank() > results[b].Verdict.Rank() })
		var noData []string
		for _, r := range results {
			if !r.Found && r.Error == "" {
				noData = append(noData, r.Provider)
				continue
			}
			d.result(r)
		}
		if len(noData) > 0 {
			d.gp.SetY(d.gp.GetY() + 3)
			d.paragraph(margin+12, contentW-12, "No data from: "+strings.Join(noData, ", "), fSans, 7.8, colFaint, 10.5)
		}
		d.gp.SetY(d.gp.GetY() + 14)
	}
}

// result prints one source's answer; sources that flag the indicator also
// show their fields.
func (d *pdfDoc) result(r *provider.Result) {
	const provX, pillX, sumX = margin + 12, margin + 100, margin + 168
	sumW := margin + contentW - sumX
	status, c := r.Summary, colText
	if r.Error != "" {
		status, c = "error: "+r.Error, verdictTone[provider.VerdictSuspicious].fg
	}
	// Summaries can name hosts and addresses (DNS, RDAP): defang them too.
	_ = d.gp.SetFont(fSans, "", 8.6)
	lines := d.wrap(ioc.DefangText(status), sumW, false)

	type field struct{ name, value []string }
	var fields []field
	fh := 0.0
	if r.Verdict.Rank() >= 2 {
		for k, f := range r.Fields {
			if k == maxFields {
				break
			}
			value := provider.Truncate(strings.ReplaceAll(f.Value, "\n", ", "), 300)
			_ = d.gp.SetFont(fSansMd, "", 7.6)
			name := d.wrap(f.Name, 86, false)
			_ = d.gp.SetFont(fSans, "", 7.6)
			val := d.wrap(ioc.DefangText(value), sumW-92, false)
			fields = append(fields, field{name, val})
			fh += 10 * float64(max(len(name), len(val)))
		}
		if fh > 0 {
			fh += 4
		}
	}
	h := 11.5*float64(len(lines)) + fh + 7
	d.ensure(h)
	y := d.gp.GetY()
	d.text(provX, y, fSansSb, 8.6, colInk, r.Provider)
	if strings.HasPrefix(r.Reference, "https://") {
		d.gp.AddExternalLink(r.Reference, provX, y, d.width(fSansSb, 8.6, r.Provider), 11)
	}
	if vt, ok := verdictTone[r.Verdict]; ok && r.Found && r.Verdict.Rank() >= 1 {
		d.pill(pillX, y-0.5, strings.ToUpper(string(r.Verdict)), vt, 6.4)
	}
	d.lines(lines, sumX, y, fSans, 8.6, c, 11.5)
	fy := y + 11.5*float64(len(lines)) + 3
	for _, f := range fields {
		d.lines(f.name, sumX, fy, fSansMd, 7.6, colMuted, 10)
		d.lines(f.value, sumX+92, fy, fSans, 7.6, colText, 10)
		fy += 10 * float64(max(len(f.name), len(f.value)))
	}
	d.hline(provX, margin+contentW, y+h-3.5, colBorder, 0.4)
	d.gp.SetY(y + h)
}

func (d *pdfDoc) notes() {
	if len(d.v.Case.Notes) == 0 {
		return
	}
	d.heading("Analyst notes")
	for _, n := range d.v.Case.Notes {
		d.ensure(44)
		y := d.gp.GetY()
		d.fill(colAccent)
		d.gp.RectFromUpperLeftWithStyle(margin, y-1, 2.5, 14, "F")
		d.spaced(margin+14, y+1, fSansMd, 6.8, colMuted, n.CreatedAt.Format("2006-01-02 15:04 UTC"))
		y += 14
		_ = d.gp.SetFont(fSans, "", 9.5)
		for _, l := range d.wrap(ioc.DefangText(n.Body), contentW-14, false) {
			if y+13.5 > bottomY {
				d.newPage()
				y = d.gp.GetY()
			}
			d.fill(colAccent)
			d.gp.RectFromUpperLeftWithStyle(margin, y-1, 2.5, 13.5, "F")
			d.text(margin+14, y, fSans, 9.5, colText, l)
			y += 13.5
		}
		d.gp.SetY(y + 12)
	}
}

func (d *pdfDoc) appendix() {
	d.heading("About this report")

	d.subheading("Verdicts")
	legend := []struct {
		v    provider.Verdict
		text string
	}{
		{provider.VerdictMalicious, "At least one source rates the indicator malicious: for example several antivirus detections, a known command-and-control server or a known malware sample."},
		{provider.VerdictSuspicious, "At least one source reports something worth investigating that is not conclusive: few detections, a newly registered domain, look-alike characters."},
		{provider.VerdictClean, "Reputation sources know the indicator and found nothing malicious. Absence of evidence is not proof of safety."},
		{provider.VerdictInfo, "Only contextual data is available, such as registration, DNS, ATT&CK or vulnerability data."},
	}
	for _, l := range legend {
		_ = d.gp.SetFont(fSans, "", 8.6)
		lines := d.wrap(l.text, contentW-92, false)
		h := 11.5*float64(len(lines)) + 7
		d.ensure(h)
		y := d.gp.GetY()
		d.pill(margin, y-0.5, strings.ToUpper(string(l.v)), verdictTone[l.v], 6.6)
		d.lines(lines, margin+92, y, fSans, 8.6, colText, 11.5)
		d.gp.SetY(y + h)
	}
	d.paragraph(margin, contentW, "The verdict of an indicator is the most severe verdict among its sources.", fSans, 8.6, colMuted, 11.5)

	d.subheading("Traffic Light Protocol")
	badge := d.tlpWidth()
	_ = d.gp.SetFont(fSans, "", 8.6)
	lines := d.wrap(tlpMeaning[d.v.Case.TLP]+" (FIRST TLP 2.0)", contentW-badge-12, false)
	d.ensure(11.5*float64(len(lines)) + 8)
	y := d.gp.GetY()
	d.tlpBadge(margin, y-2)
	d.lines(lines, margin+badge+12, y, fSans, 8.6, colText, 11.5)
	d.gp.SetY(y + 11.5*float64(len(lines)) + 4)

	d.subheading("Sources and handling")
	if sources := consultedSources(d.v); len(sources) > 0 {
		d.paragraph(margin, contentW, "Sources consulted: "+strings.Join(sources, ", ")+".", fSans, 8.6, colText, 11.5)
		d.gp.SetY(d.gp.GetY() + 4)
	}
	d.paragraph(margin, contentW, "Indicators are defanged ([.] instead of a dot, hxxp instead of http) so they cannot be opened by accident. "+
		"Source data is reproduced as received at the time of the search shown for each indicator and may have changed since. "+
		"Report generated by astro "+d.o.Version+" on "+d.o.Now.Format("2006-01-02 15:04 UTC")+".", fSans, 8.6, colText, 11.5)
}

// --- helpers ---

func (d *pdfDoc) heading(title string) {
	d.ensure(96)
	if d.gp.GetY() > topY+1 {
		d.gp.SetY(d.gp.GetY() + 16)
	}
	y := d.gp.GetY()
	d.gp.AddOutline(title)
	d.text(margin, y, fSansSb, 14, colInk, title)
	d.fill(colAccent)
	d.gp.RectFromUpperLeftWithStyle(margin, y+22, 24, 2, "F")
	d.gp.SetY(y + 34)
}

func (d *pdfDoc) subheading(title string) {
	d.ensure(72)
	y := d.gp.GetY() + 8
	d.text(margin, y, fSansSb, 10, colInk, title)
	d.gp.SetY(y + 18)
}

// panel draws a light rounded box.
func (d *pdfDoc) panel(x, y, w, h float64) {
	d.fill(colSurface)
	d.stroke(colBorder)
	d.gp.SetLineWidth(0.7)
	_ = d.gp.Rectangle(x, y, x+w, y+h, "FD", 5, 8)
}

func (d *pdfDoc) pillWidth(label string, size float64) float64 {
	return d.width(fSansSb, size, label) + size*1.5
}

// pill draws a rounded verdict label; size is the font size.
func (d *pdfDoc) pill(x, y float64, label string, t tone, size float64) {
	w := d.pillWidth(label, size)
	h := size * 1.85
	d.fill(t.bg)
	_ = d.gp.Rectangle(x, y, x+w, y+h, "F", h/2.6, 6)
	d.text(x+size*0.75, y+size*0.36, fSansSb, size, t.fg, label)
}

// paragraph prints wrapped text, keeping the line breaks of the source.
// Short paragraphs are never split across pages.
func (d *pdfDoc) paragraph(x, w float64, text, font string, size float64, c rgb, lh float64) {
	_ = d.gp.SetFont(font, "", size)
	lines := d.wrap(text, w, false)
	if len(lines) <= 6 {
		d.ensure(lh * float64(len(lines)))
	}
	for _, l := range lines {
		d.ensure(lh)
		d.text(x, d.gp.GetY(), font, size, c, l)
		d.gp.SetY(d.gp.GetY() + lh)
	}
}

func (d *pdfDoc) lines(lines []string, x, y float64, font string, size float64, c rgb, lh float64) {
	for k, l := range lines {
		d.text(x, y+float64(k)*lh, font, size, c, l)
	}
}

func (d *pdfDoc) text(x, y float64, font string, size float64, c rgb, s string) {
	_ = d.gp.SetFont(font, "", size)
	d.color(c)
	d.gp.SetXY(x, y)
	_ = d.gp.Cell(nil, d.clean(s))
}

// spaced prints small capitals-style labels with letter spacing.
func (d *pdfDoc) spaced(x, y float64, font string, size float64, c rgb, s string) {
	_ = d.gp.SetCharSpacing(size * 0.09)
	d.text(x, y, font, size, c, s)
	_ = d.gp.SetCharSpacing(0)
}

func (d *pdfDoc) width(font string, size float64, s string) float64 {
	_ = d.gp.SetFont(font, "", size)
	w, _ := d.gp.MeasureTextWidth(d.clean(s))
	return w
}

// fit shortens s with an ellipsis until it fits w.
func (d *pdfDoc) fit(s, font string, size, w float64) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if d.width(font, size, s) <= w {
		return s
	}
	r := []rune(s)
	for len(r) > 1 && d.width(font, size, string(r)+"…") > w {
		r = r[:len(r)-1]
	}
	return strings.TrimSpace(string(r)) + "…"
}

func (d *pdfDoc) hline(x0, x1, y float64, c rgb, width float64) {
	d.stroke(c)
	d.gp.SetLineWidth(width)
	d.gp.Line(x0, y, x1, y)
}

// wrap cleans text and splits it to fit width with the current font. Hard
// splitting is used for long tokens such as hashes and URLs.
func (d *pdfDoc) wrap(text string, width float64, hard bool) []string {
	var out []string
	for _, para := range strings.Split(d.clean(text), "\n") {
		if strings.TrimSpace(para) == "" {
			out = append(out, "")
			continue
		}
		var lines []string
		var err error
		if hard {
			lines, err = d.gp.SplitText(para, width)
		} else {
			lines, err = d.gp.SplitTextWithWordWrap(para, width)
		}
		if err != nil {
			lines, _ = d.gp.SplitText(para, width)
		}
		out = append(out, lines...)
	}
	for len(out) > 0 && out[len(out)-1] == "" {
		out = out[:len(out)-1]
	}
	if len(out) == 0 {
		out = []string{""}
	}
	return out
}

// clean strips control characters and replaces runes the font cannot draw.
func (d *pdfDoc) clean(s string) string {
	s = strings.ReplaceAll(render.Sanitize(s), "\t", "    ")
	return strings.Map(func(r rune) rune {
		if r == '\n' {
			return r
		}
		if i, err := d.glyphs.GlyphIndex(&d.buf, r); err != nil || i == 0 {
			return '?'
		}
		return r
	}, s)
}

func (d *pdfDoc) ensure(h float64) {
	if d.gp.GetY()+h > bottomY {
		d.newPage()
	}
}

func (d *pdfDoc) newPage() {
	d.gp.AddPage()
	d.gp.SetY(topY)
}

func (d *pdfDoc) color(c rgb)  { d.gp.SetTextColor(c.r, c.g, c.b) }
func (d *pdfDoc) fill(c rgb)   { d.gp.SetFillColor(c.r, c.g, c.b) }
func (d *pdfDoc) stroke(c rgb) { d.gp.SetStrokeColor(c.r, c.g, c.b) }

// itemVerdict is the label and colors of an indicator's verdict.
func itemVerdict(it cases.Item) (string, tone) {
	if it.SearchedAt == nil {
		return "NOT SEARCHED", toneNone
	}
	if t, ok := verdictTone[it.Verdict]; ok {
		return strings.ToUpper(string(it.Verdict)), t
	}
	return "NO VERDICT", toneNone
}

// overallVerdict is the most severe verdict of the case; "info" when only
// contextual data was found.
func overallVerdict(v *cases.View) provider.Verdict {
	var best provider.Verdict
	for _, it := range v.Items {
		if it.SearchedAt == nil {
			continue
		}
		if it.Verdict.Rank() > best.Rank() || (best == "" && it.Verdict == provider.VerdictInfo) {
			best = it.Verdict
		}
	}
	return best
}

// consultedSources lists the sources that answered for any indicator.
func consultedSources(v *cases.View) []string {
	seen := map[string]bool{}
	var out []string
	for _, it := range v.Items {
		if it.Report == nil {
			continue
		}
		for _, r := range it.Report.Results {
			if !seen[r.Provider] {
				seen[r.Provider] = true
				out = append(out, r.Provider)
			}
		}
	}
	sort.Strings(out)
	return out
}

func resultsOf(it cases.Item) []*provider.Result {
	if it.Report == nil {
		return nil
	}
	return it.Report.Results
}

func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}
