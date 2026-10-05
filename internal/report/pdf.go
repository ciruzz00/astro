package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/signintech/gopdf"
	"golang.org/x/image/font/gofont/gobold"
	"golang.org/x/image/font/gofont/gomono"
	"golang.org/x/image/font/gofont/goregular"
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
	margin   = 42.0
	contentW = pageW - 2*margin
	bottomY  = pageH - 54
)

type rgb struct{ r, g, b uint8 }

var (
	colText    = rgb{27, 35, 48}
	colMuted   = rgb{95, 107, 122}
	colBorder  = rgb{223, 227, 232}
	colBand    = rgb{18, 24, 38}
	colAccent  = rgb{51, 85, 255}
	verdictCol = map[provider.Verdict]rgb{
		provider.VerdictMalicious:  {208, 49, 45},
		provider.VerdictSuspicious: {178, 106, 0},
		provider.VerdictClean:      {25, 128, 61},
		provider.VerdictInfo:       {59, 91, 219},
	}
	// TLP 2.0 colors defined by FIRST, printed on black.
	tlpCol = map[string]rgb{
		cases.TLPRed: {255, 43, 43}, cases.TLPAmber: {255, 192, 0}, cases.TLPAmberStrict: {255, 192, 0},
		cases.TLPGreen: {51, 255, 0}, cases.TLPClear: {255, 255, 255},
	}
)

// Fonts: the Go fonts (BSD licensed) cover Latin, Greek and Cyrillic.
var fontData = map[string][]byte{"regular": goregular.TTF, "bold": gobold.TTF, "mono": gomono.TTF}

type pdfDoc struct {
	gp     *gopdf.GoPdf
	glyphs *sfnt.Font
	buf    sfnt.Buffer
	v      *cases.View
	o      Options
}

// PDF writes a case report as an A4 PDF. The TLP label is printed at the top
// and bottom of every page, as TLP 2.0 requires.
func PDF(w io.Writer, v *cases.View, o Options) error {
	gp := &gopdf.GoPdf{}
	gp.Start(gopdf.Config{PageSize: *gopdf.PageSizeA4, Unit: gopdf.UnitPT})
	gp.SetCompressLevel(9)
	for name, data := range fontData {
		if err := gp.AddTTFFontData(name, data); err != nil {
			return fmt.Errorf("load font: %w", err)
		}
	}
	glyphs, err := sfnt.Parse(goregular.TTF)
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
	d := &pdfDoc{gp: gp, glyphs: glyphs, v: v, o: o}
	gp.AddHeader(d.header)
	gp.AddFooter(d.footer)

	gp.AddPage()
	if err := d.cover(title); err != nil {
		return err
	}
	if err := d.summary(); err != nil {
		return err
	}
	if err := d.indicators(); err != nil {
		return err
	}
	if err := d.details(); err != nil {
		return err
	}
	if err := d.notes(); err != nil {
		return err
	}
	_, err = gp.WriteTo(w)
	return err
}

// --- page furniture ---

func (d *pdfDoc) tlpBadge(x, y float64) {
	label := "TLP:" + d.v.Case.TLP
	_ = d.gp.SetFont("bold", "", 8.5)
	tw, _ := d.gp.MeasureTextWidth(label)
	d.fill(rgb{0, 0, 0})
	d.gp.RectFromUpperLeftWithStyle(x-tw-10, y, tw+10, 14, "F")
	d.color(tlpCol[d.v.Case.TLP])
	d.gp.SetXY(x-tw-5, y+3)
	_ = d.gp.Cell(nil, label)
}

func (d *pdfDoc) header() {
	d.tlpBadge(pageW-margin, 18)
}

func (d *pdfDoc) footer() {
	d.stroke(colBorder)
	d.gp.SetLineWidth(0.5)
	d.gp.Line(margin, pageH-40, pageW-margin, pageH-40)
	_ = d.gp.SetFont("regular", "", 8)
	d.color(colMuted)
	d.gp.SetXY(margin, pageH-33)
	_ = d.gp.Cell(nil, d.clean("astro · case "+d.v.Case.Name+" · indicators are defanged"))
	page := fmt.Sprintf("Page %d", d.gp.GetNumberOfPages())
	pw, _ := d.gp.MeasureTextWidth(page)
	d.gp.SetXY(pageW/2-pw/2, pageH-33)
	_ = d.gp.Cell(nil, page)
	d.tlpBadge(pageW-margin, pageH-36)
}

// --- sections ---

func (d *pdfDoc) cover(title string) error {
	gp := d.gp
	d.fill(colBand)
	gp.RectFromUpperLeftWithStyle(0, 40, pageW, 92, "F")
	gp.SetXY(margin, 54)
	_ = gp.SetFont("bold", "", 9)
	d.color(rgb{150, 165, 255})
	_ = gp.Cell(nil, "ASTRO · THREAT INTELLIGENCE CASE REPORT")
	_ = gp.SetFont("bold", "", 20)
	d.color(rgb{255, 255, 255})
	lines := d.wrap(title, contentW, false)
	if len(lines) > 2 {
		lines = lines[:2]
	}
	y := 72.0
	for _, l := range lines {
		gp.SetXY(margin, y)
		_ = gp.Cell(nil, l)
		y += 24
	}
	gp.SetY(150)

	c := d.v.Case
	meta := [][2]string{
		{"Case", c.Name},
		{"Status", c.Status},
		{"TLP", "TLP:" + c.TLP},
		{"Tags", strings.Join(c.Tags, ", ")},
		{"Created", c.CreatedAt.Format("2006-01-02 15:04 UTC")},
		{"Updated", c.UpdatedAt.Format("2006-01-02 15:04 UTC")},
		{"Generated", d.o.Now.Format("2006-01-02 15:04 UTC") + " by astro " + d.o.Version},
	}
	for _, m := range meta {
		if m[1] == "" {
			continue
		}
		d.keyValue(m[0], m[1], 90)
	}
	if c.Description != "" {
		gp.Br(6)
		d.paragraph(ioc.DefangText(c.Description), "regular", 10, colText)
	}
	return nil
}

func (d *pdfDoc) summary() error {
	d.heading("Summary")
	mal, sus, clean, pending := d.v.Counts()
	stats := []struct {
		label string
		n     int
		c     rgb
	}{
		{"Indicators", len(d.v.Items), colText},
		{"Malicious", mal, verdictCol[provider.VerdictMalicious]},
		{"Suspicious", sus, verdictCol[provider.VerdictSuspicious]},
		{"Clean", clean, verdictCol[provider.VerdictClean]},
		{"Not searched", pending, colMuted},
	}
	gap := 8.0
	w := (contentW - gap*float64(len(stats)-1)) / float64(len(stats))
	y := d.gp.GetY()
	for k, s := range stats {
		x := margin + float64(k)*(w+gap)
		d.stroke(colBorder)
		d.gp.SetLineWidth(0.8)
		d.gp.RectFromUpperLeftWithStyle(x, y, w, 46, "D")
		_ = d.gp.SetFont("bold", "", 18)
		d.color(s.c)
		d.gp.SetXY(x+10, y+7)
		_ = d.gp.Cell(nil, fmt.Sprint(s.n))
		_ = d.gp.SetFont("regular", "", 8.5)
		d.color(colMuted)
		d.gp.SetXY(x+10, y+30)
		_ = d.gp.Cell(nil, s.label)
	}
	d.gp.SetY(y + 58)
	return nil
}

// Indicator table column widths.
var cols = []float64{72, 78, 236, contentW - 72 - 78 - 236}

func (d *pdfDoc) tableHeader() {
	y := d.gp.GetY()
	d.fill(rgb{240, 242, 245})
	d.gp.RectFromUpperLeftWithStyle(margin, y, contentW, 18, "F")
	_ = d.gp.SetFont("bold", "", 8)
	d.color(colMuted)
	x := margin
	for k, h := range []string{"VERDICT", "TYPE", "INDICATOR (DEFANGED)", "FLAGGED BY"} {
		d.gp.SetXY(x+5, y+5)
		_ = d.gp.Cell(nil, h)
		x += cols[k]
	}
	d.gp.SetY(y + 20)
}

func (d *pdfDoc) indicators() error {
	if len(d.v.Items) == 0 {
		return nil
	}
	d.heading("Indicators")
	d.tableHeader()
	for _, it := range d.v.Items {
		_ = d.gp.SetFont("mono", "", 8.5)
		iocLines := d.wrap(ioc.Defang(it.Indicator), cols[2]-10, true)
		_ = d.gp.SetFont("regular", "", 8.5)
		flagLines := d.wrap(strings.Join(flaggedBy(it), ", "), cols[3]-10, false)
		rowH := 8 + 11*float64(max(len(iocLines), len(flagLines), 1))
		if d.gp.GetY()+rowH > bottomY {
			d.newPage()
			d.tableHeader()
		}
		y := d.gp.GetY()

		label, c := "NOT SEARCHED", colMuted
		if it.SearchedAt != nil {
			label, c = strings.ToUpper(verdictText(it.Verdict)), verdictColor(it.Verdict)
		}
		_ = d.gp.SetFont("bold", "", 7.5)
		d.color(c)
		d.gp.SetXY(margin+5, y+5)
		_ = d.gp.Cell(nil, label)

		_ = d.gp.SetFont("regular", "", 8.5)
		d.color(colMuted)
		d.gp.SetXY(margin+cols[0]+5, y+4)
		_ = d.gp.Cell(nil, string(it.Indicator.Type))

		d.lines(iocLines, margin+cols[0]+cols[1]+5, y+4, "mono", 8.5, colText)
		d.lines(flagLines, margin+cols[0]+cols[1]+cols[2]+5, y+4, "regular", 8.5, colText)

		d.stroke(colBorder)
		d.gp.SetLineWidth(0.5)
		d.gp.Line(margin, y+rowH, pageW-margin, y+rowH)
		d.gp.SetY(y + rowH + 1)
	}
	d.gp.Br(10)
	return nil
}

func (d *pdfDoc) details() error {
	first := true
	for _, it := range d.v.Items {
		if it.Report == nil {
			continue
		}
		if first {
			d.heading("Details")
			first = false
		}
		d.ensure(60)
		_ = d.gp.SetFont("mono", "", 10)
		d.color(colText)
		for _, l := range d.wrap(ioc.Defang(it.Indicator), contentW, true) {
			d.gp.SetX(margin)
			_ = d.gp.Cell(nil, l)
			d.gp.Br(13)
		}
		_ = d.gp.SetFont("regular", "", 8)
		d.color(colMuted)
		d.gp.SetX(margin)
		meta := string(it.Indicator.Type)
		if it.SearchedAt != nil {
			meta += " · searched " + it.SearchedAt.Format("2006-01-02 15:04 UTC")
		}
		if it.Note != "" {
			meta += " · note: " + ioc.DefangText(it.Note)
		}
		for _, l := range d.wrap(meta, contentW, false) {
			d.gp.SetX(margin)
			_ = d.gp.Cell(nil, l)
			d.gp.Br(11)
		}
		d.gp.Br(3)
		for _, r := range it.Report.Results {
			d.result(r)
		}
		d.gp.Br(8)
	}
	return nil
}

func (d *pdfDoc) result(r *provider.Result) {
	var status string
	var c rgb
	switch {
	case r.Error != "":
		status, c = "error: "+r.Error, verdictCol[provider.VerdictSuspicious]
	case !r.Found:
		status, c = orDefault(r.Summary, "no data"), colMuted
	default:
		status, c = r.Summary, colText
	}
	_ = d.gp.SetFont("regular", "", 9)
	lines := d.wrap(status, contentW-150, false)
	d.ensure(12 * float64(len(lines)+1))
	y := d.gp.GetY()
	_ = d.gp.SetFont("bold", "", 9)
	d.color(colText)
	d.gp.SetXY(margin+8, y)
	_ = d.gp.Cell(nil, d.clean(r.Provider))
	if r.Found && r.Verdict.Rank() > 0 {
		_ = d.gp.SetFont("bold", "", 7.5)
		d.color(verdictColor(r.Verdict))
		d.gp.SetXY(margin+92, y+1)
		_ = d.gp.Cell(nil, strings.ToUpper(string(r.Verdict)))
	}
	d.lines(lines, margin+150, y, "regular", 9, c)
	d.gp.SetY(y + 12*float64(len(lines)) + 3)
}

func (d *pdfDoc) notes() error {
	if len(d.v.Case.Notes) == 0 {
		return nil
	}
	d.heading("Notes")
	for _, n := range d.v.Case.Notes {
		d.ensure(40)
		_ = d.gp.SetFont("bold", "", 8.5)
		d.color(colMuted)
		d.gp.SetX(margin)
		_ = d.gp.Cell(nil, n.CreatedAt.Format("2006-01-02 15:04 UTC"))
		d.gp.Br(13)
		d.paragraph(ioc.DefangText(n.Body), "regular", 10, colText)
		d.gp.Br(8)
	}
	return nil
}

// --- helpers ---

func (d *pdfDoc) heading(text string) {
	d.ensure(70)
	d.gp.Br(10)
	y := d.gp.GetY()
	d.fill(colAccent)
	d.gp.RectFromUpperLeftWithStyle(margin, y+1, 3, 14, "F")
	_ = d.gp.SetFont("bold", "", 13)
	d.color(colText)
	d.gp.SetXY(margin+10, y)
	_ = d.gp.Cell(nil, text)
	d.gp.SetY(y + 24)
}

func (d *pdfDoc) keyValue(k, v string, keyW float64) {
	_ = d.gp.SetFont("regular", "", 9.5)
	lines := d.wrap(v, contentW-keyW, false)
	y := d.gp.GetY()
	d.color(colMuted)
	d.gp.SetXY(margin, y)
	_ = d.gp.Cell(nil, k)
	d.lines(lines, margin+keyW, y, "regular", 9.5, colText)
	d.gp.SetY(y + 14*float64(len(lines)))
}

// paragraph prints multi-line text, keeping the line breaks of the source.
func (d *pdfDoc) paragraph(text, font string, size float64, c rgb) {
	_ = d.gp.SetFont(font, "", size)
	lh := size * 1.4
	for _, l := range d.wrap(text, contentW, false) {
		d.ensure(lh)
		d.color(c)
		_ = d.gp.SetFont(font, "", size)
		d.gp.SetX(margin)
		_ = d.gp.Cell(nil, l)
		d.gp.Br(lh)
	}
}

func (d *pdfDoc) lines(lines []string, x, y float64, font string, size float64, c rgb) {
	_ = d.gp.SetFont(font, "", size)
	d.color(c)
	for k, l := range lines {
		d.gp.SetXY(x, y+float64(k)*(size+2.5))
		_ = d.gp.Cell(nil, l)
	}
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
	d.gp.SetY(margin + 10)
}

func (d *pdfDoc) color(c rgb)  { d.gp.SetTextColor(c.r, c.g, c.b) }
func (d *pdfDoc) fill(c rgb)   { d.gp.SetFillColor(c.r, c.g, c.b) }
func (d *pdfDoc) stroke(c rgb) { d.gp.SetStrokeColor(c.r, c.g, c.b) }

func verdictColor(v provider.Verdict) rgb {
	if c, ok := verdictCol[v]; ok {
		return c
	}
	return colMuted
}

func verdictText(v provider.Verdict) string {
	if v == "" {
		return "no verdict"
	}
	return string(v)
}
