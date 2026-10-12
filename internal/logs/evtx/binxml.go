package evtx

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// Binary XML tokens (MS-EVEN6). Bit 0x40 marks "more data follows":
// attributes on an open element, another attribute after this one, or
// another value fragment.
const (
	tokEOF            = 0x00
	tokOpenStart      = 0x01
	tokCloseStart     = 0x02
	tokCloseEmpty     = 0x03
	tokCloseElement   = 0x04
	tokValue          = 0x05
	tokAttribute      = 0x06
	tokCDATA          = 0x07
	tokCharRef        = 0x08
	tokEntityRef      = 0x09
	tokPITarget       = 0x0a
	tokPIData         = 0x0b
	tokTemplate       = 0x0c
	tokNormalSubst    = 0x0d
	tokOptionalSubst  = 0x0e
	tokFragmentHeader = 0x0f
	flagMore          = 0x40
)

// Limits that keep a hostile file from exhausting memory or time.
const (
	maxDepth  = 32     // nested elements and templates
	maxTokens = 100000 // per record
	maxValues = 4096   // substitutions per template instance
	// maxChunkTokens bounds the work on one chunk: small records that all
	// instantiate a large template could otherwise make it quadratic.
	// Real chunks need a few hundred thousand tokens at most.
	maxChunkTokens = 4_000_000
)

var errBadXML = errors.New("malformed binary XML")

// cursor reads little-endian data from a chunk. Positions are absolute in
// the chunk, as are the offsets stored in binary XML. Reading past the end
// sets err instead of panicking; callers check it once.
type cursor struct {
	b   []byte
	pos int
	end int
	err error
}

func (c *cursor) fail(format string, a ...any) {
	if c.err == nil {
		c.err = fmt.Errorf("%w at 0x%x: %s", errBadXML, c.pos, fmt.Sprintf(format, a...))
	}
}

func (c *cursor) take(n int) []byte {
	if c.err != nil || n < 0 || c.pos+n > c.end {
		c.fail("needs %d bytes", n)
		c.pos = c.end
		return make([]byte, max(n, 0))
	}
	b := c.b[c.pos : c.pos+n]
	c.pos += n
	return b
}

func (c *cursor) u8() byte    { return c.take(1)[0] }
func (c *cursor) u16() uint16 { return binary.LittleEndian.Uint16(c.take(2)) }
func (c *cursor) u32() uint32 { return binary.LittleEndian.Uint32(c.take(4)) }
func (c *cursor) peek() byte {
	if c.err != nil || c.pos >= c.end {
		c.fail("unexpected end")
		return tokEOF
	}
	return c.b[c.pos]
}

// node is an element of the decoded event XML.
type node struct {
	name     string
	attrs    []attr
	children []*node
	text     strings.Builder
}

type attr struct{ name, value string }

// value is a template substitution: its type and its bytes in the chunk.
type value struct {
	typ  byte
	off  int
	size int
}

// decoder turns the binary XML of one chunk into nodes.
type decoder struct {
	chunk       []byte
	names       map[int]string
	tokens      int // in the current record
	chunkTokens int
}

func newDecoder(chunk []byte) *decoder { return &decoder{chunk: chunk, names: map[int]string{}} }

func (d *decoder) cursor(off, size int) *cursor {
	c := &cursor{b: d.chunk, pos: off, end: off + size}
	if off < 0 || size < 0 || off+size > len(d.chunk) {
		c.end = len(d.chunk)
		c.fail("fragment outside the chunk")
	}
	return c
}

// fragment decodes binary XML up to its end-of-fragment token, appending
// what it finds to parent.
func (d *decoder) fragment(c *cursor, vals []value, parent *node, depth int) {
	if depth > maxDepth {
		c.fail("nested too deeply")
		return
	}
	for c.err == nil {
		d.tokens++
		d.chunkTokens++
		if d.tokens > maxTokens || d.chunkTokens > maxChunkTokens {
			c.fail("too many tokens")
			return
		}
		switch tok := c.peek(); tok &^ flagMore {
		case tokEOF:
			c.pos++
			return
		case tokFragmentHeader:
			c.take(4) // token, major and minor version, flags
		case tokTemplate:
			d.template(c, parent, depth+1)
		case tokOpenStart:
			if el := d.element(c, vals, depth+1); el != nil {
				parent.children = append(parent.children, el)
			}
		case tokCloseElement:
			// The caller (element) consumes it: end of this content.
			return
		case tokValue, tokNormalSubst, tokOptionalSubst, tokCDATA, tokCharRef, tokEntityRef:
			d.text(c, vals, parent, depth)
		case tokPITarget:
			c.u8()
			d.name(c, int(c.u32()))
		case tokPIData:
			c.u8()
			c.take(2 * int(c.u16()))
		default:
			c.fail("unknown token 0x%02x", tok)
		}
	}
}

// text decodes one character data token into parent (substituted binary
// XML becomes child elements).
func (d *decoder) text(c *cursor, vals []value, parent *node, depth int) {
	switch tok := c.u8(); tok &^ flagMore {
	case tokValue:
		t := c.u8()
		if t != tString {
			c.fail("value of type 0x%02x", t)
			return
		}
		parent.text.WriteString(utf16Raw(c.take(2 * int(c.u16()))))
	case tokCDATA:
		parent.text.WriteString(utf16Raw(c.take(2 * int(c.u16()))))
	case tokCharRef:
		parent.text.WriteRune(rune(c.u16()))
	case tokEntityRef:
		parent.text.WriteString(entity(d.name(c, int(c.u32()))))
	case tokNormalSubst, tokOptionalSubst:
		idx := int(c.u16())
		c.u8() // declared type; the instance carries the actual one
		if idx >= len(vals) {
			return // optional values may be missing
		}
		v := vals[idx]
		if v.typ == tBinXML {
			d.fragment(d.cursor(v.off, v.size), nil, parent, depth+1)
			return
		}
		parent.text.WriteString(formatValue(v.typ, d.chunk[v.off:v.off+v.size]))
	}
}

func entity(name string) string {
	switch name {
	case "lt":
		return "<"
	case "gt":
		return ">"
	case "amp":
		return "&"
	case "quot":
		return `"`
	case "apos":
		return "'"
	}
	return "&" + name + ";"
}

// element decodes an element from its open start token.
func (d *decoder) element(c *cursor, vals []value, depth int) *node {
	if depth > maxDepth {
		c.fail("nested too deeply")
		return nil
	}
	tok := c.u8()
	// Elements carry a 2-byte dependency identifier before their size;
	// accept the rare layout without it when that is the one that leads
	// to a valid name.
	start := c.pos
	if !d.validName(int(binary.LittleEndian.Uint32(c.b[min(start+6, c.end-4):])), start+10) &&
		d.validName(int(binary.LittleEndian.Uint32(c.b[min(start+4, c.end-4):])), start+8) {
		c.take(4) // size
	} else {
		c.take(2) // dependency identifier
		c.take(4) // size
	}
	el := &node{name: d.name(c, int(c.u32()))}
	if tok&flagMore != 0 {
		listSize := int(c.u32())
		listEnd := c.pos + listSize
		for c.err == nil && c.pos < listEnd {
			at := c.u8()
			if at&^flagMore != tokAttribute {
				c.fail("attribute token 0x%02x", at)
				return nil
			}
			a := attr{name: d.name(c, int(c.u32()))}
			holder := &node{}
			for c.err == nil {
				next := c.peek() &^ flagMore
				if next != tokValue && next != tokNormalSubst && next != tokOptionalSubst && next != tokCharRef && next != tokEntityRef {
					break
				}
				d.text(c, vals, holder, depth)
			}
			a.value = holder.text.String()
			el.attrs = append(el.attrs, a)
			if at&flagMore == 0 {
				break
			}
		}
	}
	switch end := c.u8(); end {
	case tokCloseEmpty:
	case tokCloseStart:
		d.fragment(c, vals, el, depth)
		if c.err == nil && c.u8() != tokCloseElement {
			c.fail("element %s not closed", el.name)
		}
	default:
		c.fail("element %s: token 0x%02x after the start tag", el.name, end)
	}
	return el
}

// name reads an element or attribute name at off: inline (right here, so
// the cursor moves past it) or shared earlier in the chunk.
func (d *decoder) name(c *cursor, off int) string {
	if c.err != nil {
		return ""
	}
	if off == c.pos {
		c.take(4 + 2) // next name offset, hash
		n := int(c.u16())
		s := utf16Raw(c.take(2 * n))
		c.take(2) // NUL
		d.names[off] = s
		return s
	}
	if s, ok := d.names[off]; ok {
		return s
	}
	nc := d.cursor(off, len(d.chunk)-off)
	nc.take(6)
	n := int(nc.u16())
	s := utf16Raw(nc.take(2 * n))
	if nc.err != nil {
		c.fail("bad name offset 0x%x", off)
		return ""
	}
	d.names[off] = s
	return s
}

// validName reports whether off can hold a name for an element whose name
// field ends at inlineAt.
func (d *decoder) validName(off, inlineAt int) bool {
	if off == inlineAt {
		return off+8 <= len(d.chunk)
	}
	if _, ok := d.names[off]; ok {
		return true
	}
	if off < chunkHeaderSize || off+8 > len(d.chunk) || off > inlineAt {
		return false
	}
	n := int(binary.LittleEndian.Uint16(d.chunk[off+6:]))
	return n > 0 && n < 256 && off+8+2*n+2 <= len(d.chunk)
}

// template decodes a template instance: the definition (inline the first
// time it is used in the chunk, then shared by offset) and its values.
func (d *decoder) template(c *cursor, parent *node, depth int) {
	if depth > maxDepth {
		c.fail("nested too deeply")
		return
	}
	c.take(2) // token, unknown
	c.u32()   // template identifier
	def := int(c.u32())
	if def < chunkHeaderSize || def+24 > len(d.chunk) {
		c.fail("template definition offset 0x%x", def)
		return
	}
	size := int(binary.LittleEndian.Uint32(d.chunk[def+20:]))
	if def == c.pos { // defined here: skip next offset, GUID, size and body
		c.take(24 + size)
	}
	n := int(c.u32())
	if n > maxValues {
		c.fail("%d substitution values", n)
		return
	}
	vals := make([]value, n)
	for i := range vals {
		vals[i].size = int(c.u16())
		vals[i].typ = c.u8()
		c.u8()
	}
	for i := range vals {
		vals[i].off = c.pos
		c.take(vals[i].size)
	}
	if c.err != nil {
		return
	}
	body := d.cursor(def+24, size)
	d.fragment(body, vals, parent, depth)
	if body.err != nil {
		c.err = body.err
	}
}
