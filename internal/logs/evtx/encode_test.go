package evtx

import (
	"encoding/binary"
	"hash/crc32"
	"time"
	"unicode/utf16"
)

// This file is a small binary XML encoder used only by the tests: it builds
// synthetic EVTX files, so no third-party event logs enter the repository.

// xel describes an element of a template: literal text, a substitution
// (sub >= 0) or children.
type xel struct {
	name     string
	attrs    []xattr
	text     string
	sub      int
	optional bool
	children []xel
}

type xattr struct {
	name string
	text string
	sub  int
}

func el(name string, children ...xel) xel { return xel{name: name, sub: -1, children: children} }
func lit(name, text string) xel           { return xel{name: name, sub: -1, text: text} }
func sub(name string, i int) xel          { return xel{name: name, sub: i} }

func (x xel) with(a ...xattr) xel { x.attrs = append(x.attrs, a...); return x }

func data(name string, i int) xel {
	return sub("Data", i).with(xattr{name: "Name", text: name, sub: -1})
}

// tval is a substitution value; nested holds binary XML for type 0x21.
type tval struct {
	typ    byte
	b      []byte
	nested *record
}

type record struct {
	tmplID int
	tmpl   xel
	vals   []tval
}

// chunkWriter appends to a chunk; len(b) is the absolute chunk offset.
type chunkWriter struct {
	b         []byte
	names     map[string]int
	templates map[int]int
	first     uint64
	count     uint64
	lastRec   int
}

func newChunk(firstID uint64) *chunkWriter {
	return &chunkWriter{b: make([]byte, chunkHeaderSize), names: map[string]int{}, templates: map[int]int{}, first: firstID}
}

func (w *chunkWriter) u8(v byte)    { w.b = append(w.b, v) }
func (w *chunkWriter) u16(v uint16) { w.b = binary.LittleEndian.AppendUint16(w.b, v) }
func (w *chunkWriter) u32(v uint32) { w.b = binary.LittleEndian.AppendUint32(w.b, v) }
func (w *chunkWriter) u64(v uint64) { w.b = binary.LittleEndian.AppendUint64(w.b, v) }
func (w *chunkWriter) patch32(at int, v uint32) {
	binary.LittleEndian.PutUint32(w.b[at:], v)
}

func utf16le(s string) []byte {
	var b []byte
	for _, u := range utf16.Encode([]rune(s)) {
		b = binary.LittleEndian.AppendUint16(b, u)
	}
	return b
}

// name writes a name reference, inline the first time.
func (w *chunkWriter) name(s string) {
	if off, ok := w.names[s]; ok {
		w.u32(uint32(off))
		return
	}
	off := len(w.b) + 4
	w.names[s] = off
	w.u32(uint32(off))
	w.u32(0) // next name
	w.u16(0) // hash
	w.u16(uint16(len(utf16.Encode([]rune(s)))))
	w.b = append(w.b, utf16le(s)...)
	w.u16(0)
}

func (w *chunkWriter) value(text string) {
	w.u8(tokValue)
	w.u8(tString)
	w.u16(uint16(len(utf16.Encode([]rune(text)))))
	w.b = append(w.b, utf16le(text)...)
}

func (w *chunkWriter) element(x xel) {
	tok := byte(tokOpenStart)
	if len(x.attrs) > 0 {
		tok |= flagMore
	}
	w.u8(tok)
	w.u16(0xffff) // dependency identifier
	sizeAt := len(w.b)
	w.u32(0)
	w.name(x.name)
	if len(x.attrs) > 0 {
		listAt := len(w.b)
		w.u32(0)
		for i, a := range x.attrs {
			at := byte(tokAttribute)
			if i < len(x.attrs)-1 {
				at |= flagMore
			}
			w.u8(at)
			w.name(a.name)
			if a.sub >= 0 {
				w.u8(tokNormalSubst)
				w.u16(uint16(a.sub))
				w.u8(tString)
			} else {
				w.value(a.text)
			}
		}
		w.patch32(listAt, uint32(len(w.b)-listAt-4))
	}
	if x.text == "" && x.sub < 0 && len(x.children) == 0 {
		w.u8(tokCloseEmpty)
	} else {
		w.u8(tokCloseStart)
		if x.text != "" {
			w.value(x.text)
		}
		if x.sub >= 0 {
			if x.optional {
				w.u8(tokOptionalSubst)
			} else {
				w.u8(tokNormalSubst)
			}
			w.u16(uint16(x.sub))
			w.u8(tString)
		}
		for _, c := range x.children {
			w.element(c)
		}
		w.u8(tokCloseElement)
	}
	w.patch32(sizeAt, uint32(len(w.b)-sizeAt-4))
}

// fragment writes a fragment header, a template instance and the end token.
func (w *chunkWriter) fragment(r *record) {
	w.b = append(w.b, tokFragmentHeader, 1, 1, 0)
	w.u8(tokTemplate)
	w.u8(1)
	w.u32(uint32(r.tmplID))
	if def, ok := w.templates[r.tmplID]; ok {
		w.u32(uint32(def))
	} else {
		def := len(w.b) + 4
		w.templates[r.tmplID] = def
		w.u32(uint32(def))
		w.u32(0) // next template
		w.u32(uint32(r.tmplID))
		w.b = append(w.b, make([]byte, 12)...) // rest of the GUID
		sizeAt := len(w.b)
		w.u32(0)
		w.b = append(w.b, tokFragmentHeader, 1, 1, 0)
		w.element(r.tmpl)
		w.u8(tokEOF)
		w.patch32(sizeAt, uint32(len(w.b)-sizeAt-4))
	}
	w.u32(uint32(len(r.vals)))
	descAt := len(w.b)
	for _, v := range r.vals {
		w.u16(uint16(len(v.b)))
		w.u8(v.typ)
		w.u8(0)
	}
	for i, v := range r.vals {
		start := len(w.b)
		if v.nested != nil {
			w.fragment(v.nested)
		} else {
			w.b = append(w.b, v.b...)
		}
		binary.LittleEndian.PutUint16(w.b[descAt+4*i:], uint16(len(w.b)-start))
	}
	w.u8(tokEOF)
}

func (w *chunkWriter) record(r *record, written time.Time) {
	start := len(w.b)
	w.lastRec = start
	w.b = append(w.b, recordMagic...)
	w.u32(0)
	w.u64(w.first + w.count)
	w.u64(toFiletime(written))
	w.fragment(r)
	size := len(w.b) - start + 4
	w.u32(uint32(size))
	w.patch32(start+4, uint32(size))
	w.count++
}

// raw appends arbitrary bytes framed as a record (for corruption tests).
func (w *chunkWriter) raw(body []byte) {
	start := len(w.b)
	w.b = append(w.b, recordMagic...)
	w.u32(0)
	w.u64(w.first + w.count)
	w.u64(0)
	w.b = append(w.b, body...)
	size := len(w.b) - start + 4
	w.u32(uint32(size))
	w.patch32(start+4, uint32(size))
	w.count++
}

func (w *chunkWriter) finish() []byte {
	free := len(w.b)
	out := make([]byte, chunkSize)
	copy(out, w.b)
	le := binary.LittleEndian
	copy(out, chunkMagic)
	le.PutUint64(out[8:], w.first)
	le.PutUint64(out[16:], w.first+w.count-1)
	le.PutUint64(out[24:], w.first)
	le.PutUint64(out[32:], w.first+w.count-1)
	le.PutUint32(out[40:], 128)
	le.PutUint32(out[44:], uint32(w.lastRec))
	le.PutUint32(out[48:], uint32(free))
	le.PutUint32(out[52:], crc32.ChecksumIEEE(out[chunkHeaderSize:free]))
	le.PutUint32(out[124:], crc32.Update(crc32.ChecksumIEEE(out[:120]), crc32.IEEETable, out[128:chunkHeaderSize]))
	return out
}

func buildFile(chunks ...[]byte) []byte {
	le := binary.LittleEndian
	h := make([]byte, fileHeaderSize)
	copy(h, fileMagic)
	le.PutUint64(h[16:], uint64(len(chunks)-1))
	le.PutUint32(h[32:], 128)
	le.PutUint16(h[36:], 2)
	le.PutUint16(h[38:], 3)
	le.PutUint16(h[40:], fileHeaderSize)
	le.PutUint16(h[42:], uint16(len(chunks)))
	le.PutUint32(h[124:], crc32.ChecksumIEEE(h[:120]))
	for _, c := range chunks {
		h = append(h, c...)
	}
	return h
}

func toFiletime(t time.Time) uint64 {
	return uint64(t.Unix()+11644473600)*10_000_000 + uint64(t.Nanosecond()/100)
}

// Value constructors.

func vString(s string) tval { return tval{typ: tString, b: utf16le(s)} }
func vU16(v uint16) tval    { return tval{typ: tUInt16, b: binary.LittleEndian.AppendUint16(nil, v)} }
func vU32(v uint32) tval    { return tval{typ: tUInt32, b: binary.LittleEndian.AppendUint32(nil, v)} }
func vU64(v uint64) tval    { return tval{typ: tUInt64, b: binary.LittleEndian.AppendUint64(nil, v)} }
func vHex64(v uint64) tval  { return tval{typ: tHexInt64, b: binary.LittleEndian.AppendUint64(nil, v)} }
func vTime(t time.Time) tval {
	return tval{typ: tFileTime, b: binary.LittleEndian.AppendUint64(nil, toFiletime(t))}
}
func vNull() tval { return tval{typ: tNull} }

// vSID encodes S-1-5-21-a-b-c-rid style identifiers.
func vSID(authority byte, subs ...uint32) tval {
	b := []byte{1, byte(len(subs)), 0, 0, 0, 0, 0, authority}
	for _, s := range subs {
		b = binary.LittleEndian.AppendUint32(b, s)
	}
	return tval{typ: tSID, b: b}
}

func vGUID() tval {
	b := binary.LittleEndian.AppendUint32(nil, 0x01234567)
	b = binary.LittleEndian.AppendUint16(b, 0x89ab)
	b = binary.LittleEndian.AppendUint16(b, 0xcdef)
	return tval{typ: tGUID, b: append(b, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef)}
}
