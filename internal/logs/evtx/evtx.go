// Package evtx parses Windows event log files (.evtx) with the Go standard
// library only: the file and chunk layout, the binary XML with its
// templates and substitutions, and the value types, following the public
// description of the format (MS-EVEN6 and the EVTX file format notes).
//
// The file is read in a single pass, one 64 KiB chunk at a time. Corrupt
// chunks or records are counted and skipped; parsing goes on.
package evtx

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"strconv"

	"github.com/ciruzz00/astro/internal/logs"
)

const (
	fileHeaderSize  = 4096
	chunkSize       = 65536
	chunkHeaderSize = 512
	recordHeader    = 24 // magic, size, record id, written time
)

var (
	fileMagic   = []byte("ElfFile\x00")
	chunkMagic  = []byte("ElfChnk\x00")
	recordMagic = []byte{0x2a, 0x2a, 0x00, 0x00}
)

// debugf, when set by a test, receives why records or chunks were skipped.
var debugf func(format string, args ...any)

func debug(format string, args ...any) {
	if debugf != nil {
		debugf(format, args...)
	}
}

// Parser reads EVTX files.
type Parser struct{}

// New returns an EVTX parser.
func New() *Parser { return &Parser{} }

// Kind implements logs.Parser.
func (*Parser) Kind() logs.Kind { return logs.KindEVTX }

// Parse implements logs.Parser.
func (*Parser) Parse(ctx context.Context, r io.Reader, opts logs.Options, emit func(*logs.Event) error) (logs.Stats, error) {
	var st logs.Stats
	hdr := make([]byte, fileHeaderSize)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return st, fmt.Errorf("evtx file header: %w", err)
	}
	if !bytes.HasPrefix(hdr, fileMagic) {
		return st, errors.New("not an EVTX file")
	}
	// A wrong header checksum is common in files copied from a live system
	// ("dirty"): count it, the chunks are checked on their own.
	if crc32.ChecksumIEEE(hdr[:120]) != binary.LittleEndian.Uint32(hdr[124:]) {
		st.Errors++
	}

	// Chunks past the declared count are usually unused space with stale
	// bytes; the ones that still carry a chunk signature are read anyway.
	declared := int(binary.LittleEndian.Uint16(hdr[42:]))
	chunk := make([]byte, chunkSize)
	for n := 0; ; n++ {
		if err := ctx.Err(); err != nil {
			return st, err
		}
		got, err := io.ReadFull(r, chunk)
		if errors.Is(err, io.EOF) {
			return st, nil
		}
		if errors.Is(err, io.ErrUnexpectedEOF) {
			if !allZero(chunk[:got]) {
				st.Errors++ // truncated last chunk
			}
			return st, nil
		}
		if err != nil {
			return st, err
		}
		if !bytes.HasPrefix(chunk, chunkMagic) {
			if n < declared && !allZero(chunk) { // zeroed chunks are preallocated space
				st.Errors++
				debug("chunk %d: no chunk signature", n)
			}
			continue
		}
		if err := parseChunk(chunk, n, opts, &st, emit); err != nil {
			return st, err
		}
	}
}

// parseChunk emits the records of one chunk. Only an error from emit stops it.
func parseChunk(chunk []byte, index int, opts logs.Options, st *logs.Stats, emit func(*logs.Event) error) error {
	le := binary.LittleEndian
	if crc32.Update(crc32.ChecksumIEEE(chunk[:120]), crc32.IEEETable, chunk[128:chunkHeaderSize]) != le.Uint32(chunk[124:]) {
		st.Errors++
		debug("chunk %d: header checksum", index)
	}
	free := int(le.Uint32(chunk[48:]))
	if free < chunkHeaderSize || free > chunkSize {
		free = chunkSize
	} else if crc32.ChecksumIEEE(chunk[chunkHeaderSize:free]) != le.Uint32(chunk[52:]) {
		st.Errors++
		debug("chunk %d: records checksum", index)
	}

	d := newDecoder(chunk)
	off := chunkHeaderSize
	for off+recordHeader+4 <= chunkSize {
		// In dirty files the last records may lie past the free space
		// offset that was not updated yet: follow them while they chain.
		if off >= free && !bytes.Equal(chunk[off:off+4], recordMagic) {
			return nil
		}
		if !bytes.Equal(chunk[off:off+4], recordMagic) {
			debug("chunk %d offset 0x%x: no record signature", index, off)
			if off = nextRecord(chunk, off+1, max(free, off+1)); off < 0 {
				return nil
			}
			st.Errors++
			continue
		}
		size := int(le.Uint32(chunk[off+4:]))
		// A record whose trailing size copy is missing was only partly
		// written: it is still decoded, and kept if anything readable is in it.
		incomplete := size >= recordHeader+4 && off+size <= chunkSize && int(le.Uint32(chunk[off+size-4:])) != size
		if size < recordHeader+4 || off+size > chunkSize {
			st.Errors++
			debug("chunk %d offset 0x%x: bad record size %d", index, off, size)
			if off = nextRecord(chunk, off+1, max(free, off+1)); off < 0 {
				return nil
			}
			continue
		}
		id := le.Uint64(chunk[off+8:])
		written := filetime(le.Uint64(chunk[off+16:]))
		root := &node{}
		d.tokens = 0
		c := d.cursor(off+recordHeader, size-recordHeader-4)
		d.fragment(c, nil, root, 0)
		if c.err != nil {
			st.Errors++
			debug("chunk %d record %d: %v", index, id, c.err)
			if d.chunkTokens > maxChunkTokens {
				return nil // the rest of the chunk is not worth the time
			}
			off += size
			continue
		}
		e := toEvent(root, id, written, opts)
		if incomplete {
			st.Errors++
			debug("chunk %d record %d: incomplete record", index, id)
			if e.EventID == 0 && e.Provider == "" {
				off += size
				continue
			}
			e.Fields["record_incomplete"] = "true"
		}
		e.Ref.Record = "record " + strconv.FormatUint(id, 10) + ", chunk " + strconv.Itoa(index)
		if err := emit(e); err != nil {
			return err
		}
		st.Events++
		off += size
	}
	return nil
}

// nextRecord finds the next record signature at or after from, or -1.
func nextRecord(chunk []byte, from, end int) int {
	if from >= end {
		return -1
	}
	i := bytes.Index(chunk[from:end], recordMagic)
	if i < 0 {
		return -1
	}
	return from + i
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}
