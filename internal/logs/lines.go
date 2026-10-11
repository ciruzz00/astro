package logs

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// MaxLine bounds the length of a text log line; longer lines are skipped.
const MaxLine = 1 << 20

// ScanLines calls fn for every line of r, numbered from 1, without the line
// terminator and with invalid UTF-8 replaced. Lines longer than max bytes
// are dropped and counted in the returned total. An error from fn stops
// the scan and is returned.
func ScanLines(ctx context.Context, r io.Reader, max int, fn func(n int, line string) error) (long int, err error) {
	return ScanRawLines(ctx, r, max, func(n int, line []byte) error {
		return fn(n, strings.ToValidUTF8(string(line), "\uFFFD"))
	})
}

// ScanRawLines is ScanLines without the UTF-8 repair, for formats that
// encode bytes on their own (zsh history). line is only valid during fn.
func ScanRawLines(ctx context.Context, r io.Reader, max int, fn func(n int, line []byte) error) (long int, err error) {
	br := bufio.NewReaderSize(r, 64<<10)
	var buf []byte
	n := 0
	tooLong := false
	for {
		frag, isPrefix, err := br.ReadLine()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return long, nil
			}
			return long, err
		}
		if !tooLong {
			if len(buf)+len(frag) > max {
				tooLong, buf = true, buf[:0]
			} else {
				buf = append(buf, frag...)
			}
		}
		if isPrefix {
			continue
		}
		n++
		if tooLong {
			long++
			tooLong = false
			continue
		}
		if n%4096 == 0 && ctx.Err() != nil {
			return long, ctx.Err()
		}
		line := bytes.TrimSuffix(buf, []byte("\r"))
		if err := fn(n, line); err != nil {
			return long, err
		}
		buf = buf[:0]
	}
}

// StripNUL removes NUL bytes from a line and returns how many there were.
// Text logs get NUL runs when they are truncated while a writer still
// appends at the old offset (log wiping) or after an unclean shutdown.
func StripNUL(line string) (string, int) {
	n := strings.Count(line, "\x00")
	if n == 0 {
		return line, 0
	}
	return strings.ReplaceAll(line, "\x00", ""), n
}

// KindNULPadding marks a run of NUL bytes found in a text log.
const KindNULPadding = "log-nul-padding"

// NULPaddingEvent reports n NUL bytes found before line n of a text log.
func NULPaddingEvent(source string, line, n int, t time.Time) *Event {
	return &Event{Time: t, Source: source, Kind: KindNULPadding, Severity: Medium,
		Message: fmt.Sprintf("%d NUL bytes in the log before line %d: the file was truncated while being written (log wiping) or the system stopped abruptly", n, line),
		Fields:  map[string]string{"nul_bytes": strconv.Itoa(n)},
		Ref:     EvidenceRef{Record: "line " + strconv.Itoa(line)}}
}
