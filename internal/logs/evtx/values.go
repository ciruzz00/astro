package evtx

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
)

// Value types of template substitutions (MS-EVEN6 BinXmlValueType).
const (
	tNull       = 0x00
	tString     = 0x01
	tAnsiString = 0x02
	tInt8       = 0x03
	tUInt8      = 0x04
	tInt16      = 0x05
	tUInt16     = 0x06
	tInt32      = 0x07
	tUInt32     = 0x08
	tInt64      = 0x09
	tUInt64     = 0x0a
	tReal32     = 0x0b
	tReal64     = 0x0c
	tBool       = 0x0d
	tBinary     = 0x0e
	tGUID       = 0x0f
	tSizeT      = 0x10
	tFileTime   = 0x11
	tSysTime    = 0x12
	tSID        = 0x13
	tHexInt32   = 0x14
	tHexInt64   = 0x15
	tEvtHandle  = 0x20
	tBinXML     = 0x21
	tEvtXML     = 0x23
	tArray      = 0x80
)

// timeLayout is how Windows renders FILETIME values in event XML.
const timeLayout = "2006-01-02T15:04:05.0000000Z"

// fixedSize is the size of one element of a fixed-size type, 0 otherwise.
func fixedSize(t byte) int {
	switch t {
	case tInt8, tUInt8:
		return 1
	case tInt16, tUInt16:
		return 2
	case tInt32, tUInt32, tReal32, tBool, tHexInt32:
		return 4
	case tInt64, tUInt64, tReal64, tHexInt64, tFileTime:
		return 8
	case tGUID, tSysTime:
		return 16
	}
	return 0
}

// formatValue renders a substitution value as Windows renders it in XML.
// Malformed values never fail: they are shown as hex.
func formatValue(t byte, b []byte) string {
	if t&tArray != 0 {
		return formatArray(t&^tArray, b)
	}
	le := binary.LittleEndian
	if n := fixedSize(t); n > 0 && len(b) != n {
		return hexValue(b)
	}
	switch t {
	case tNull:
		return ""
	case tString:
		return utf16String(b)
	case tAnsiString:
		return strings.ToValidUTF8(strings.TrimRight(string(b), "\x00"), "\uFFFD")
	case tInt8:
		return strconv.FormatInt(signed(uint64(b[0]), 8), 10)
	case tUInt8:
		return strconv.Itoa(int(b[0]))
	case tInt16:
		return strconv.FormatInt(signed(uint64(le.Uint16(b)), 16), 10)
	case tUInt16:
		return strconv.Itoa(int(le.Uint16(b)))
	case tInt32:
		return strconv.FormatInt(signed(uint64(le.Uint32(b)), 32), 10)
	case tUInt32:
		return strconv.FormatUint(uint64(le.Uint32(b)), 10)
	case tInt64:
		return strconv.FormatInt(int64(le.Uint64(b)), 10) // #nosec G115 -- two's complement reinterpretation is the format
	case tUInt64:
		return strconv.FormatUint(le.Uint64(b), 10)
	case tReal32:
		return strconv.FormatFloat(float64(math.Float32frombits(le.Uint32(b))), 'g', -1, 32)
	case tReal64:
		return strconv.FormatFloat(math.Float64frombits(le.Uint64(b)), 'g', -1, 64)
	case tBool:
		if le.Uint32(b) != 0 {
			return "true"
		}
		return "false"
	case tBinary:
		return strings.ToUpper(hex.EncodeToString(b))
	case tGUID:
		return guid(b)
	case tSizeT:
		switch len(b) {
		case 4:
			return fmt.Sprintf("0x%x", le.Uint32(b))
		case 8:
			return fmt.Sprintf("0x%x", le.Uint64(b))
		}
		return hexValue(b)
	case tFileTime:
		return filetime(le.Uint64(b)).Format(timeLayout)
	case tSysTime:
		return systemtime(b)
	case tSID:
		return sid(b)
	case tHexInt32:
		return fmt.Sprintf("0x%x", le.Uint32(b))
	case tHexInt64:
		return fmt.Sprintf("0x%x", le.Uint64(b))
	}
	return hexValue(b)
}

// signed reads the low bits of v as a two's complement integer (bits < 64).
func signed(v uint64, bits uint) int64 {
	if v >= 1<<(bits-1) {
		return int64(v) - 1<<bits // #nosec G115 -- v < 2^bits <= 2^32
	}
	return int64(v) // #nosec G115 -- as above
}

func formatArray(t byte, b []byte) string {
	switch t {
	case tString:
		parts := strings.Split(strings.TrimRight(utf16Raw(b), "\x00"), "\x00")
		return strings.Join(parts, ", ")
	case tAnsiString:
		return strings.ToValidUTF8(strings.Join(strings.Split(strings.TrimRight(string(b), "\x00"), "\x00"), ", "), "\uFFFD")
	}
	n := fixedSize(t)
	if n == 0 || len(b)%n != 0 {
		return hexValue(b)
	}
	parts := make([]string, 0, len(b)/n)
	for i := 0; i < len(b); i += n {
		parts = append(parts, formatValue(t, b[i:i+n]))
	}
	return strings.Join(parts, ", ")
}

func hexValue(b []byte) string { return "0x" + strings.ToUpper(hex.EncodeToString(b)) }

// utf16Raw decodes UTF-16LE (an odd trailing byte is dropped).
func utf16Raw(b []byte) string {
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[2*i:])
	}
	return string(utf16.Decode(u))
}

// utf16String decodes a UTF-16LE string without its trailing NULs.
func utf16String(b []byte) string { return strings.TrimRight(utf16Raw(b), "\x00") }

// filetime converts 100 ns intervals since 1601-01-01 UTC.
func filetime(v uint64) time.Time {
	const epochSeconds = 11644473600                     // 1601-01-01 → 1970-01-01
	sec := int64(v/10_000_000) - epochSeconds            // #nosec G115 -- v/1e7 < 2^41
	return time.Unix(sec, int64(v%10_000_000)*100).UTC() // #nosec G115 -- < 1e9
}

func systemtime(b []byte) string {
	le := binary.LittleEndian
	f := func(i int) int { return int(le.Uint16(b[2*i:])) }
	// year, month, day of week, day, hour, minute, second, milliseconds
	t := time.Date(f(0), time.Month(f(1)), f(3), f(4), f(5), f(6), f(7)*1_000_000, time.UTC)
	return t.Format(timeLayout)
}

func guid(b []byte) string {
	le := binary.LittleEndian
	return fmt.Sprintf("{%08X-%04X-%04X-%X-%X}", le.Uint32(b[0:4]), le.Uint16(b[4:6]), le.Uint16(b[6:8]), b[8:10], b[10:16])
}

// sid renders a security identifier: S-revision-authority-subauthorities.
func sid(b []byte) string {
	if len(b) < 8 {
		return hexValue(b)
	}
	n := int(b[1])
	if len(b) < 8+4*n {
		return hexValue(b)
	}
	var auth uint64
	for _, c := range b[2:8] {
		auth = auth<<8 | uint64(c)
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "S-%d-%d", b[0], auth)
	for i := range n {
		fmt.Fprintf(&sb, "-%d", binary.LittleEndian.Uint32(b[8+4*i:]))
	}
	return sb.String()
}
