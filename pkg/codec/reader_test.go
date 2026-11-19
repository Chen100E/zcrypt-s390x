package codec

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math"
	"testing"
)

// The tests in this file assert exact byte sequences, not round trips.
//
// This is the whole point. A little-endian implementation of a big-endian format
// round-trips perfectly on a little-endian machine: encode writes the bytes one
// way, decode reads them the same way, and the value comes back unchanged. The
// test passes and the wire format is wrong. On s390x there is no compensating
// error to hide behind, but a test that only round-trips would still pass on
// amd64 CI and would not prove anything about the bytes.
//
// Every encoding assertion below therefore compares against a literal hex string
// that was worked out by hand from the format definition.

// TestWriterUint16ExactBytes pins the two-byte encoding.
func TestWriterUint16ExactBytes(t *testing.T) {
	cases := []struct {
		v    uint16
		want string
	}{
		{0x0000, "0000"},
		{0x0001, "0001"},
		{0x0100, "0100"},
		{0x00FF, "00ff"},
		{0xFF00, "ff00"},
		{0x1234, "1234"},
		{0xABCD, "abcd"},
		{0xFFFF, "ffff"},
	}
	for _, c := range cases {
		w := NewSizedWriter(2)
		if err := w.Uint16(c.v); err != nil {
			t.Fatalf("%#04x: %v", c.v, err)
		}
		if got := hex.EncodeToString(w.Written()); got != c.want {
			t.Errorf("Uint16(%#04x) = %s, want %s", c.v, got, c.want)
		}
	}
}

// TestWriterUint32ExactBytes pins the four-byte encoding. 0x01020304 must
// produce "01020304" — the most significant byte first — which is the assertion
// that fails on a little-endian writer.
func TestWriterUint32ExactBytes(t *testing.T) {
	cases := []struct {
		v    uint32
		want string
	}{
		{0x00000000, "00000000"},
		{0x00000001, "00000001"},
		{0x00000100, "00000100"},
		{0x00010000, "00010000"},
		{0x01000000, "01000000"},
		{0x01020304, "01020304"},
		{0xDEADBEEF, "deadbeef"},
		{0xFFFFFFFF, "ffffffff"},
	}
	for _, c := range cases {
		w := NewSizedWriter(4)
		if err := w.Uint32(c.v); err != nil {
			t.Fatalf("%#08x: %v", c.v, err)
		}
		if got := hex.EncodeToString(w.Written()); got != c.want {
			t.Errorf("Uint32(%#08x) = %s, want %s", c.v, got, c.want)
		}
	}
}

// TestWriterUint64ExactBytes pins the eight-byte encoding.
func TestWriterUint64ExactBytes(t *testing.T) {
	cases := []struct {
		v    uint64
		want string
	}{
		{0, "0000000000000000"},
		{1, "0000000000000001"},
		{0x0102030405060708, "0102030405060708"},
		{0xFFEEDDCCBBAA9988, "ffeeddccbbaa9988"},
		{math.MaxUint64, "ffffffffffffffff"},
	}
	for _, c := range cases {
		w := NewSizedWriter(8)
		if err := w.Uint64(c.v); err != nil {
			t.Fatalf("%#016x: %v", c.v, err)
		}
		if got := hex.EncodeToString(w.Written()); got != c.want {
			t.Errorf("Uint64(%#016x) = %s, want %s", c.v, got, c.want)
		}
	}
}

// TestWriterSignedTypesExactBytes pins two's-complement encoding for the signed
// widths: -1 must be all ones, -2 must be all ones except the last byte 0xfe.
func TestWriterSignedTypesExactBytes(t *testing.T) {
	cases := []struct {
		name string
		enc  func(*Writer) error
		want string
	}{
		{"int8(-1)", func(w *Writer) error { return w.Int8(-1) }, "ff"},
		{"int8(-128)", func(w *Writer) error { return w.Int8(-128) }, "80"},
		{"int8(127)", func(w *Writer) error { return w.Int8(127) }, "7f"},
		{"int16(-1)", func(w *Writer) error { return w.Int16(-1) }, "ffff"},
		{"int16(-2)", func(w *Writer) error { return w.Int16(-2) }, "fffe"},
		{"int16(-32768)", func(w *Writer) error { return w.Int16(-32768) }, "8000"},
		{"int32(-1)", func(w *Writer) error { return w.Int32(-1) }, "ffffffff"},
		{"int32(-2147483648)", func(w *Writer) error { return w.Int32(math.MinInt32) }, "80000000"},
		{"int64(-1)", func(w *Writer) error { return w.Int64(-1) }, "ffffffffffffffff"},
		{"int64(-2)", func(w *Writer) error { return w.Int64(-2) }, "fffffffffffffffe"},
	}
	for _, c := range cases {
		w := NewSizedWriter(8)
		if err := c.enc(w); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := hex.EncodeToString(w.Written()); got != c.want {
			t.Errorf("%s = %s, want %s", c.name, got, c.want)
		}
	}
}

// TestWriterFloat64ExactBytes pins the IEEE-754 double encoding against values
// with known bit patterns.
func TestWriterFloat64ExactBytes(t *testing.T) {
	cases := []struct {
		v    float64
		want string
	}{
		{0.0, "0000000000000000"},
		{1.0, "3ff0000000000000"},  // exponent 1023, mantissa 0
		{-1.0, "bff0000000000000"}, // sign bit set
		{2.0, "4000000000000000"},
		{0.5, "3fe0000000000000"},
	}
	for _, c := range cases {
		w := NewSizedWriter(8)
		if err := w.Float64(c.v); err != nil {
			t.Fatalf("%v: %v", c.v, err)
		}
		if got := hex.EncodeToString(w.Written()); got != c.want {
			t.Errorf("Float64(%v) = %s, want %s", c.v, got, c.want)
		}
	}

	// +Inf and NaN have defined bit patterns and must not be special-cased.
	w := NewSizedWriter(16)
	if err := w.Float64(math.Inf(1)); err != nil {
		t.Fatal(err)
	}
	if err := w.Float64(math.NaN()); err != nil {
		t.Fatal(err)
	}
	got := hex.EncodeToString(w.Written())
	if got[:16] != "7ff0000000000000" {
		t.Errorf("+Inf = %s, want 7ff0000000000000", got[:16])
	}
	// NaN is any pattern with all exponent bits set and a non-zero mantissa; the
	// canonical Go NaN is 7ff8000000000001.
	if got[16:20] != "7ff8" {
		t.Errorf("NaN prefix = %s, want 7ff8", got[16:20])
	}
}

// TestWriterFloat32ExactBytes pins the single-precision encoding.
func TestWriterFloat32ExactBytes(t *testing.T) {
	cases := []struct {
		v    float32
		want string
	}{
		{0.0, "00000000"},
		{1.0, "3f800000"},
		{-1.0, "bf800000"},
		{2.0, "40000000"},
		{0.5, "3f000000"},
	}
	for _, c := range cases {
		w := NewSizedWriter(4)
		if err := w.Float32(c.v); err != nil {
			t.Fatalf("%v: %v", c.v, err)
		}
		if got := hex.EncodeToString(w.Written()); got != c.want {
			t.Errorf("Float32(%v) = %s, want %s", c.v, got, c.want)
		}
	}
}

// TestWriterLengthPrefixedBytesExactBytes proves the length prefix is big-endian
// and counts bytes rather than runes.
func TestWriterLengthPrefixedBytesExactBytes(t *testing.T) {
	w := NewSizedWriter(64)
	if err := w.Bytes([]byte{0xAA, 0xBB, 0xCC}); err != nil {
		t.Fatal(err)
	}
	if got, want := hex.EncodeToString(w.Written()), "00000003aabbcc"; got != want {
		t.Errorf("Bytes = %s, want %s", got, want)
	}

	// An empty field is a zero length prefix with no payload.
	w = NewSizedWriter(4)
	if err := w.Bytes(nil); err != nil {
		t.Fatal(err)
	}
	if got, want := hex.EncodeToString(w.Written()), "00000000"; got != want {
		t.Errorf("empty Bytes = %s, want %s", got, want)
	}

	// A string is length-prefixed UTF-8 bytes, so a multi-byte rune makes the
	// prefix longer than the character count. "é" is two bytes in UTF-8.
	w = NewSizedWriter(16)
	if err := w.String("é"); err != nil {
		t.Fatal(err)
	}
	if got, want := hex.EncodeToString(w.Written()), "00000002c3a9"; got != want {
		t.Errorf("String(é) = %s, want %s", got, want)
	}
}

// TestWriterBoolExactBytes proves a bool is one byte, 1 or 0.
func TestWriterBoolExactBytes(t *testing.T) {
	w := NewSizedWriter(2)
	if err := w.Bool(true); err != nil {
		t.Fatal(err)
	}
	if err := w.Bool(false); err != nil {
		t.Fatal(err)
	}
	if got, want := hex.EncodeToString(w.Written()), "0100"; got != want {
		t.Errorf("Bool true,false = %s, want %s", got, want)
	}
}

// TestReaderExactBytes proves the reader interprets the same literals back to the
// values the writer encoded, which is the other half of the wire-format contract.
func TestReaderExactBytes(t *testing.T) {
	// A hand-assembled buffer: u16 0x1234, u32 0xDEADBEEF, u64 1,
	// length-prefixed "hi", bool true.
	const wire = "1234" + "deadbeef" + "0000000000000001" + "00000002" + "6869" + "01"
	buf, err := hex.DecodeString(wire)
	if err != nil {
		t.Fatal(err)
	}

	r := NewReader(buf)

	v16, err := r.Uint16()
	if err != nil || v16 != 0x1234 {
		t.Errorf("Uint16 = %#x, %v; want 0x1234", v16, err)
	}
	v32, err := r.Uint32()
	if err != nil || v32 != 0xDEADBEEF {
		t.Errorf("Uint32 = %#x, %v; want 0xDEADBEEF", v32, err)
	}
	v64, err := r.Uint64()
	if err != nil || v64 != 1 {
		t.Errorf("Uint64 = %#x, %v; want 1", v64, err)
	}
	s, err := r.String()
	if err != nil || s != "hi" {
		t.Errorf("String = %q, %v; want \"hi\"", s, err)
	}
	b, err := r.Bool()
	if err != nil || !b {
		t.Errorf("Bool = %v, %v; want true", b, err)
	}
	if r.Len() != 0 {
		t.Errorf("%d bytes left unread", r.Len())
	}
	if r.Offset() != len(buf) {
		t.Errorf("offset = %d, want %d", r.Offset(), len(buf))
	}
}

// TestReaderShortBufferLeavesCursorUnchanged proves a failed read does not
// advance the cursor, so a caller can report the offset where parsing stopped.
func TestReaderShortBufferLeavesCursorUnchanged(t *testing.T) {
	r := NewReader([]byte{0x01, 0x02})
	if _, err := r.Uint8(); err != nil {
		t.Fatalf("first read: %v", err)
	}
	before := r.Offset()

	// Only one byte remains; a four-byte read must fail.
	if _, err := r.Uint32(); !errors.Is(err, ErrShortBuffer) {
		t.Fatalf("error = %v, want ErrShortBuffer", err)
	}
	if r.Offset() != before {
		t.Errorf("offset moved from %d to %d after a failed read", before, r.Offset())
	}
	// The reader is still usable: a one-byte read succeeds.
	if v, err := r.Uint8(); err != nil || v != 0x02 {
		t.Errorf("Uint8 after failure = %#x, %v", v, err)
	}
}

// TestReaderTruncationAtEveryLength proves every typed read fails cleanly for
// every possible truncation, rather than panicking. A panic here would be a
// remotely triggerable crash in any parser built on this.
func TestReaderTruncationAtEveryLength(t *testing.T) {
	full := []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
	}
	for n := 0; n < len(full); n++ {
		short := full[:n]
		// Each of these must either succeed or return an error, never panic.
		func() {
			defer func() {
				if p := recover(); p != nil {
					t.Errorf("truncation to %d bytes panicked: %v", n, p)
				}
			}()
			r := NewReader(short)
			_, _ = r.Uint16()
			r.Reset()
			_, _ = r.Uint32()
			r.Reset()
			_, _ = r.Uint64()
			r.Reset()
			_, _ = r.Float64()
			r.Reset()
			_, _ = r.String()
			r.Reset()
			_ = r.Skip(8)
		}()
	}
}

// TestReaderLengthPrefixOverflow proves a hostile length prefix is rejected
// before any allocation, and that the maximum-length cap is enforced.
func TestReaderLengthPrefixOverflow(t *testing.T) {
	// A prefix claiming 0xFFFFFFFF bytes with nothing behind it.
	buf := []byte{0xFF, 0xFF, 0xFF, 0xFF}
	r := NewReader(buf)
	_, err := r.Bytes()
	if err == nil {
		t.Fatal("accepted a 4 GiB length prefix with no payload")
	}
	if !errors.Is(err, ErrLengthOverflow) {
		t.Errorf("error = %v, want ErrLengthOverflow", err)
	}

	// A prefix claiming more than the remaining input but under the max.
	buf = []byte{0x00, 0x00, 0x00, 0x10, 0x01, 0x02}
	r = NewReader(buf)
	if _, err := r.Bytes(); !errors.Is(err, ErrLengthOverflow) {
		t.Errorf("error = %v, want ErrLengthOverflow", err)
	}

	// A prefix under the remaining input but above a lowered cap.
	buf = []byte{0x00, 0x00, 0x00, 0x08, 1, 2, 3, 4, 5, 6, 7, 8}
	r = NewReader(buf)
	r.SetMaxFieldLen(4)
	if _, err := r.Bytes(); !errors.Is(err, ErrLengthOverflow) {
		t.Errorf("error = %v, want ErrLengthOverflow with a 4-byte cap", err)
	}

	// The same buffer with the default cap must succeed.
	r = NewReader(buf)
	if b, err := r.Bytes(); err != nil || len(b) != 8 {
		t.Errorf("default cap: %d bytes, %v", len(b), err)
	}
}

// TestReaderRejectsInvalidUTF8 proves a string field containing an invalid
// sequence is rejected at the parse boundary, and that RawString still returns it.
func TestReaderRejectsInvalidUTF8(t *testing.T) {
	cases := []struct {
		name string
		body []byte
	}{
		{"lone continuation", []byte{0x80}},
		{"truncated two-byte", []byte{0xC3}},
		{"overlong two-byte", []byte{0xC0, 0xAF}},
		{"overlong three-byte", []byte{0xE0, 0x80, 0xAF}},
		{"surrogate", []byte{0xED, 0xA0, 0x80}},
		{"truncated four-byte", []byte{0xF0, 0x9F, 0x92}},
		{"above U+10FFFF", []byte{0xF4, 0x90, 0x80, 0x80}},
		{"invalid start byte", []byte{0xFF}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			buf := make([]byte, 4+len(c.body))
			buf[0] = byte(len(c.body) >> 24)
			buf[1] = byte(len(c.body) >> 16)
			buf[2] = byte(len(c.body) >> 8)
			buf[3] = byte(len(c.body))
			copy(buf[4:], c.body)

			r := NewReader(buf)
			if _, err := r.String(); !errors.Is(err, ErrInvalidUTF8) {
				t.Errorf("error = %v, want ErrInvalidUTF8", err)
			}

			// RawString must return the bytes regardless.
			r = NewReader(buf)
			got, err := r.RawString()
			if err != nil {
				t.Fatalf("RawString: %v", err)
			}
			if !bytes.Equal([]byte(got), c.body) {
				t.Errorf("RawString = %x, want %x", []byte(got), c.body)
			}
		})
	}

	// Valid multi-byte sequences must be accepted.
	for _, valid := range [][]byte{
		[]byte("hello"),
		{0xC3, 0xA9},             // é
		{0xE2, 0x82, 0xAC},       // €
		{0xF0, 0x9F, 0x92, 0xA9}, // 💩
		{0x7F},                   // DEL, still valid ASCII
		{0xC2, 0x80},             // U+0080, the lowest two-byte sequence
	} {
		buf := make([]byte, 4+len(valid))
		buf[3] = byte(len(valid))
		copy(buf[4:], valid)
		r := NewReader(buf)
		if _, err := r.String(); err != nil {
			t.Errorf("rejected valid UTF-8 %x: %v", valid, err)
		}
	}
}

// TestWriterBufferFull proves a write past the end fails rather than panicking or
// silently truncating, and that the cursor does not advance on failure.
func TestWriterBufferFull(t *testing.T) {
	w := NewSizedWriter(4)
	if err := w.Uint16(0x1234); err != nil {
		t.Fatalf("first write: %v", err)
	}
	before := w.Offset()

	if err := w.Uint32(0); !errors.Is(err, ErrBufferFull) {
		t.Fatalf("error = %v, want ErrBufferFull", err)
	}
	if w.Offset() != before {
		t.Errorf("offset moved from %d to %d after a failed write", before, w.Offset())
	}
	// The remaining space is still usable.
	if err := w.Uint16(0x5678); err != nil {
		t.Errorf("Uint16 into the remaining space: %v", err)
	}
	if got, want := hex.EncodeToString(w.Written()), "12345678"; got != want {
		t.Errorf("buffer = %s, want %s", got, want)
	}
}

// TestWriterZeroLengthWriter proves a zero-sized writer fails every write rather
// than panicking.
func TestWriterZeroLengthWriter(t *testing.T) {
	w := NewSizedWriter(0)
	if err := w.Uint8(1); !errors.Is(err, ErrBufferFull) {
		t.Errorf("error = %v, want ErrBufferFull", err)
	}
	// A negative size must be treated as zero rather than panicking on make.
	w = NewSizedWriter(-10)
	if w.Len() != 0 {
		t.Errorf("negative size produced a %d-byte buffer", w.Len())
	}
}

// TestWriterResetReusesBuffer proves Reset rewinds without reallocating, which is
// what makes the writer usable in a hot loop.
func TestWriterResetReusesBuffer(t *testing.T) {
	w := NewSizedWriter(16)
	if err := w.Uint32(0xAABBCCDD); err != nil {
		t.Fatal(err)
	}
	first := w.Written()
	w.Reset()
	if w.Offset() != 0 {
		t.Errorf("offset after Reset = %d, want 0", w.Offset())
	}
	if err := w.Uint32(0x11223344); err != nil {
		t.Fatal(err)
	}
	if got, want := hex.EncodeToString(w.Written()), "11223344"; got != want {
		t.Errorf("after Reset = %s, want %s", got, want)
	}
	// The underlying array is shared, so the first slice now shows the new bytes.
	// That is documented behaviour and the reason Bytes() returns a view.
	if len(first) != 4 {
		t.Errorf("previous view length changed to %d", len(first))
	}
}

// TestWriterZeroPadsRemainder covers the padding helper.
func TestWriterZeroPadsRemainder(t *testing.T) {
	w := NewSizedWriter(8)
	if err := w.Uint16(0x0102); err != nil {
		t.Fatal(err)
	}
	if err := w.Zero(); err != nil {
		t.Fatal(err)
	}
	if got, want := hex.EncodeToString(w.Written()), "0102000000000000"; got != want {
		t.Errorf("padded = %s, want %s", got, want)
	}
	if w.Len() != 0 {
		t.Errorf("%d bytes remain after Zero", w.Len())
	}
}

// TestReaderSkipAndRemaining covers the cursor helpers.
func TestReaderSkipAndRemaining(t *testing.T) {
	r := NewReader([]byte{1, 2, 3, 4, 5})
	if err := r.Skip(2); err != nil {
		t.Fatal(err)
	}
	if got := r.Remaining(); !bytes.Equal(got, []byte{3, 4, 5}) {
		t.Errorf("Remaining = %v, want [3 4 5]", got)
	}
	if r.Len() != 3 {
		t.Errorf("Len = %d, want 3", r.Len())
	}
	if err := r.Skip(10); !errors.Is(err, ErrShortBuffer) {
		t.Errorf("overskip error = %v, want ErrShortBuffer", err)
	}
	if err := r.Skip(-1); err == nil {
		t.Error("negative skip was accepted")
	}
	r.Reset()
	if r.Offset() != 0 || r.Len() != 5 {
		t.Errorf("after Reset offset=%d len=%d", r.Offset(), r.Len())
	}
}

// TestReaderIsCopyable proves a Reader copy is an independent cursor, which is
// what makes speculative parsing safe.
func TestReaderIsCopyable(t *testing.T) {
	r := NewReader([]byte{1, 2, 3, 4})
	if _, err := r.Uint8(); err != nil {
		t.Fatal(err)
	}
	snapshot := *r // copy

	// Advance the copy.
	if _, err := snapshot.Uint8(); err != nil {
		t.Fatal(err)
	}
	if snapshot.Offset() != 2 {
		t.Errorf("copy offset = %d, want 2", snapshot.Offset())
	}
	// The original must be untouched.
	if r.Offset() != 1 {
		t.Errorf("original offset = %d, want 1; the copy shared state", r.Offset())
	}
}
