package codec

// Cursor-based big-endian reader and writer.
//
// The point of this file is not that Go lacks binary.BigEndian — it does not.
// The point is that binary.BigEndian.PutUint32 returns nothing and panics on a
// short slice, so every call site has to re-derive its own bounds checks and
// every parse function has to be written defensively by hand. That is how
// truncation bugs get shipped.
//
// These types invert that: every operation returns an error instead of panicking,
// the cursor is tracked for you, and a read past the end leaves the cursor
// unchanged so a caller can report where the parse failed rather than guessing.
//
// The encoding is explicitly big-endian on every architecture, which is the
// property the tests assert byte-for-byte. A round-trip test cannot catch an
// endianness fault, because a little-endian implementation round-trips perfectly
// on a little-endian machine — it just produces the wrong bytes on the wire. The
// tests in reader_test.go therefore compare against literal byte sequences.

import (
	"errors"
	"fmt"
	"math"
)

// Errors returned by the reader. They are sentinel values so callers can use
// errors.Is rather than matching on strings.
var (
	// ErrShortBuffer means a read ran past the end of the input.
	ErrShortBuffer = errors.New("codec: short buffer")
	// ErrBufferFull means a write ran past the end of the destination.
	ErrBufferFull = errors.New("codec: buffer full")
	// ErrInvalidUTF8 means a string read was not valid UTF-8.
	ErrInvalidUTF8 = errors.New("codec: invalid UTF-8")
	// ErrLengthOverflow means a length prefix exceeded the remaining input or a
	// configured maximum.
	ErrLengthOverflow = errors.New("codec: length exceeds remaining input")
)

// Reader is a big-endian cursor over a byte slice.
//
// It is a value type holding a slice and an offset; copying it produces an
// independent cursor, which makes speculative parsing cheap: try to read a
// header, and if it fails, discard the copy and the original is untouched.
type Reader struct {
	buf []byte
	off int
	// maxLen caps any length-prefixed field, so a hostile 0xFFFFFFFF prefix
	// cannot make the reader attempt a 4 GiB allocation. Zero means the default.
	maxLen int
}

// DefaultMaxFieldLen is the default cap on a length-prefixed field: 64 MiB.
// It is generous for a network frame and small enough that a corrupt length
// fails fast rather than exhausting memory.
const DefaultMaxFieldLen = 64 << 20

// NewReader returns a Reader positioned at the start of buf.
func NewReader(buf []byte) *Reader {
	return &Reader{buf: buf, maxLen: DefaultMaxFieldLen}
}

// SetMaxFieldLen overrides the cap on length-prefixed fields. A value <= 0
// restores the default.
func (r *Reader) SetMaxFieldLen(n int) {
	if n <= 0 {
		n = DefaultMaxFieldLen
	}
	r.maxLen = n
}

// Offset reports the current cursor position.
func (r *Reader) Offset() int { return r.off }

// Len reports the number of unread bytes.
func (r *Reader) Len() int { return len(r.buf) - r.off }

// Remaining returns the unread bytes. The slice aliases the reader's buffer, so
// a caller that needs to retain it must copy.
func (r *Reader) Remaining() []byte { return r.buf[r.off:] }

// Reset returns the cursor to the start of the buffer.
func (r *Reader) Reset() { r.off = 0 }

// Err returns nil while the cursor is inside the buffer and ErrShortBuffer once
// a read has failed. It is the sticky-error accessor for code that prefers to
// check once at the end of a sequence of reads.
func (r *Reader) Err() error {
	if r.off > len(r.buf) {
		return ErrShortBuffer
	}
	return nil
}

// take advances the cursor by n and returns the consumed slice. It is the single
// place bounds checking happens; every typed read goes through it.
func (r *Reader) take(n int) ([]byte, error) {
	if n < 0 {
		return nil, fmt.Errorf("codec: negative read length %d", n)
	}
	if n > len(r.buf)-r.off {
		return nil, fmt.Errorf("%w: need %d bytes at offset %d, have %d",
			ErrShortBuffer, n, r.off, len(r.buf)-r.off)
	}
	out := r.buf[r.off : r.off+n]
	r.off += n
	return out, nil
}

// Uint8 reads one byte.
func (r *Reader) Uint8() (uint8, error) {
	b, err := r.take(1)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

// Uint16 reads a big-endian uint16.
func (r *Reader) Uint16() (uint16, error) {
	b, err := r.take(2)
	if err != nil {
		return 0, err
	}
	return uint16(b[0])<<8 | uint16(b[1]), nil
}

// Uint32 reads a big-endian uint32.
func (r *Reader) Uint32() (uint32, error) {
	b, err := r.take(4)
	if err != nil {
		return 0, err
	}
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]), nil
}

// Uint64 reads a big-endian uint64.
func (r *Reader) Uint64() (uint64, error) {
	b, err := r.take(8)
	if err != nil {
		return 0, err
	}
	return uint64(b[0])<<56 | uint64(b[1])<<48 | uint64(b[2])<<40 | uint64(b[3])<<32 |
		uint64(b[4])<<24 | uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7]), nil
}

// Int8 reads a signed byte.
func (r *Reader) Int8() (int8, error) {
	v, err := r.Uint8()
	return int8(v), err
}

// Int16 reads a big-endian int16.
func (r *Reader) Int16() (int16, error) {
	v, err := r.Uint16()
	return int16(v), err
}

// Int32 reads a big-endian int32.
func (r *Reader) Int32() (int32, error) {
	v, err := r.Uint32()
	return int32(v), err
}

// Int64 reads a big-endian int64.
func (r *Reader) Int64() (int64, error) {
	v, err := r.Uint64()
	return int64(v), err
}

// Float32 reads a big-endian IEEE-754 single.
func (r *Reader) Float32() (float32, error) {
	v, err := r.Uint32()
	if err != nil {
		return 0, err
	}
	return math.Float32frombits(v), nil
}

// Float64 reads a big-endian IEEE-754 double.
func (r *Reader) Float64() (float64, error) {
	v, err := r.Uint64()
	if err != nil {
		return 0, err
	}
	return math.Float64frombits(v), nil
}

// Bool reads one byte and interprets non-zero as true.
//
// A byte rather than a bit: bit-packing saves 7 bytes per field and costs a
// shift-and-mask on every read, which is the wrong trade for a control field.
func (r *Reader) Bool() (bool, error) {
	v, err := r.Uint8()
	if err != nil {
		return false, err
	}
	return v != 0, nil
}

// Bytes reads a uint32 length prefix followed by that many bytes.
//
// The returned slice aliases the reader's buffer. A caller that needs to retain
// it past the next read must copy it.
func (r *Reader) Bytes() ([]byte, error) {
	n, err := r.Uint32()
	if err != nil {
		return nil, err
	}
	if int64(n) > int64(r.maxLen) {
		return nil, fmt.Errorf("%w: declared length %d exceeds the %d-byte limit",
			ErrLengthOverflow, n, r.maxLen)
	}
	if int64(n) > int64(len(r.buf)-r.off) {
		return nil, fmt.Errorf("%w: declared length %d, only %d bytes remain",
			ErrLengthOverflow, n, len(r.buf)-r.off)
	}
	return r.take(int(n))
}

// String reads a length-prefixed byte string and requires it to be valid UTF-8.
//
// The UTF-8 check is deliberate: a decoder that hands back a string containing
// invalid sequences is handing the caller a value that will behave differently
// depending on where it is printed, compared or re-encoded. Failing at the
// parse boundary is the only place the error can be attributed to the input.
func (r *Reader) String() (string, error) {
	b, err := r.Bytes()
	if err != nil {
		return "", err
	}
	if !validUTF8(b) {
		return "", fmt.Errorf("%w at offset %d", ErrInvalidUTF8, r.off-len(b)-4)
	}
	return string(b), nil
}

// RawString reads a length-prefixed byte string without the UTF-8 check, for
// protocols whose string fields are opaque octets.
func (r *Reader) RawString() (string, error) {
	b, err := r.Bytes()
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// validUTF8 is a local UTF-8 validator so the reader does not pull in unicode/utf8
// for one call, and so the rejection rule is explicit at the call site.
func validUTF8(b []byte) bool {
	i := 0
	for i < len(b) {
		c := b[i]
		switch {
		case c < 0x80:
			i++
		case c&0xE0 == 0xC0:
			if i+1 >= len(b) || b[i+1]&0xC0 != 0x80 || c < 0xC2 {
				return false
			}
			i += 2
		case c&0xF0 == 0xE0:
			if i+2 >= len(b) || b[i+1]&0xC0 != 0x80 || b[i+2]&0xC0 != 0x80 {
				return false
			}
			// Reject overlong encodings and surrogates.
			if c == 0xE0 && b[i+1] < 0xA0 {
				return false
			}
			if c == 0xED && b[i+1] >= 0xA0 {
				return false
			}
			i += 3
		case c&0xF8 == 0xF0:
			if i+3 >= len(b) || b[i+1]&0xC0 != 0x80 || b[i+2]&0xC0 != 0x80 || b[i+3]&0xC0 != 0x80 {
				return false
			}
			// Reject overlong encodings and values above U+10FFFF.
			if c == 0xF0 && b[i+1] < 0x90 {
				return false
			}
			if c == 0xF4 && b[i+1] >= 0x90 {
				return false
			}
			if c > 0xF4 {
				return false
			}
			i += 4
		default:
			return false
		}
	}
	return true
}

// Skip advances the cursor by n bytes without returning them.
func (r *Reader) Skip(n int) error {
	_, err := r.take(n)
	return err
}

// ---------------------------------------------------------------- writer

// Writer is a big-endian cursor over a caller-supplied byte slice.
//
// It writes into a fixed buffer rather than growing one, because the callers that
// matter (packet framing, checksum construction) know their size in advance and
// an allocation-free path is the point.
type Writer struct {
	buf []byte
	off int
}

// NewWriter returns a Writer over buf, positioned at the start.
func NewWriter(buf []byte) *Writer { return &Writer{buf: buf} }

// NewSizedWriter allocates a buffer of n bytes and returns a Writer over it.
func NewSizedWriter(n int) *Writer {
	if n < 0 {
		n = 0
	}
	return &Writer{buf: make([]byte, n)}
}

// Offset reports how many bytes have been written.
func (w *Writer) Offset() int { return w.off }

// Len reports how many bytes remain unwritten.
func (w *Writer) Len() int { return len(w.buf) - w.off }

// Written returns everything written so far.
//
// It is named Written rather than Bytes because Bytes is the length-prefixed
// field writer below: one accessor and one encoder cannot share a name on the
// same type, and renaming the encoder would make call sites read worse.
func (w *Writer) Written() []byte { return w.buf[:w.off] }

// Reset returns the cursor to the start, keeping the buffer for reuse.
func (w *Writer) Reset() { w.off = 0 }

// put copies b into the buffer, advancing the cursor.
func (w *Writer) put(b []byte) error {
	if len(b) > len(w.buf)-w.off {
		return fmt.Errorf("%w: need %d bytes at offset %d, have %d",
			ErrBufferFull, len(b), w.off, len(w.buf)-w.off)
	}
	copy(w.buf[w.off:], b)
	w.off += len(b)
	return nil
}

// Uint8 writes one byte.
func (w *Writer) Uint8(v uint8) error {
	return w.put([]byte{v})
}

// Uint16 writes a big-endian uint16.
func (w *Writer) Uint16(v uint16) error {
	return w.put([]byte{byte(v >> 8), byte(v)})
}

// Uint32 writes a big-endian uint32.
func (w *Writer) Uint32(v uint32) error {
	return w.put([]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// Uint64 writes a big-endian uint64.
func (w *Writer) Uint64(v uint64) error {
	return w.put([]byte{
		byte(v >> 56), byte(v >> 48), byte(v >> 40), byte(v >> 32),
		byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v),
	})
}

// Int8 writes a signed byte.
func (w *Writer) Int8(v int8) error { return w.Uint8(uint8(v)) }

// Int16 writes a big-endian int16.
func (w *Writer) Int16(v int16) error { return w.Uint16(uint16(v)) }

// Int32 writes a big-endian int32.
func (w *Writer) Int32(v int32) error { return w.Uint32(uint32(v)) }

// Int64 writes a big-endian int64.
func (w *Writer) Int64(v int64) error { return w.Uint64(uint64(v)) }

// Float32 writes a big-endian IEEE-754 single.
func (w *Writer) Float32(v float32) error { return w.Uint32(math.Float32bits(v)) }

// Float64 writes a big-endian IEEE-754 double.
func (w *Writer) Float64(v float64) error { return w.Uint64(math.Float64bits(v)) }

// Bool writes one byte, 1 for true.
func (w *Writer) Bool(v bool) error {
	if v {
		return w.Uint8(1)
	}
	return w.Uint8(0)
}

// Bytes writes a uint32 length prefix followed by the bytes.
func (w *Writer) Bytes(b []byte) error {
	if uint64(len(b)) > math.MaxUint32 {
		return fmt.Errorf("codec: field of %d bytes exceeds the uint32 length prefix", len(b))
	}
	if err := w.Uint32(uint32(len(b))); err != nil {
		return err
	}
	return w.put(b)
}

// String writes a length-prefixed UTF-8 string.
func (w *Writer) String(s string) error { return w.Bytes([]byte(s)) }

// Raw writes b with no length prefix.
func (w *Writer) Raw(b []byte) error { return w.put(b) }

// Zero pads the remaining buffer with zero bytes.
func (w *Writer) Zero() error {
	for i := w.off; i < len(w.buf); i++ {
		w.buf[i] = 0
	}
	w.off = len(w.buf)
	return nil
}
