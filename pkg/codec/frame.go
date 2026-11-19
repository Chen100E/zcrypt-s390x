package codec

// A self-describing network frame: magic, version, type, flags, length, sequence
// number, payload, and a CRC-32C trailer.
//
// The design is driven by what actually goes wrong with a binary framing layer:
//
//	Wrong bytes on the wire   -> magic number checked first, so a stream that is
//	                             not ours fails at byte 0 instead of being
//	                             misparsed into a plausible-looking header.
//	Protocol version skew     -> explicit version field, rejected if unknown.
//	Truncation                -> length prefix checked against remaining input
//	                             before any allocation.
//	Length lies               -> a maximum frame size, enforced on both encode and
//	                             decode.
//	Bit rot / torn writes     -> CRC-32C over everything except the trailer.
//	Replay / reorder          -> sequence number carried in the header, left for
//	                             the caller to enforce.
//
// The header layout is fixed and big-endian:
//
//	 0      4      5      6      7      8      12     16
//	 +------+------+------+------+------+-------+------+---------+--------+
//	 |magic | ver  | type |flags | len  |  seq  |payload|  crc32c | (frame)
//	 |  4B  |  1B  |  1B  |  1B  |  4B  |  8B   | len B |   4B    |
//	 +------+------+------+------+------+-------+------+---------+--------+
//
// `len` counts the payload only, so the total frame size is
// FrameHeaderSize + len + FrameTrailerSize.
//
// CRC-32C (Castagnoli) rather than CRC-32 (IEEE) because Castagnoli is what
// s390x accelerates in hardware: the kernel registers crc32c-vx at priority 300
// on this machine, and the polynomial has better error-detection properties for
// the burst lengths that matter in a frame. The implementation here is the
// portable table-driven one; a caller that needs the hardware path can substitute
// hash/crc32, which dispatches to the vector instruction automatically.

import (
	"errors"
	"fmt"
	"math"
)

const (
	// FrameMagic is the four-byte identifier at the start of every frame. The
	// value spells "ZCRY" in ASCII, which makes a hexdump of a captured stream
	// self-explanatory.
	FrameMagic uint32 = 0x5A435259

	// FrameVersion is the only protocol version this build understands.
	FrameVersion uint8 = 1

	// FrameHeaderSize is the fixed header length in bytes.
	FrameHeaderSize = 4 + 1 + 1 + 1 + 4 + 8 // 19

	// FrameTrailerSize is the checksum length in bytes.
	FrameTrailerSize = 4

	// MaxFramePayload is the largest payload a frame may carry. 1 MiB is enough
	// for a batch of records and small enough that a corrupt length prefix fails
	// before a 4 GiB allocation is attempted.
	MaxFramePayload = 1 << 20
)

// FrameType identifies what a frame carries. The values are part of the wire
// protocol, so they must never be renumbered.
type FrameType uint8

const (
	// FrameTypeData carries application payload.
	FrameTypeData FrameType = 0x01
	// FrameTypeControl carries protocol control messages.
	FrameTypeControl FrameType = 0x02
	// FrameTypeHeartbeat carries no payload and exists to keep a NAT binding
	// alive.
	FrameTypeHeartbeat FrameType = 0x03
)

// String names a frame type for logging.
func (t FrameType) String() string {
	switch t {
	case FrameTypeData:
		return "DATA"
	case FrameTypeControl:
		return "CONTROL"
	case FrameTypeHeartbeat:
		return "HEARTBEAT"
	}
	return fmt.Sprintf("UNKNOWN(0x%02x)", uint8(t))
}

// Valid reports whether the type is one this build understands. An unknown type
// is a protocol error, not something to pass through, because the receiver
// cannot know whether the payload is safe to ignore.
func (t FrameType) Valid() bool {
	switch t {
	case FrameTypeData, FrameTypeControl, FrameTypeHeartbeat:
		return true
	}
	return false
}

// Frame flag bits.
const (
	// FlagCompressed marks the payload as compressed. The codec does not
	// compress; the flag is carried so a peer knows to decompress.
	FlagCompressed uint8 = 1 << 0
	// FlagEncrypted marks the payload as already encrypted at the application
	// layer, so a transport should not double-encrypt.
	FlagEncrypted uint8 = 1 << 1
	// FlagFinal marks the last frame of a message split across frames.
	FlagFinal uint8 = 1 << 2
)

// Frame is a decoded protocol frame.
type Frame struct {
	Version uint8
	Type    FrameType
	Flags   uint8
	Seq     uint64
	Payload []byte
}

// Errors returned by the frame layer.
var (
	// ErrBadMagic means the stream does not start with FrameMagic.
	ErrBadMagic = errors.New("codec: bad frame magic")
	// ErrBadVersion means the frame declares a version this build cannot parse.
	ErrBadVersion = errors.New("codec: unsupported frame version")
	// ErrBadFrameType means the type byte is not a known type.
	ErrBadFrameType = errors.New("codec: unknown frame type")
	// ErrFrameTooLarge means the declared payload exceeds MaxFramePayload.
	ErrFrameTooLarge = errors.New("codec: frame payload too large")
	// ErrBadChecksum means the CRC-32C trailer does not match the frame body.
	ErrBadChecksum = errors.New("codec: frame checksum mismatch")
	// ErrTrailingBytes means the buffer held more than one complete frame and
	// the caller asked for exactly one.
	ErrTrailingBytes = errors.New("codec: trailing bytes after frame")
)

// EncodeFrame serialises a frame into a newly allocated buffer.
//
// The returned slice is exactly FrameHeaderSize + len(Payload) + FrameTrailerSize
// bytes, with no slack, so a caller can write it straight to a socket.
func EncodeFrame(f Frame) ([]byte, error) {
	if f.Version == 0 {
		f.Version = FrameVersion
	}
	if f.Version != FrameVersion {
		return nil, fmt.Errorf("%w: got %d, this build speaks %d",
			ErrBadVersion, f.Version, FrameVersion)
	}
	if !f.Type.Valid() {
		return nil, fmt.Errorf("%w: 0x%02x", ErrBadFrameType, uint8(f.Type))
	}
	if len(f.Payload) > MaxFramePayload {
		return nil, fmt.Errorf("%w: %d bytes exceeds the %d-byte limit",
			ErrFrameTooLarge, len(f.Payload), MaxFramePayload)
	}
	// A heartbeat carries no payload by definition; allowing one would make the
	// type meaningless.
	if f.Type == FrameTypeHeartbeat && len(f.Payload) != 0 {
		return nil, fmt.Errorf("codec: heartbeat frame must have an empty payload, got %d bytes",
			len(f.Payload))
	}

	total := FrameHeaderSize + len(f.Payload) + FrameTrailerSize
	buf := make([]byte, total)
	w := NewWriter(buf)

	if err := w.Uint32(FrameMagic); err != nil {
		return nil, err
	}
	if err := w.Uint8(f.Version); err != nil {
		return nil, err
	}
	if err := w.Uint8(uint8(f.Type)); err != nil {
		return nil, err
	}
	if err := w.Uint8(f.Flags); err != nil {
		return nil, err
	}
	if err := w.Uint32(uint32(len(f.Payload))); err != nil {
		return nil, err
	}
	if err := w.Uint64(f.Seq); err != nil {
		return nil, err
	}
	if err := w.Raw(f.Payload); err != nil {
		return nil, err
	}

	// The checksum covers everything written so far: header and payload, not the
	// trailer itself (which cannot cover itself).
	crc := crc32c(buf[:w.Offset()])
	if err := w.Uint32(crc); err != nil {
		return nil, err
	}
	return buf, nil
}

// DecodeFrame parses exactly one frame from buf.
//
// It requires buf to contain exactly one frame: trailing bytes are an error
// rather than being ignored, because a caller that thinks it is reading one frame
// and silently gets the first of several will desynchronise. Use DecodeFrameFrom
// when the buffer holds a stream.
func DecodeFrame(buf []byte) (*Frame, error) {
	f, n, err := DecodeFrameFrom(buf)
	if err != nil {
		return nil, err
	}
	if n != len(buf) {
		return nil, fmt.Errorf("%w: parsed %d of %d bytes", ErrTrailingBytes, n, len(buf))
	}
	return f, nil
}

// DecodeFrameFrom parses one frame from the front of buf and reports how many
// bytes it consumed, so a caller can loop over a stream.
//
// The order of checks is the point of the function. Magic, version, type and
// length are all validated before the payload slice is taken, and the checksum is
// validated before the payload is returned. A caller therefore never sees a
// payload that failed its integrity check, which is the property that makes this
// usable as a trust boundary.
func DecodeFrameFrom(buf []byte) (*Frame, int, error) {
	if len(buf) < FrameHeaderSize {
		return nil, 0, fmt.Errorf("%w: need %d header bytes, have %d",
			ErrShortBuffer, FrameHeaderSize, len(buf))
	}

	r := NewReader(buf)
	r.SetMaxFieldLen(MaxFramePayload)

	magic, err := r.Uint32()
	if err != nil {
		return nil, 0, err
	}
	if magic != FrameMagic {
		return nil, 0, fmt.Errorf("%w: got 0x%08x, want 0x%08x", ErrBadMagic, magic, FrameMagic)
	}

	version, err := r.Uint8()
	if err != nil {
		return nil, 0, err
	}
	if version != FrameVersion {
		return nil, 0, fmt.Errorf("%w: got %d, this build speaks %d",
			ErrBadVersion, version, FrameVersion)
	}

	typeByte, err := r.Uint8()
	if err != nil {
		return nil, 0, err
	}
	ft := FrameType(typeByte)
	if !ft.Valid() {
		return nil, 0, fmt.Errorf("%w: 0x%02x", ErrBadFrameType, typeByte)
	}

	flags, err := r.Uint8()
	if err != nil {
		return nil, 0, err
	}

	payloadLen, err := r.Uint32()
	if err != nil {
		return nil, 0, err
	}
	if payloadLen > MaxFramePayload {
		return nil, 0, fmt.Errorf("%w: declared %d bytes, limit is %d",
			ErrFrameTooLarge, payloadLen, MaxFramePayload)
	}

	seq, err := r.Uint64()
	if err != nil {
		return nil, 0, err
	}

	// Check the total length before touching the payload, so a declared length
	// that runs past the buffer fails with a clear error rather than a short read.
	needed := FrameHeaderSize + int(payloadLen) + FrameTrailerSize
	if len(buf) < needed {
		return nil, 0, fmt.Errorf("%w: frame declares %d payload bytes, needs %d total, have %d",
			ErrShortBuffer, payloadLen, needed, len(buf))
	}

	bodyEnd := FrameHeaderSize + int(payloadLen)
	storedCRC, err := peekUint32(buf[bodyEnd : bodyEnd+FrameTrailerSize])
	if err != nil {
		return nil, 0, err
	}

	// Verify before returning anything derived from the payload.
	actualCRC := crc32c(buf[:bodyEnd])
	if actualCRC != storedCRC {
		return nil, 0, fmt.Errorf("%w: stored 0x%08x, computed 0x%08x",
			ErrBadChecksum, storedCRC, actualCRC)
	}

	payload := buf[FrameHeaderSize:bodyEnd]
	if ft == FrameTypeHeartbeat && len(payload) != 0 {
		return nil, 0, fmt.Errorf("codec: heartbeat frame carries %d payload bytes", len(payload))
	}

	return &Frame{
		Version: version,
		Type:    ft,
		Flags:   flags,
		Seq:     seq,
		Payload: payload,
	}, needed, nil
}

// peekUint32 reads a big-endian uint32 without advancing anything.
func peekUint32(b []byte) (uint32, error) {
	if len(b) < 4 {
		return 0, fmt.Errorf("%w: need 4 bytes for the checksum, have %d", ErrShortBuffer, len(b))
	}
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]), nil
}

// HasFlag reports whether a flag bit is set.
func (f *Frame) HasFlag(bit uint8) bool { return f.Flags&bit != 0 }

// crc32c computes the CRC-32C (Castagnoli, polynomial 0x1EDC6F41, reflected form
// 0x82F63B78) of data.
//
// It is the standard reflected table-driven implementation: build the 256-entry
// table once, then fold in one byte at a time. The initial value and final XOR
// are both all-ones, which is what every CRC-32C definition in use specifies —
// getting either wrong produces a checksum that is self-consistent (so a
// round-trip test passes) but disagrees with every other implementation, which is
// why the tests assert against published CRC-32C test vectors.
func crc32c(data []byte) uint32 {
	crc := ^uint32(0)
	for _, b := range data {
		crc = crcTable[byte(crc)^b] ^ (crc >> 8)
	}
	return ^crc
}

// crcTable is the CRC-32C lookup table, built at init from the reflected
// polynomial.
var crcTable = func() [256]uint32 {
	const poly = 0x82F63B78 // reflected 0x1EDC6F41
	var t [256]uint32
	for i := 0; i < 256; i++ {
		crc := uint32(i)
		for bit := 0; bit < 8; bit++ {
			if crc&1 != 0 {
				crc = (crc >> 1) ^ poly
			} else {
				crc >>= 1
			}
		}
		t[i] = crc
	}
	return t
}()

// CRC32C exposes the checksum for callers that want to protect their own
// structures with the same function the frame trailer uses.
func CRC32C(data []byte) uint32 { return crc32c(data) }

// FrameSizeFor returns the total encoded size of a frame carrying payloadLen
// bytes, so a caller can size a buffer before encoding.
func FrameSizeFor(payloadLen int) (int, error) {
	if payloadLen < 0 {
		return 0, errors.New("codec: negative payload length")
	}
	if payloadLen > MaxFramePayload {
		return 0, fmt.Errorf("%w: %d bytes exceeds the %d-byte limit",
			ErrFrameTooLarge, payloadLen, MaxFramePayload)
	}
	if int64(payloadLen)+FrameHeaderSize+FrameTrailerSize > math.MaxInt32 {
		return 0, errors.New("codec: frame size overflows int32")
	}
	return FrameHeaderSize + payloadLen + FrameTrailerSize, nil
}
