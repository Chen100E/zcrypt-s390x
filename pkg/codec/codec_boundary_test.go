package codec

import (
	"bytes"
	"math"
	"testing"
)

// headerLen is the fixed prefix size: magic(4) + timestamp(8) + float(8) + len(4).
const headerLen = 24

func TestPacketRoundTripEmptyPayload(t *testing.T) {
	original := &MainframePacket{
		Magic:     0x5A435250,
		Timestamp: -1,
		FloatVal:  -0.0,
		Payload:   nil,
	}
	encoded := original.Encode()
	if len(encoded) != headerLen {
		t.Fatalf("encoded length = %d, want %d for an empty payload", len(encoded), headerLen)
	}
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if decoded.Magic != original.Magic || decoded.Timestamp != original.Timestamp {
		t.Errorf("scalar fields corrupted: got %+v", decoded)
	}
	if decoded.PayloadLen != 0 || len(decoded.Payload) != 0 {
		t.Errorf("payload should be empty, got len=%d", len(decoded.Payload))
	}
}

func TestPacketRoundTripExtremes(t *testing.T) {
	original := &MainframePacket{
		Magic:     math.MaxUint32,
		Timestamp: math.MaxInt64,
		FloatVal:  math.MaxFloat64,
		Payload:   bytes.Repeat([]byte{0xFE}, 4096),
	}
	decoded, err := Decode(original.Encode())
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if decoded.Magic != math.MaxUint32 {
		t.Errorf("Magic = %#x, want %#x", decoded.Magic, uint32(math.MaxUint32))
	}
	if decoded.Timestamp != math.MaxInt64 {
		t.Errorf("Timestamp = %d, want %d", decoded.Timestamp, int64(math.MaxInt64))
	}
	if decoded.FloatVal != math.MaxFloat64 {
		t.Errorf("FloatVal = %v, want %v", decoded.FloatVal, math.MaxFloat64)
	}
	if !bytes.Equal(decoded.Payload, original.Payload) {
		t.Error("payload mismatch on a 4 KiB packet")
	}
}

// TestPacketBigEndianLayout pins the on-wire byte order byte by byte. This is
// the core endianness guarantee of the package: a little-endian host must
// still emit a big-endian stream.
func TestPacketBigEndianLayout(t *testing.T) {
	p := &MainframePacket{
		Magic:     0x01020304,
		Timestamp: 0x0102030405060708,
		FloatVal:  0,
		Payload:   []byte{0xAA, 0xBB},
	}
	buf := p.Encode()
	want := []byte{
		0x01, 0x02, 0x03, 0x04, // magic, big-endian
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // timestamp, big-endian
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // float64(0), big-endian
		0x00, 0x00, 0x00, 0x02, // payload length 2, big-endian
		0xAA, 0xBB, // payload
	}
	if !bytes.Equal(buf, want) {
		t.Fatalf("wire layout mismatch\n got %x\nwant %x", buf, want)
	}
}

func TestDecodeTruncatedBuffer(t *testing.T) {
	// Every length below the 24-byte header must be rejected, including zero.
	for _, n := range []int{0, 1, 4, 12, 23} {
		if _, err := Decode(make([]byte, n)); err == nil {
			t.Errorf("Decode accepted a %d-byte buffer, want an underflow error", n)
		}
	}
	// Exactly the header is legal and yields an empty payload.
	if _, err := Decode(make([]byte, headerLen)); err != nil {
		t.Errorf("Decode rejected a bare %d-byte header: %v", headerLen, err)
	}
}

// TestDecodePayloadLengthLies covers the malformed-buffer case where the header
// claims more payload than the buffer actually carries.
func TestDecodePayloadLengthLies(t *testing.T) {
	p := &MainframePacket{Magic: 1, Payload: []byte("abc")}
	buf := p.Encode()

	// Truncate the payload but leave the length field claiming 3 bytes.
	truncated := buf[:len(buf)-1]
	if _, err := Decode(truncated); err == nil {
		t.Error("Decode accepted a buffer whose payload length exceeds the data")
	}

	// Inflate the declared length far past the buffer end.
	inflated := append([]byte(nil), buf...)
	inflated[20], inflated[21], inflated[22], inflated[23] = 0xFF, 0xFF, 0xFF, 0xFF
	if _, err := Decode(inflated); err == nil {
		t.Error("Decode accepted a buffer with a 4 GiB declared payload")
	}

	// A declared length of exactly the remaining bytes must still succeed.
	exact := append([]byte(nil), buf...)
	exact[20], exact[21], exact[22], exact[23] = 0, 0, 0, 3
	if _, err := Decode(exact); err != nil {
		t.Errorf("Decode rejected a correct length field: %v", err)
	}
}

// TestDecodeTrailingBytesAreIgnored documents that a longer buffer decodes on
// the declared length rather than failing, which is what a streaming reader
// needs when several packets share one read.
func TestDecodeTrailingBytesAreIgnored(t *testing.T) {
	p := &MainframePacket{Magic: 7, Timestamp: 42, Payload: []byte("xy")}
	buf := append(p.Encode(), []byte("TRAILING")...)
	decoded, err := Decode(buf)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !bytes.Equal(decoded.Payload, []byte("xy")) {
		t.Errorf("Payload = %q, want \"xy\"", decoded.Payload)
	}
}

func TestEncodeZeroValuePacket(t *testing.T) {
	var p MainframePacket
	buf := p.Encode()
	if len(buf) != headerLen {
		t.Fatalf("zero-value Encode length = %d, want %d", len(buf), headerLen)
	}
	if !bytes.Equal(buf, make([]byte, headerLen)) {
		t.Errorf("zero-value packet should encode to all zeros, got %x", buf)
	}
	decoded, err := Decode(buf)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if decoded.Magic != 0 || decoded.PayloadLen != 0 {
		t.Errorf("zero-value round trip corrupted: %+v", decoded)
	}
}

// TestEncodeLengthFieldTracksPayload guards against the length field being
// taken from a stale PayloadLen rather than the actual slice.
func TestEncodeLengthFieldTracksPayload(t *testing.T) {
	p := &MainframePacket{Payload: []byte("hello"), PayloadLen: 999}
	buf := p.Encode()
	gotLen := int(uint32(buf[20])<<24 | uint32(buf[21])<<16 | uint32(buf[22])<<8 | uint32(buf[23]))
	if gotLen != 5 {
		t.Errorf("encoded length field = %d, want 5 (the real payload size)", gotLen)
	}
}
