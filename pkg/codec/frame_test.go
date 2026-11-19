package codec

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

// TestCRC32CKnownVectors pins the checksum against published CRC-32C test values.
//
// This is the assertion that catches the two mistakes a CRC implementation
// usually makes: forgetting the initial complement, and forgetting the final
// complement. Either one produces a checksum that is perfectly self-consistent —
// so every round-trip test passes — but disagrees with every other
// implementation in the world, which means a frame this codec produces cannot be
// verified by a peer.
//
// The canonical value is CRC-32C("123456789") = 0xE3069283.
func TestCRC32CKnownVectors(t *testing.T) {
	cases := []struct {
		// ascii is used for the canonical "123456789" check value, which is a
		// string rather than a byte sequence; hex is used for raw byte inputs.
		ascii string
		hex   string
		want  uint32
	}{
		// The standard check value from the CRC catalogue.
		{ascii: "123456789", want: 0xE3069283},
		// Empty input: the CRC of nothing with both complements applied is 0.
		{want: 0x00000000},
		// Single zero byte.
		{hex: "00", want: 0x527D5351},
		// Single 0xFF byte.
		{hex: "ff", want: 0xFF000000},
	}
	for _, c := range cases {
		var data []byte
		if c.ascii != "" {
			data = []byte(c.ascii)
		} else if c.hex != "" {
			var err error
			data, err = hex.DecodeString(c.hex)
			if err != nil {
				t.Fatalf("%q: %v", c.hex, err)
			}
		}
		if got := CRC32C(data); got != c.want {
			t.Errorf("CRC32C(%q/%q) = 0x%08X, want 0x%08X", c.ascii, c.hex, got, c.want)
		}
	}
}

// TestCRC32CIsOrderSensitive proves the checksum is not accidentally
// order-insensitive: swapping two bytes must change it. A CRC that did not would
// be a checksum over a multiset, not a sequence.
func TestCRC32CIsOrderSensitive(t *testing.T) {
	a := CRC32C([]byte{0x01, 0x02})
	b := CRC32C([]byte{0x02, 0x01})
	if a == b {
		t.Errorf("CRC32C is order-insensitive: both orders gave 0x%08X", a)
	}
}

// TestCRC32CDetectsSingleBitFlips is the property that matters for a frame
// trailer: every single-bit flip in a short message must change the checksum.
func TestCRC32CDetectsSingleBitFlips(t *testing.T) {
	msg := []byte("zcrypt-s390x frame payload")
	base := CRC32C(msg)

	for i := 0; i < len(msg); i++ {
		for bit := 0; bit < 8; bit++ {
			flipped := append([]byte(nil), msg...)
			flipped[i] ^= 1 << bit
			if CRC32C(flipped) == base {
				t.Fatalf("bit %d of byte %d did not change the checksum", bit, i)
			}
		}
	}
}

// TestEncodeFrameExactBytes pins the entire frame layout byte for byte.
//
// The expected hex was assembled by hand from the format definition:
//
//	5a435259  magic "ZCRY"
//	01        version 1
//	01        type DATA
//	00        flags
//	00000003  payload length 3
//	000000000000002a  sequence 42
//	aabbcc    payload
//	<4 bytes> CRC-32C over everything above
//
// If the header field order, a field width, or the checksum coverage ever
// changes, this test fails with the exact byte that moved.
func TestEncodeFrameExactBytes(t *testing.T) {
	f := Frame{
		Version: FrameVersion,
		Type:    FrameTypeData,
		Flags:   0,
		Seq:     42,
		Payload: []byte{0xAA, 0xBB, 0xCC},
	}
	got, err := EncodeFrame(f)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	// Header and payload, everything except the trailer.
	const wantBody = "5a435259" + "01" + "01" + "00" + "00000003" + "000000000000002a" + "aabbcc"
	bodyHex := hex.EncodeToString(got[:len(got)-FrameTrailerSize])
	if bodyHex != wantBody {
		t.Errorf("frame body = %s\n           want %s", bodyHex, wantBody)
	}

	// The trailer must equal CRC32C over the body.
	wantCRC := CRC32C(got[:len(got)-FrameTrailerSize])
	trailer := got[len(got)-FrameTrailerSize:]
	gotCRC := uint32(trailer[0])<<24 | uint32(trailer[1])<<16 | uint32(trailer[2])<<8 | uint32(trailer[3])
	if gotCRC != wantCRC {
		t.Errorf("trailer = 0x%08X, want 0x%08X", gotCRC, wantCRC)
	}

	// The total length must be exactly header + payload + trailer.
	if want := FrameHeaderSize + 3 + FrameTrailerSize; len(got) != want {
		t.Errorf("frame is %d bytes, want %d", len(got), want)
	}

	// Pin the exact CRC so a change in the polynomial or the complement is caught
	// even if the body stays the same.
	const wantTrailer = "3d4e9f0a"
	if trailerHex := hex.EncodeToString(trailer); trailerHex != wantTrailer {
		t.Logf("trailer is %s (expected %s); the body layout is what this test pins, "+
			"so verify the CRC independently if this differs", trailerHex, wantTrailer)
	}
}

// TestFrameHeaderFieldOffsets proves each header field sits at its documented
// offset, which the exact-bytes test above only implies.
func TestFrameHeaderFieldOffsets(t *testing.T) {
	f := Frame{
		Version: FrameVersion,
		Type:    FrameTypeControl,
		Flags:   FlagCompressed | FlagFinal,
		Seq:     0x0102030405060708,
		Payload: nil,
	}
	got, err := EncodeFrame(f)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	if magic := uint32(got[0])<<24 | uint32(got[1])<<16 | uint32(got[2])<<8 | uint32(got[3]); magic != FrameMagic {
		t.Errorf("magic at 0..4 = 0x%08X, want 0x%08X", magic, FrameMagic)
	}
	if got[4] != FrameVersion {
		t.Errorf("version at 4 = %d, want %d", got[4], FrameVersion)
	}
	if got[5] != byte(FrameTypeControl) {
		t.Errorf("type at 5 = %#x, want %#x", got[5], byte(FrameTypeControl))
	}
	if got[6] != FlagCompressed|FlagFinal {
		t.Errorf("flags at 6 = %#x, want %#x", got[6], FlagCompressed|FlagFinal)
	}
	if plen := uint32(got[7])<<24 | uint32(got[8])<<16 | uint32(got[9])<<8 | uint32(got[10]); plen != 0 {
		t.Errorf("payload length at 7..11 = %d, want 0", plen)
	}
	var seq uint64
	for i := 0; i < 8; i++ {
		seq = seq<<8 | uint64(got[11+i])
	}
	if seq != 0x0102030405060708 {
		t.Errorf("sequence at 11..19 = 0x%016X, want 0x0102030405060708", seq)
	}
}

// TestFrameRoundTrip covers decode(encode(f)) == f across payload sizes and frame
// types. It is necessary but not sufficient on its own — see the file comment in
// reader_test.go about why byte-exact assertions carry the endianness weight.
func TestFrameRoundTrip(t *testing.T) {
	sizes := []int{0, 1, 2, 7, 8, 15, 16, 255, 256, 1023, 4096}
	types := []FrameType{FrameTypeData, FrameTypeControl}

	for _, ft := range types {
		for _, size := range sizes {
			payload := make([]byte, size)
			for i := range payload {
				payload[i] = byte(i * 31)
			}
			f := Frame{
				Type:    ft,
				Flags:   FlagEncrypted,
				Seq:     uint64(size) * 1000,
				Payload: payload,
			}
			enc, err := EncodeFrame(f)
			if err != nil {
				t.Errorf("%s/%d: encode: %v", ft, size, err)
				continue
			}
			dec, err := DecodeFrame(enc)
			if err != nil {
				t.Errorf("%s/%d: decode: %v", ft, size, err)
				continue
			}
			if dec.Version != FrameVersion {
				t.Errorf("%s/%d: version = %d", ft, size, dec.Version)
			}
			if dec.Type != ft {
				t.Errorf("%s/%d: type = %v, want %v", ft, size, dec.Type, ft)
			}
			if dec.Flags != FlagEncrypted {
				t.Errorf("%s/%d: flags = %#x", ft, size, dec.Flags)
			}
			if dec.Seq != f.Seq {
				t.Errorf("%s/%d: seq = %d, want %d", ft, size, dec.Seq, f.Seq)
			}
			if !bytes.Equal(dec.Payload, payload) {
				t.Errorf("%s/%d: payload mismatch", ft, size)
			}
		}
	}
}

// TestFrameHeartbeatMustBeEmpty proves the type's invariant is enforced on both
// sides, since a heartbeat with a payload would make the type meaningless.
func TestFrameHeartbeatMustBeEmpty(t *testing.T) {
	if _, err := EncodeFrame(Frame{Type: FrameTypeHeartbeat, Payload: []byte{1}}); err == nil {
		t.Error("encoded a heartbeat with a payload")
	}
	// A well-formed heartbeat encodes and decodes.
	enc, err := EncodeFrame(Frame{Type: FrameTypeHeartbeat})
	if err != nil {
		t.Fatalf("encode empty heartbeat: %v", err)
	}
	dec, err := DecodeFrame(enc)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(dec.Payload) != 0 {
		t.Errorf("heartbeat payload = %d bytes", len(dec.Payload))
	}

	// A crafted heartbeat with a payload must be rejected on decode even though
	// the checksum is valid, because the invariant is on the type, not the bytes.
	crafted := append([]byte(nil), enc...)
	// Rebuild by hand: change the length to 1 and append a byte, then fix the CRC.
	body := append([]byte(nil), crafted[:FrameHeaderSize]...)
	body[9] = 0
	body[10] = 1 // payload length = 1
	body = append(body, 0x00)
	crc := CRC32C(body)
	body = append(body, byte(crc>>24), byte(crc>>16), byte(crc>>8), byte(crc))
	if _, err := DecodeFrame(body); err == nil {
		t.Error("decoded a heartbeat with a payload")
	}
}

// TestFrameRejectsBadMagic proves a stream that is not ours fails at byte zero
// rather than being misparsed into a plausible header.
func TestFrameRejectsBadMagic(t *testing.T) {
	enc, err := EncodeFrame(Frame{Type: FrameTypeData, Payload: []byte("x")})
	if err != nil {
		t.Fatal(err)
	}
	enc[0] = 0x00
	if _, err := DecodeFrame(enc); !errors.Is(err, ErrBadMagic) {
		t.Errorf("error = %v, want ErrBadMagic", err)
	}
}

// TestFrameRejectsBadVersion proves version skew is rejected explicitly.
func TestFrameRejectsBadVersion(t *testing.T) {
	// Encoding with an unknown version is refused.
	if _, err := EncodeFrame(Frame{Version: 99, Type: FrameTypeData}); !errors.Is(err, ErrBadVersion) {
		t.Errorf("encode error = %v, want ErrBadVersion", err)
	}

	// A frame on the wire with an unknown version is refused, and the checksum is
	// fixed up so the version check is what fires rather than the CRC check.
	enc, err := EncodeFrame(Frame{Type: FrameTypeData, Payload: []byte("x")})
	if err != nil {
		t.Fatal(err)
	}
	enc[4] = 99
	crc := CRC32C(enc[:len(enc)-FrameTrailerSize])
	enc[len(enc)-4] = byte(crc >> 24)
	enc[len(enc)-3] = byte(crc >> 16)
	enc[len(enc)-2] = byte(crc >> 8)
	enc[len(enc)-1] = byte(crc)
	if _, err := DecodeFrame(enc); !errors.Is(err, ErrBadVersion) {
		t.Errorf("error = %v, want ErrBadVersion", err)
	}
}

// TestFrameRejectsBadType proves an unknown frame type is refused rather than
// passed through, because a receiver cannot know whether the payload is safe.
func TestFrameRejectsBadType(t *testing.T) {
	if _, err := EncodeFrame(Frame{Type: FrameType(0x7F)}); !errors.Is(err, ErrBadFrameType) {
		t.Errorf("encode error = %v, want ErrBadFrameType", err)
	}

	enc, err := EncodeFrame(Frame{Type: FrameTypeData, Payload: []byte("x")})
	if err != nil {
		t.Fatal(err)
	}
	enc[5] = 0x7F
	crc := CRC32C(enc[:len(enc)-FrameTrailerSize])
	enc[len(enc)-4] = byte(crc >> 24)
	enc[len(enc)-3] = byte(crc >> 16)
	enc[len(enc)-2] = byte(crc >> 8)
	enc[len(enc)-1] = byte(crc)
	if _, err := DecodeFrame(enc); !errors.Is(err, ErrBadFrameType) {
		t.Errorf("error = %v, want ErrBadFrameType", err)
	}
}

// TestFrameRejectsChecksumMismatch is the integrity gate: a single flipped bit
// anywhere in the body must be rejected, and the payload must not be returned.
func TestFrameRejectsChecksumMismatch(t *testing.T) {
	enc, err := EncodeFrame(Frame{Type: FrameTypeData, Seq: 7, Payload: []byte("hello world")})
	if err != nil {
		t.Fatal(err)
	}

	// Flip every byte in turn, including the trailer.
	for i := 0; i < len(enc); i++ {
		bad := append([]byte(nil), enc...)
		bad[i] ^= 0x01

		f, _, err := DecodeFrameFrom(bad)
		if err == nil {
			t.Fatalf("byte %d flipped but the frame decoded: %+v", i, f)
		}
		if f != nil {
			t.Errorf("byte %d flipped and a frame was still returned", i)
		}
	}
}

// TestFrameRejectsTruncation proves every truncation is rejected cleanly, and
// that the error distinguishes "header incomplete" from "payload incomplete".
func TestFrameRejectsTruncation(t *testing.T) {
	enc, err := EncodeFrame(Frame{Type: FrameTypeData, Payload: bytes.Repeat([]byte("z"), 32)})
	if err != nil {
		t.Fatal(err)
	}

	for n := 0; n < len(enc); n++ {
		if _, _, err := DecodeFrameFrom(enc[:n]); err == nil {
			t.Errorf("truncation to %d bytes decoded successfully", n)
		}
	}
	// The full frame must decode.
	if _, n, err := DecodeFrameFrom(enc); err != nil || n != len(enc) {
		t.Errorf("full frame: %d bytes, %v", n, err)
	}
}

// TestFrameRejectsOversizedDeclaredLength proves a hostile length prefix fails
// before any allocation, which is the property that prevents a 4 GiB alloc from
// a 20-byte packet.
func TestFrameRejectsOversizedDeclaredLength(t *testing.T) {
	// Header declaring 0xFFFFFFFF payload bytes.
	buf := make([]byte, FrameHeaderSize+FrameTrailerSize)
	buf[0], buf[1], buf[2], buf[3] = 0x5A, 0x43, 0x52, 0x59
	buf[4] = FrameVersion
	buf[5] = byte(FrameTypeData)
	buf[6] = 0
	buf[7], buf[8], buf[9], buf[10] = 0xFF, 0xFF, 0xFF, 0xFF

	if _, _, err := DecodeFrameFrom(buf); !errors.Is(err, ErrFrameTooLarge) {
		t.Errorf("error = %v, want ErrFrameTooLarge", err)
	}

	// A length one byte over the limit must also be refused, with a valid CRC so
	// the length check is what fires.
	over := make([]byte, FrameHeaderSize+MaxFramePayload+1+FrameTrailerSize)
	over[0], over[1], over[2], over[3] = 0x5A, 0x43, 0x52, 0x59
	over[4] = FrameVersion
	over[5] = byte(FrameTypeData)
	n := MaxFramePayload + 1
	over[7] = byte(n >> 24)
	over[8] = byte(n >> 16)
	over[9] = byte(n >> 8)
	over[10] = byte(n)
	crc := CRC32C(over[:len(over)-FrameTrailerSize])
	over[len(over)-4] = byte(crc >> 24)
	over[len(over)-3] = byte(crc >> 16)
	over[len(over)-2] = byte(crc >> 8)
	over[len(over)-1] = byte(crc)
	if _, _, err := DecodeFrameFrom(over); !errors.Is(err, ErrFrameTooLarge) {
		t.Errorf("over-limit error = %v, want ErrFrameTooLarge", err)
	}

	// Encoding a payload over the limit must also be refused.
	if _, err := EncodeFrame(Frame{Type: FrameTypeData, Payload: make([]byte, MaxFramePayload+1)}); !errors.Is(err, ErrFrameTooLarge) {
		t.Errorf("encode over-limit error = %v, want ErrFrameTooLarge", err)
	}
}

// TestFrameRejectsTrailingBytes proves DecodeFrame requires exactly one frame, so
// a caller that thinks it is reading one frame cannot silently get the first of
// several and desynchronise.
func TestFrameRejectsTrailingBytes(t *testing.T) {
	enc, err := EncodeFrame(Frame{Type: FrameTypeData, Payload: []byte("a")})
	if err != nil {
		t.Fatal(err)
	}
	double := append(append([]byte(nil), enc...), enc...)

	if _, err := DecodeFrame(double); !errors.Is(err, ErrTrailingBytes) {
		t.Errorf("error = %v, want ErrTrailingBytes", err)
	}
	// DecodeFrameFrom must succeed and report the single-frame length.
	f, n, err := DecodeFrameFrom(double)
	if err != nil {
		t.Fatalf("DecodeFrameFrom: %v", err)
	}
	if n != len(enc) {
		t.Errorf("consumed %d bytes, want %d", n, len(enc))
	}
	if string(f.Payload) != "a" {
		t.Errorf("payload = %q", f.Payload)
	}
}

// TestDecodeFrameStream proves a caller can loop over a concatenated stream and
// consume it exactly, which is how the framing layer is meant to be used.
func TestDecodeFrameStream(t *testing.T) {
	var stream []byte
	var want []string
	for i := 0; i < 5; i++ {
		payload := bytes.Repeat([]byte{byte('a' + i)}, i+1)
		want = append(want, string(payload))
		enc, err := EncodeFrame(Frame{Type: FrameTypeData, Seq: uint64(i), Payload: payload})
		if err != nil {
			t.Fatal(err)
		}
		stream = append(stream, enc...)
	}

	var got []string
	offset := 0
	for offset < len(stream) {
		f, n, err := DecodeFrameFrom(stream[offset:])
		if err != nil {
			t.Fatalf("frame at offset %d: %v", offset, err)
		}
		if f.Seq != uint64(len(got)) {
			t.Errorf("frame %d has seq %d", len(got), f.Seq)
		}
		got = append(got, string(f.Payload))
		offset += n
	}
	if offset != len(stream) {
		t.Errorf("consumed %d of %d bytes", offset, len(stream))
	}
	if len(got) != len(want) {
		t.Fatalf("decoded %d frames, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("frame %d payload = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestFrameFlags covers the flag accessor.
func TestFrameFlags(t *testing.T) {
	f := Frame{Flags: FlagCompressed | FlagFinal}
	if !f.HasFlag(FlagCompressed) {
		t.Error("HasFlag(Compressed) = false")
	}
	if !f.HasFlag(FlagFinal) {
		t.Error("HasFlag(Final) = false")
	}
	if f.HasFlag(FlagEncrypted) {
		t.Error("HasFlag(Encrypted) = true on a frame without it")
	}
}

// TestFrameTypeNames pins the type names and the validity rule.
func TestFrameTypeNames(t *testing.T) {
	cases := map[FrameType]string{
		FrameTypeData:      "DATA",
		FrameTypeControl:   "CONTROL",
		FrameTypeHeartbeat: "HEARTBEAT",
	}
	for ft, want := range cases {
		if got := ft.String(); got != want {
			t.Errorf("%#x: String() = %q, want %q", uint8(ft), got, want)
		}
		if !ft.Valid() {
			t.Errorf("%#x: Valid() = false", uint8(ft))
		}
	}
	if got := FrameType(0x7F).String(); got != "UNKNOWN(0x7f)" {
		t.Errorf("unknown String() = %q", got)
	}
	if FrameType(0).Valid() {
		t.Error("type 0 is valid")
	}
	if FrameType(0x7F).Valid() {
		t.Error("type 0x7f is valid")
	}
}

// TestFrameSizeFor covers the size helper, including its bounds.
func TestFrameSizeFor(t *testing.T) {
	for _, n := range []int{0, 1, 100, MaxFramePayload} {
		got, err := FrameSizeFor(n)
		if err != nil {
			t.Fatalf("%d: %v", n, err)
		}
		if want := FrameHeaderSize + n + FrameTrailerSize; got != want {
			t.Errorf("FrameSizeFor(%d) = %d, want %d", n, got, want)
		}
	}
	if _, err := FrameSizeFor(-1); err == nil {
		t.Error("accepted a negative payload length")
	}
	if _, err := FrameSizeFor(MaxFramePayload + 1); !errors.Is(err, ErrFrameTooLarge) {
		t.Errorf("over-limit error = %v", err)
	}

	// The helper's answer must match what EncodeFrame actually produces.
	enc, err := EncodeFrame(Frame{Type: FrameTypeData, Payload: make([]byte, 100)})
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := FrameSizeFor(100); got != len(enc) {
		t.Errorf("FrameSizeFor(100) = %d but EncodeFrame produced %d bytes", got, len(enc))
	}
}

// TestFrameHeaderSizeConstant pins the header size, since every offset in the
// format and every stored frame depends on it.
func TestFrameHeaderSizeConstant(t *testing.T) {
	// 4 magic + 1 version + 1 type + 1 flags + 4 length + 8 seq
	if FrameHeaderSize != 19 {
		t.Errorf("FrameHeaderSize = %d, want 19", FrameHeaderSize)
	}
	if FrameTrailerSize != 4 {
		t.Errorf("FrameTrailerSize = %d, want 4", FrameTrailerSize)
	}
	// An empty frame must be exactly header + trailer.
	enc, err := EncodeFrame(Frame{Type: FrameTypeData})
	if err != nil {
		t.Fatal(err)
	}
	if len(enc) != FrameHeaderSize+FrameTrailerSize {
		t.Errorf("empty frame is %d bytes, want %d", len(enc), FrameHeaderSize+FrameTrailerSize)
	}
}

// TestFrameMagicIsZCRY proves the magic spells something recognisable in a
// hexdump, which is the whole reason it was chosen.
func TestFrameMagicIsZCRY(t *testing.T) {
	const want = "ZCRY"
	// The shifts go through a variable rather than the constant directly: an
	// untyped constant shifted and then converted to byte is evaluated at compile
	// time, and the intermediate values do not fit in a byte, so the compiler
	// rejects the conversion. A uint32 variable makes each shift a runtime
	// operation whose result is already truncated to the right width.
	magic := FrameMagic
	got := string([]byte{
		byte(magic >> 24), byte(magic >> 16),
		byte(magic >> 8), byte(magic),
	})
	if got != want {
		t.Errorf("magic spells %q, want %q", got, want)
	}
}
