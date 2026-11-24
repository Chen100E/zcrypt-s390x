package cipher

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestGCMNonStdIVVectors is the test for the second, distinct use of GHASH in
// GCM: deriving the pre-counter block J0 when the IV is not 96 bits.
//
// This is the gap the 96-bit-only NISTGCMVectors cannot cover. There, J0 is
// IV||0^31||1 and GHASH is used exactly once, on the AAD and ciphertext. Here,
// GHASH is used twice: once to turn the IV into J0 and again on the message, so
// a length-block or padding bug in the IV path changes the tag without changing
// anything the standard vectors look at.
func TestGCMNonStdIVVectors(t *testing.T) {
	passed, err := VerifyGCMNonStdIVVectors()
	if err != nil {
		t.Fatalf("non-96-bit-IV GCM vectors failed: %v", err)
	}
	if want := len(NISTGCMNonStdIVVectors); passed != want {
		t.Fatalf("passed = %d, want %d", passed, want)
	}
	t.Logf("%d/%d non-96-bit-IV GCM vectors bit-exact (seal + open + tag tamper)",
		passed, len(NISTGCMNonStdIVVectors))
}

// TestGCMNonStdIVVectorShape validates the vectors as data: AES-256 key, an IV
// that is deliberately not 96 bits, and a tag that is a full block.
func TestGCMNonStdIVVectorShape(t *testing.T) {
	for _, v := range NISTGCMNonStdIVVectors {
		key, err := hex.DecodeString(v.Key)
		if err != nil {
			t.Errorf("%s: bad key hex: %v", v.Name, err)
			continue
		}
		if len(key) != 32 {
			t.Errorf("%s: key is %d bytes, want 32", v.Name, len(key))
		}
		iv, err := hex.DecodeString(v.IV)
		if err != nil {
			t.Errorf("%s: bad IV hex: %v", v.Name, err)
			continue
		}
		if len(iv) == 12 {
			t.Errorf("%s: IV is 96 bits, which does not exercise the GHASH-derived J0 path", v.Name)
		}
		tag, err := hex.DecodeString(v.Tag)
		if err != nil {
			t.Errorf("%s: bad tag hex: %v", v.Name, err)
			continue
		}
		if len(tag) != 16 {
			t.Errorf("%s: tag is %d bytes, want 16", v.Name, len(tag))
		}
		ct, err := hex.DecodeString(v.Ciphertext)
		if err != nil {
			t.Errorf("%s: bad ciphertext hex: %v", v.Name, err)
			continue
		}
		pt, err := hex.DecodeString(v.Plaintext)
		if err != nil {
			t.Errorf("%s: bad plaintext hex: %v", v.Name, err)
			continue
		}
		if len(ct) != len(pt) {
			t.Errorf("%s: ciphertext is %d bytes, plaintext is %d", v.Name, len(ct), len(pt))
		}
	}
}

// TestGCMNonStdIVCoverage asserts that both IV lengths from the CAVP file are
// present: the shortest legal IV (8 bits) and the longest (1024 bits).
func TestGCMNonStdIVCoverage(t *testing.T) {
	seen := map[int]bool{}
	for _, v := range NISTGCMNonStdIVVectors {
		iv, err := hex.DecodeString(v.IV)
		if err != nil {
			continue
		}
		seen[len(iv)*8] = true
	}
	for _, bits := range []int{8, 1024} {
		if !seen[bits] {
			t.Errorf("no vector with a %d-bit IV", bits)
		}
	}
}

// TestGCMJ096Bit checks the common branch directly: J0 must be the IV with
// 0x00000001 appended.
func TestGCMJ096Bit(t *testing.T) {
	key, _ := hex.DecodeString("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
	iv, _ := hex.DecodeString("cafebabefacedbaddecaf888")
	j0, err := GCMJ0(key, iv)
	if err != nil {
		t.Fatal(err)
	}
	want := "cafebabefacedbaddecaf88800000001"
	if got := hex.EncodeToString(j0); got != want {
		t.Fatalf("J0 = %s, want %s", got, want)
	}
}

// TestGCMJ0NonStdIVIsNotIVPlusOne asserts the negative case: for a non-96-bit
// IV, J0 must NOT be the IV padded with zeros and a trailing 1. This is the
// mistake a "just pad it to 16 bytes" implementation makes, and it is invisible
// unless a vector like the 8-bit one is checked.
func TestGCMJ0NonStdIVIsNotIVPlusOne(t *testing.T) {
	key, _ := hex.DecodeString("9473c28f6e978eb15e1967b888282aa6b078d320034fe5f40f8bb68674f1ecda")
	iv, _ := hex.DecodeString("0a")
	j0, err := GCMJ0(key, iv)
	if err != nil {
		t.Fatal(err)
	}
	naive := make([]byte, 16)
	copy(naive, iv)
	naive[15] = 1
	if bytes.Equal(j0, naive) {
		t.Fatalf("J0 for an 8-bit IV equals IV||0^31||1 (%s); the GHASH derivation was skipped",
			hex.EncodeToString(j0))
	}
	// J0 must depend on H, so a different key must give a different J0 for the
	// same IV. If the IV path ignored the key, this would fail.
	other, _ := hex.DecodeString("d0c267c19f30d80b8914bbbfb72f73b8d3cd5f6a787015848a7b30e38f16f18b")
	j0Other, err := GCMJ0(other, iv)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(j0, j0Other) {
		t.Error("J0 for an 8-bit IV does not depend on the key")
	}
}

// TestGCMJ0LengthIsBits is the byte-versus-bit check. For a 16-byte IV the
// length field is 128 bits, so the GHASH input is the IV followed by 0x80; a
// byte-length implementation would put 0x10 there instead.
func TestGCMJ0LengthIsBits(t *testing.T) {
	h, _ := hex.DecodeString("acbef20579b4b8ebce889bac8732dad7")
	iv := make([]byte, 16)
	for i := range iv {
		iv[i] = byte(i)
	}

	j0, err := gcmJ0(h, iv)
	if err != nil {
		t.Fatal(err)
	}

	// Rebuild the input explicitly and hash it, so the assertion documents the
	// construction instead of just comparing two opaque values.
	input := append(append([]byte(nil), iv...), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x80)
	want := GHASHSum(h, input)
	if !bytes.Equal(j0, want) {
		t.Fatalf("J0 = %s, want %s (IV || 0^64 || [128]_64)",
			hex.EncodeToString(j0), hex.EncodeToString(want))
	}
}

// TestGCMSealWithIVMatchesStdVectors re-runs the four existing 96-bit-IV NIST
// vectors through the new arbitrary-IV seal. It is the regression guard: the
// hardware path in aes.go is unchanged, but a mistake in J0 or inc32 here would
// otherwise go unnoticed because VerifyAESGCMVectors uses crypto/cipher.
func TestGCMSealWithIVMatchesStdVectors(t *testing.T) {
	passed, err := VerifyGCMStdIVVectorsWithGCMSeal()
	if err != nil {
		t.Fatalf("96-bit-IV regression through GCMSealWithIV: %v", err)
	}
	if want := len(NISTGCMVectors); passed != want {
		t.Fatalf("passed = %d, want %d", passed, want)
	}
	t.Logf("%d/%d existing 96-bit-IV vectors still bit-exact through GCMSealWithIV", passed, len(NISTGCMVectors))
}

// TestGCMSealWithIVRejectsBadInput checks the error paths rather than letting a
// zero-length IV or a truncated sealed message panic.
func TestGCMSealWithIVRejectsBadInput(t *testing.T) {
	key := make([]byte, 32)
	if _, err := GCMSealWithIV(key, nil, nil, []byte("x")); err == nil {
		t.Error("empty IV accepted, want error")
	}
	// GCMSealWithIV takes any AES key length, so the invalid case is a length
	// that is not one of 16/24/32.
	if _, err := GCMSealWithIV(make([]byte, 17), make([]byte, 12), nil, nil); err == nil {
		t.Error("17-byte key accepted, want error")
	}
	sealed, err := GCMSealWithIV(key, make([]byte, 12), nil, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := GCMOpenWithIV(key, make([]byte, 12), nil, sealed[:8]); err == nil {
		t.Error("truncated sealed message accepted, want error")
	}
}

// TestGCMSealWithIVRoundTrip walks a spread of IV lengths, including both sides
// of the 96-bit branch and the block boundaries of the GHASH padding, and checks
// that seal then open recovers the plaintext.
func TestGCMSealWithIVRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i * 3)
	}
	aad := []byte("associated data")
	pt := []byte("the quick brown fox jumps over the lazy dog")

	for _, ivLen := range []int{1, 2, 7, 8, 11, 12, 13, 15, 16, 17, 31, 32, 33, 64, 128} {
		iv := make([]byte, ivLen)
		for i := range iv {
			iv[i] = byte(i*5 + 1)
		}
		sealed, err := GCMSealWithIV(key, iv, aad, pt)
		if err != nil {
			t.Fatalf("ivLen %d: seal: %v", ivLen, err)
		}
		if len(sealed) != len(pt)+16 {
			t.Fatalf("ivLen %d: sealed is %d bytes, want %d", ivLen, len(sealed), len(pt)+16)
		}
		back, err := GCMOpenWithIV(key, iv, aad, sealed)
		if err != nil {
			t.Fatalf("ivLen %d: open: %v", ivLen, err)
		}
		if !bytes.Equal(back, pt) {
			t.Fatalf("ivLen %d: round trip mismatch", ivLen)
		}
		// A different AAD must be rejected, which proves the AAD is actually
		// authenticated and not silently dropped.
		if _, err := GCMOpenWithIV(key, iv, []byte("wrong"), sealed); err == nil {
			t.Fatalf("ivLen %d: wrong AAD accepted", ivLen)
		}
	}
}
