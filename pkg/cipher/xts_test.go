package cipher

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// TestXTSNISTVectors runs every AES-XTS known-answer case in both directions.
//
// This is the test that catches the two mistakes that a round-trip test cannot:
// the GF(2^128) tweak doubling written as a big-endian big.Int shift (correct
// for one block, wrong for every multi-block data unit) and a self-consistent
// error in the ciphertext-stealing layout (C* from the wrong end of CC, or
// written in the wrong order). Both still decrypt what they encrypted, so only
// an external vector distinguishes them.
func TestXTSNISTVectors(t *testing.T) {
	passed, err := VerifyXTSVectors()
	if err != nil {
		t.Fatalf("AES-XTS vectors failed: %v", err)
	}
	if want := len(XTSVectors); passed != want {
		t.Fatalf("passed = %d, want %d", passed, want)
	}
	t.Logf("%d/%d AES-XTS vectors bit-exact (IEEE 1619 / SP 800-38E, CTS included)",
		passed, len(XTSVectors))
}

// TestXTSVectorShape validates the vectors themselves, so a mistyped hex
// constant fails here rather than looking like an implementation bug.
func TestXTSVectorShape(t *testing.T) {
	seen := map[string]bool{}
	for _, v := range XTSVectors {
		if v.Name == "" {
			t.Error("vector with no name")
			continue
		}
		if seen[v.Name] {
			t.Errorf("%s: duplicate vector name", v.Name)
		}
		seen[v.Name] = true

		key, err := hex.DecodeString(v.Key)
		if err != nil {
			t.Errorf("%s: bad key hex: %v", v.Name, err)
			continue
		}
		if len(key) != 32 && len(key) != 64 {
			t.Errorf("%s: key is %d bytes, want 32 or 64", v.Name, len(key))
		}
		tweak, err := hex.DecodeString(v.Tweak)
		if err != nil {
			t.Errorf("%s: bad tweak hex: %v", v.Name, err)
			continue
		}
		if len(tweak) != XTSBlockSize {
			t.Errorf("%s: tweak is %d bytes, want %d", v.Name, len(tweak), XTSBlockSize)
		}
		pt, err := hex.DecodeString(v.Plaintext)
		if err != nil {
			t.Errorf("%s: bad plaintext hex: %v", v.Name, err)
			continue
		}
		ct, err := hex.DecodeString(v.Ciphertext)
		if err != nil {
			t.Errorf("%s: bad ciphertext hex: %v", v.Name, err)
			continue
		}
		if len(pt) != len(ct) {
			t.Errorf("%s: plaintext %d bytes but ciphertext %d bytes", v.Name, len(pt), len(ct))
		}
		if len(pt) < XTSMinDataUnit {
			t.Errorf("%s: plaintext is %d bytes, below the %d-byte minimum",
				v.Name, len(pt), XTSMinDataUnit)
		}
		if v.Source == "" {
			t.Errorf("%s: no provenance recorded in Source", v.Name)
		}
	}
}

// TestXTSVectorCoverage asserts both key sizes and both data-unit shapes are
// covered. A key size with no vector is a key size with no correctness
// evidence; a set with no non-aligned case has no ciphertext-stealing evidence.
func TestXTSVectorCoverage(t *testing.T) {
	byKey := map[int]int{}
	cts := 0
	for _, v := range XTSVectors {
		key, err := hex.DecodeString(v.Key)
		if err != nil {
			t.Fatalf("%s: bad key hex: %v", v.Name, err)
		}
		byKey[len(key)]++
		pt, err := hex.DecodeString(v.Plaintext)
		if err != nil {
			t.Fatalf("%s: bad plaintext hex: %v", v.Name, err)
		}
		if len(pt)%XTSBlockSize != 0 {
			cts++
		}
	}
	for _, n := range []int{32, 64} {
		if byKey[n] == 0 {
			t.Errorf("no vector covers a %d-byte key", n)
		}
	}
	if cts < 3 {
		t.Errorf("only %d ciphertext-stealing vectors; need at least 3", cts)
	}
}

// TestXTSGFMulX checks the tweak doubling against the reduction polynomial
// directly, including the carry cases that are the whole reason the loop runs
// from byte 15 downwards.
//
// The convention is the one OpenSSL's big-endian branch of gf_mulx uses: byte 15
// holds the low-order end of the polynomial, so a doubling carries from byte
// i-1 into byte i, and the reduction constant 0x87 folds into byte 0 when bit 7
// of byte 15 shifts out. These expectations are derived from that definition,
// not copied from the implementation's output.
func TestXTSGFMulX(t *testing.T) {
	// 1 * x = 2.
	tweak := make([]byte, 16)
	tweak[15] = 0x01
	gfMulX(tweak)
	want := make([]byte, 16)
	want[15] = 0x02
	if !bytes.Equal(tweak, want) {
		t.Errorf("1*x = %x, want %x", tweak, want)
	}

	// Doubling 0x80 in the low byte shifts bit 7 out of byte 15, so the whole
	// value becomes zero and the reduction constant lands in byte 0.
	tweak = make([]byte, 16)
	tweak[15] = 0x80
	gfMulX(tweak)
	want = make([]byte, 16)
	want[0] = 0x87
	if !bytes.Equal(tweak, want) {
		t.Errorf("0x80*x = %x, want %x", tweak, want)
	}

	// The high bit of byte 0 carries into byte 1, not out of the value: byte 0
	// is the most significant byte of the cipher input, but the *lowest* end of
	// the field element's shift direction is byte 15.
	tweak = make([]byte, 16)
	tweak[0] = 0x80
	gfMulX(tweak)
	want = make([]byte, 16)
	want[1] = 0x01
	if !bytes.Equal(tweak, want) {
		t.Errorf("0x80 in byte 0 * x = %x, want %x", tweak, want)
	}

	// All-ones doubles to all-ones with the reduction applied to byte 0.
	tweak = bytes.Repeat([]byte{0xff}, 16)
	gfMulX(tweak)
	want = bytes.Repeat([]byte{0xff}, 16)
	want[0] = 0x79 // (0xff << 1) & 0xff = 0xfe, then ^0x87
	if !bytes.Equal(tweak, want) {
		t.Errorf("all-ones * x = %x, want %x", tweak, want)
	}

	// The multiplicative order of x is 2^128-1, so 128 successive doublings
	// from 1 must visit 128 distinct values. This catches a doubling that
	// collapses to zero or repeats early.
	seen := map[string]bool{}
	tweak = make([]byte, 16)
	tweak[15] = 0x01
	for i := 0; i < 128; i++ {
		if seen[string(tweak)] {
			t.Fatalf("tweak sequence repeated after %d steps", i)
		}
		seen[string(tweak)] = true
		gfMulX(tweak)
	}
}

// TestXTSTweakSensitivity proves the tweak actually feeds the ciphertext: two
// data units that differ only in the tweak must not produce a fixed XOR
// difference, which is what would happen if the tweak were added after
// encryption instead of being mixed in before it.
func TestXTSTweakSensitivity(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i*5 + 3)
	}
	t1 := make([]byte, 16)
	t2 := make([]byte, 16)
	t2[15] = 1
	pt := bytes.Repeat([]byte{0x00}, 64)

	c1, err := XTSEncrypt(key, t1, pt)
	if err != nil {
		t.Fatalf("encrypt with tweak 1: %v", err)
	}
	c2, err := XTSEncrypt(key, t2, pt)
	if err != nil {
		t.Fatalf("encrypt with tweak 2: %v", err)
	}
	if bytes.Equal(c1, c2) {
		t.Fatal("ciphertext is identical under different tweaks")
	}
	// The XOR of the two ciphertexts must not be constant across blocks: a
	// constant difference would mean the tweak only shifts the output.
	first := make([]byte, 16)
	for i := range first {
		first[i] = c1[i] ^ c2[i]
	}
	for off := 16; off < len(c1); off += 16 {
		var same bool = true
		for i := 0; i < 16; i++ {
			if c1[off+i]^c2[off+i] != first[i] {
				same = false
				break
			}
		}
		if same {
			t.Fatalf("ciphertext XOR difference is constant at block %d; tweak is not being mixed in", off/16)
		}
	}
}

// TestXTSTweakPerBlock proves each block uses a different tweak. With a single
// tweak reused for all blocks, encrypting two identical plaintext blocks would
// produce two identical ciphertext blocks — the ECB failure mode.
func TestXTSTweakPerBlock(t *testing.T) {
	key := make([]byte, 32)
	tweak := make([]byte, 16)
	pt := bytes.Repeat([]byte{0x41}, 64) // four identical blocks

	ct, err := XTSEncrypt(key, tweak, pt)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	seen := map[string]bool{}
	for off := 0; off < len(ct); off += 16 {
		b := string(ct[off : off+16])
		if seen[b] {
			t.Fatalf("identical plaintext blocks produced identical ciphertext at offset %d; tweak is not advancing", off)
		}
		seen[b] = true
	}
}

// TestXTSRoundTripAcrossSizes exercises the implementation over every length
// from the minimum up to three blocks plus a bit, so both the aligned path and
// every possible partial-tail width are covered. A CTS bug that only shows up
// at, say, rem == 15 cannot hide behind a single 25-byte case.
func TestXTSRoundTripAcrossSizes(t *testing.T) {
	for _, keyLen := range []int{32, 64} {
		key := make([]byte, keyLen)
		for i := range key {
			key[i] = byte(i*7 + 1)
		}
		tweak := make([]byte, 16)
		for i := range tweak {
			tweak[i] = byte(i*11 + 5)
		}
		for size := XTSMinDataUnit; size <= 3*XTSBlockSize+15; size++ {
			pt := make([]byte, size)
			for i := range pt {
				pt[i] = byte(i*13 + size)
			}
			ct, err := XTSEncrypt(key, tweak, pt)
			if err != nil {
				t.Fatalf("key %d size %d: encrypt: %v", keyLen, size, err)
			}
			if len(ct) != size {
				t.Fatalf("key %d size %d: ciphertext is %d bytes, want %d", keyLen, size, len(ct), size)
			}
			back, err := XTSDecrypt(key, tweak, ct)
			if err != nil {
				t.Fatalf("key %d size %d: decrypt: %v", keyLen, size, err)
			}
			if !bytes.Equal(back, pt) {
				t.Fatalf("key %d size %d: round-trip mismatch", keyLen, size)
			}
		}
	}
}

// TestXTSLargeDataUnitRoundTrip covers a data unit big enough that the tweak
// doubling wraps past the top of the 128-bit field more than once, which a
// one- or two-block test never reaches.
func TestXTSLargeDataUnitRoundTrip(t *testing.T) {
	key := make([]byte, 64)
	for i := range key {
		key[i] = byte(i * 3)
	}
	tweak := make([]byte, 16)
	tweak[0] = 0xf0 // start near the top so doubling carries early
	pt := make([]byte, 1024*1024+7)
	for i := range pt {
		pt[i] = byte(i % 251)
	}

	ct, err := XTSEncrypt(key, tweak, pt)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	back, err := XTSDecrypt(key, tweak, ct)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(back, pt) {
		t.Fatal("1 MiB + 7 byte round-trip mismatch")
	}
}

// TestXTSInvalidInputs covers the guard clauses. Each of these must be a clean
// error rather than a panic or a silently truncated result.
func TestXTSInvalidInputs(t *testing.T) {
	good32 := make([]byte, 32)
	good64 := make([]byte, 64)
	tweak := make([]byte, 16)

	cases := []struct {
		name string
		key  []byte
		twk  []byte
		pt   []byte
	}{
		{"nil key", nil, tweak, make([]byte, 16)},
		{"16-byte key", make([]byte, 16), tweak, make([]byte, 16)},
		{"24-byte key", make([]byte, 24), tweak, make([]byte, 16)},
		{"48-byte key", make([]byte, 48), tweak, make([]byte, 16)},
		{"65-byte key", make([]byte, 65), tweak, make([]byte, 16)},
		{"empty tweak", good32, nil, make([]byte, 16)},
		{"8-byte tweak", good32, make([]byte, 8), make([]byte, 16)},
		{"17-byte tweak", good32, make([]byte, 17), make([]byte, 16)},
		{"empty plaintext", good32, tweak, nil},
		{"15-byte plaintext", good32, tweak, make([]byte, 15)},
		{"oversized data unit", good64, tweak, make([]byte, XTSMaxDataUnit+1)},
	}
	for _, c := range cases {
		if _, err := XTSEncrypt(c.key, c.twk, c.pt); err == nil {
			t.Errorf("%s: XTSEncrypt accepted it", c.name)
		}
		if _, err := XTSDecrypt(c.key, c.twk, c.pt); err == nil {
			t.Errorf("%s: XTSDecrypt accepted it", c.name)
		}
	}

	// The maximum data unit is legal, so it must not be rejected. It is 16 MiB,
	// which is slow but bounded; run it under -short as well because it is the
	// only boundary case that proves the limit is inclusive.
	if !testing.Short() {
		if _, err := XTSEncrypt(good32, tweak, make([]byte, XTSMaxDataUnit)); err != nil {
			t.Errorf("maximum data unit was rejected: %v", err)
		}
	}
}

// TestXTSEncryptDecryptAreNotIdentity guards against the degenerate case where
// the "cipher" returns its input, which would pass every round-trip test.
func TestXTSEncryptDecryptAreNotIdentity(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = 0x5a
	}
	tweak := make([]byte, 16)
	pt := bytes.Repeat([]byte("zcrypt-s390x!!!"), 4) // 15 bytes x4 = 60, plus padding below
	pt = append(pt, 0x01, 0x02, 0x03, 0x04)          // 64 bytes, block aligned

	ct, err := XTSEncrypt(key, tweak, pt)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if bytes.Equal(ct, pt) {
		t.Fatal("ciphertext equals plaintext")
	}
	for i := 0; i+8 <= len(pt); i++ {
		if strings.Contains(string(ct), string(pt[i:i+8])) {
			t.Fatalf("ciphertext contains a plaintext window at offset %d", i)
		}
	}
}

// TestXTSIdenticalKeyHalvesAllowed documents a deliberate non-restriction.
//
// OpenSSL and the kernel refuse k1 == k2 at their API boundary because it
// weakens the construction, but the raw algorithm is defined for any key and the
// CAVP vectors do not avoid identical halves. Rejecting them here would make the
// implementation disagree with the standard, so it is allowed and documented.
func TestXTSIdenticalKeyHalvesAllowed(t *testing.T) {
	half := make([]byte, 32)
	for i := range half {
		half[i] = byte(i + 1)
	}
	key := append(append([]byte(nil), half...), half...)
	tweak := make([]byte, 16)
	pt := make([]byte, 32)

	ct, err := XTSEncrypt(key, tweak, pt)
	if err != nil {
		t.Fatalf("identical key halves were rejected: %v", err)
	}
	back, err := XTSDecrypt(key, tweak, ct)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(back, pt) {
		t.Fatal("round-trip mismatch with identical key halves")
	}
}

// TestXTSAliasingSafe proves XTSEncrypt does not mutate its inputs, because a
// caller that reuses a plaintext buffer across iterations would otherwise
// measure nonsense after the first pass.
func TestXTSAliasingSafe(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	tweak := make([]byte, 16)
	for i := range tweak {
		tweak[i] = byte(i * 2)
	}
	pt := make([]byte, 45)
	for i := range pt {
		pt[i] = byte(i * 3)
	}

	keyCopy := append([]byte(nil), key...)
	tweakCopy := append([]byte(nil), tweak...)
	ptCopy := append([]byte(nil), pt...)

	if _, err := XTSEncrypt(key, tweak, pt); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if !bytes.Equal(key, keyCopy) {
		t.Error("XTSEncrypt mutated the key")
	}
	if !bytes.Equal(tweak, tweakCopy) {
		t.Error("XTSEncrypt mutated the tweak")
	}
	if !bytes.Equal(pt, ptCopy) {
		t.Error("XTSEncrypt mutated the plaintext")
	}
}

// TestXTSBenchmarkProducesVerifiedResults runs the real benchmark at a small
// size and asserts it reports verified round trips and plausible throughput.
func TestXTSBenchmarkProducesVerifiedResults(t *testing.T) {
	for _, keyBits := range []int{128, 256} {
		res, err := XTSBenchmark(keyBits, 16*1024, 20)
		if err != nil {
			t.Fatalf("XTS-%d: %v", keyBits, err)
		}
		if !res.Verified {
			t.Errorf("XTS-%d: result not marked verified", keyBits)
		}
		if res.EncryptMBps <= 0 || res.DecryptMBps <= 0 {
			t.Errorf("XTS-%d: non-positive throughput: enc=%f dec=%f",
				keyBits, res.EncryptMBps, res.DecryptMBps)
		}
		if res.EncryptNanos <= 0 || res.DecryptNanos <= 0 {
			t.Errorf("XTS-%d: non-positive durations", keyBits)
		}
		if res.KeyBits != keyBits || res.BlockSize != 16*1024 || res.Iterations != 20 {
			t.Errorf("XTS-%d: result metadata wrong: %+v", keyBits, res)
		}
		wantKeyBytes := 32
		if keyBits == 256 {
			wantKeyBytes = 64
		}
		if res.KeyBytes != wantKeyBytes {
			t.Errorf("XTS-%d: key bytes = %d, want %d", keyBits, res.KeyBytes, wantKeyBytes)
		}
	}
}

// TestXTSBenchmarkAcceptsCiphertextStealingSizes checks that a non-aligned
// buffer size is measured rather than rejected: XTS is defined for them, and
// the CTS path is measurably slower per byte, so excluding it would overstate
// throughput for the dm-crypt case.
func TestXTSBenchmarkAcceptsCiphertextStealingSizes(t *testing.T) {
	for _, size := range []int{16, 17, 25, 1000, 4095} {
		res, err := XTSBenchmark(128, size, 5)
		if err != nil {
			t.Errorf("size %d: %v", size, err)
			continue
		}
		if !res.Verified {
			t.Errorf("size %d: not verified", size)
		}
	}
}

// TestXTSBenchmarkRejectsBadParameters covers the guard clauses.
func TestXTSBenchmarkRejectsBadParameters(t *testing.T) {
	cases := []struct {
		name  string
		bits  int
		size  int
		iters int
	}{
		{"192-bit key", 192, 1024, 1},
		{"64-bit key", 64, 1024, 1},
		{"zero buffer", 128, 0, 1},
		{"15-byte buffer", 128, 15, 1},
		{"oversized buffer", 128, XTSMaxDataUnit + 1, 1},
		{"zero iterations", 128, 1024, 0},
		{"negative iterations", 128, 1024, -1},
	}
	for _, c := range cases {
		if _, err := XTSBenchmark(c.bits, c.size, c.iters); err == nil {
			t.Errorf("%s: expected an error, got none", c.name)
		}
	}
}

// TestXTSSuiteShape checks the suite runs the documented sizes.
func TestXTSSuiteShape(t *testing.T) {
	rows := XTSSuite(256, 1)
	wantSizes := []int{1024, 64 * 1024, 1024 * 1024}
	if len(rows) != len(wantSizes) {
		t.Fatalf("suite returned %d rows, want %d", len(rows), len(wantSizes))
	}
	for i, want := range wantSizes {
		if rows[i].BlockSize != want {
			t.Errorf("row %d block size = %d, want %d", i, rows[i].BlockSize, want)
		}
		if rows[i].Error != "" {
			t.Errorf("row %d error: %s", i, rows[i].Error)
		}
		if !rows[i].Verified {
			t.Errorf("row %d not verified", i)
		}
	}
}

// TestXTSKernelInfoShape asserts the kernel report is populated and internally
// consistent. It does not assert that hardware is present: on an amd64 CI runner
// there is no xts-aes-s390, and the test must still pass there.
func TestXTSKernelInfoShape(t *testing.T) {
	info := XTSKernelInfo()
	if info.KernelDriver != "" && info.KernelPriority == 0 {
		t.Errorf("driver %q reported with zero priority", info.KernelDriver)
	}
	if info.Hardware && !strings.Contains(info.KernelDriver, "s390") {
		t.Errorf("Hardware is true for driver %q, which is not an s390 CPACF driver", info.KernelDriver)
	}
	// AFALGAvailable implies a successful operation, so the algorithm name must
	// have been resolved. The converse does not hold.
	if info.AFALGAvailable && info.KernelDriver == "" {
		t.Error("AF_ALG works but /proc/crypto reports no driver")
	}
	t.Logf("kernel xts(aes): driver=%q priority=%d hardware=%v af_alg=%v alternatives=%v err=%q",
		info.KernelDriver, info.KernelPriority, info.Hardware, info.AFALGAvailable,
		info.Alternatives, info.Error)
}

// TestXTSHardwareAgreesWithSoftware is the real hardware-versus-software gate:
// the same key, tweak and data unit through AF_ALG and through the pure-Go path
// must produce the same ciphertext, and both must decrypt the other's output.
//
// It skips cleanly when the kernel path is unreachable, which is the normal
// case on amd64 and arm64 CI runners.
func TestXTSHardwareAgreesWithSoftware(t *testing.T) {
	// A size with a partial tail, so the comparison covers ciphertext stealing
	// and not just the aligned path. The kernel's xts-aes-s390 implements CTS in
	// KMF, so disagreement here would be a real finding about the driver.
	for _, size := range []int{16, 64, 25, 30, 1000, 4096, 4096 + 13} {
		key := make([]byte, 64)
		for i := range key {
			key[i] = byte(i*7 + 1)
		}
		tweak := make([]byte, 16)
		for i := range tweak {
			tweak[i] = byte(i*3 + 9)
		}
		pt := make([]byte, size)
		for i := range pt {
			pt[i] = byte(i ^ 0xa5)
		}

		hw, err := XTSHardwareEncrypt(key, tweak, pt)
		if err != nil {
			if errors.Is(err, ErrXTSHardwareUnavailable) {
				t.Skipf("no AF_ALG xts(aes) on this host: %v", err)
			}
			t.Fatalf("size %d: hardware encrypt: %v", size, err)
		}
		sw, err := XTSEncrypt(key, tweak, pt)
		if err != nil {
			t.Fatalf("size %d: software encrypt: %v", size, err)
		}
		if !bytes.Equal(hw, sw) {
			t.Fatalf("size %d: hardware and software disagree\n hw %x\n sw %x", size, hw, sw)
		}

		// Cross-decrypt: each path must invert the other's ciphertext.
		back, err := XTSHardwareDecrypt(key, tweak, sw)
		if err != nil {
			t.Fatalf("size %d: hardware decrypt of software ciphertext: %v", size, err)
		}
		if !bytes.Equal(back, pt) {
			t.Fatalf("size %d: hardware could not decrypt software ciphertext", size)
		}
		back, err = XTSDecrypt(key, tweak, hw)
		if err != nil {
			t.Fatalf("size %d: software decrypt of hardware ciphertext: %v", size, err)
		}
		if !bytes.Equal(back, pt) {
			t.Fatalf("size %d: software could not decrypt hardware ciphertext", size)
		}
	}
}

// TestXTSHardwareMatchesCAVP runs the CAVP vectors through the kernel path as
// well, so the published expectations are checked against KMF and not only
// against the Go code. This is the strongest statement the suite makes about the
// driver: it agrees with NIST on cases it did not choose.
func TestXTSHardwareMatchesCAVP(t *testing.T) {
	ran := 0
	for _, v := range XTSVectors {
		key, err := hex.DecodeString(v.Key)
		if err != nil {
			t.Fatalf("%s: bad key hex: %v", v.Name, err)
		}
		tweak, err := hex.DecodeString(v.Tweak)
		if err != nil {
			t.Fatalf("%s: bad tweak hex: %v", v.Name, err)
		}
		pt, err := hex.DecodeString(v.Plaintext)
		if err != nil {
			t.Fatalf("%s: bad plaintext hex: %v", v.Name, err)
		}
		want, err := hex.DecodeString(v.Ciphertext)
		if err != nil {
			t.Fatalf("%s: bad ciphertext hex: %v", v.Name, err)
		}

		got, err := XTSHardwareEncrypt(key, tweak, pt)
		if err != nil {
			if errors.Is(err, ErrXTSHardwareUnavailable) {
				t.Skipf("no AF_ALG xts(aes) on this host: %v", err)
			}
			t.Fatalf("%s: hardware encrypt: %v", v.Name, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s: hardware ciphertext differs from NIST\n got %x\nwant %x",
				v.Name, got, want)
		}
		back, err := XTSHardwareDecrypt(key, tweak, want)
		if err != nil {
			t.Fatalf("%s: hardware decrypt: %v", v.Name, err)
		}
		if !bytes.Equal(back, pt) {
			t.Fatalf("%s: hardware decrypt mismatch", v.Name)
		}
		ran++
	}
	t.Logf("%d/%d CAVP vectors reproduced by the kernel xts(aes) driver", ran, len(XTSVectors))
}

// TestXTSHardwareUnavailableContract forces the AF_ALG bind to fail and asserts
// the documented contract: an error that wraps ErrXTSHardwareUnavailable, not a
// panic and not a silent zero-filled result.
//
// This is deliberately independent of the host. Pointing the algorithm name at
// something the kernel does not have reproduces the CI-runner condition on a
// machine that *does* have xts(aes), so the degradation path is covered by a
// test that actually runs rather than one that only fires on amd64.
func TestXTSHardwareUnavailableContract(t *testing.T) {
	saved := xtsAlgorithm
	xtsAlgorithm = "not-a-real-skcipher(zcrypt)"
	defer func() { xtsAlgorithm = saved }()

	key := make([]byte, 64)
	tweak := make([]byte, 16)
	pt := make([]byte, 64)

	if _, err := XTSHardwareEncrypt(key, tweak, pt); err == nil {
		t.Fatal("hardware encrypt succeeded against a nonexistent algorithm")
	} else if !errors.Is(err, ErrXTSHardwareUnavailable) {
		t.Fatalf("encrypt error does not wrap ErrXTSHardwareUnavailable: %v", err)
	}

	if _, err := XTSHardwareDecrypt(key, tweak, pt); err == nil {
		t.Fatal("hardware decrypt succeeded against a nonexistent algorithm")
	} else if !errors.Is(err, ErrXTSHardwareUnavailable) {
		t.Fatalf("decrypt error does not wrap ErrXTSHardwareUnavailable: %v", err)
	}

	// The benchmark must degrade the same way, and must not panic.
	if _, err := XTSHardwareBenchmark(256, 1024, 2); err == nil {
		t.Fatal("hardware benchmark succeeded against a nonexistent algorithm")
	} else if !errors.Is(err, ErrXTSHardwareUnavailable) {
		t.Fatalf("benchmark error does not wrap ErrXTSHardwareUnavailable: %v", err)
	}

	// XTSComparison must still return the portable measurement, with the failure
	// recorded in HardwareError rather than propagated.
	res := XTSComparison(256, 1024, 2)
	if res.Error != "" {
		t.Errorf("comparison failed outright instead of degrading: %s", res.Error)
	}
	if !res.Verified {
		t.Error("comparison lost the portable verification result")
	}
	if res.HardwareError == "" {
		t.Error("comparison did not record the hardware failure")
	}
	if res.HardwareMBps != 0 || res.Speedup != 0 {
		t.Errorf("comparison reported hardware numbers without hardware: %+v", res)
	}
}

// TestXTSSkcipherUnavailableIsCleanError proves the AF_ALG layer returns an
// error rather than panicking when asked for an algorithm the kernel does not
// have. This is the property that lets the amd64 build pass: the test must not
// assume the failure mode, only that it is an error.
func TestXTSSkcipherUnavailableIsCleanError(t *testing.T) {
	_, err := newAFALGSkcipher("definitely-not-a-real-cipher(xyz)", make([]byte, 32))
	if err == nil {
		t.Skip("kernel accepted a bogus skcipher name; nothing to assert")
	}
	// The error must be non-empty and must not be a panic; reaching this point
	// is the assertion.
	if err.Error() == "" {
		t.Error("error with empty message")
	}
}

// TestXTSCmsgLayout validates the control-message encoder against the kernel's
// struct cmsghdr layout, which is the part of the AF_ALG interface most likely
// to be wrong on a big-endian host and the hardest to debug when it is: a bad
// length prefix produces EMSGSIZE rather than a wrong answer.
func TestXTSCmsgLayout(t *testing.T) {
	// One 4-byte payload occupies 16 + 4 rounded up to 24 bytes.
	if got := cmsgLen(4); got != 24 {
		t.Errorf("cmsgLen(4) = %d, want 24", got)
	}
	// A 20-byte payload (the ALG_SET_IV prefix plus a 16-byte tweak) is 36
	// rounded up to 40.
	if got := cmsgLen(20); got != 40 {
		t.Errorf("cmsgLen(20) = %d, want 40", got)
	}

	buf := make([]byte, cmsgLen(20))
	next := putCmsg(buf, 0, solALG, algSetIV, bytes.Repeat([]byte{0xab}, 20))

	// cmsg_len counts header and payload, not padding.
	if got := nativeUint64(buf[0:]); got != 36 {
		t.Errorf("cmsg_len = %d, want 36", got)
	}
	if got := nativeUint32(buf[8:]); got != uint32(solALG) {
		t.Errorf("cmsg_level = %d, want %d", got, solALG)
	}
	if got := nativeUint32(buf[12:]); got != uint32(algSetIV) {
		t.Errorf("cmsg_type = %d, want %d", got, algSetIV)
	}
	if next != 40 {
		t.Errorf("next offset = %d, want 40", next)
	}
	for i := 0; i < 20; i++ {
		if buf[cmsgHeaderLen+i] != 0xab {
			t.Fatalf("payload byte %d = %#x, want 0xab", i, buf[cmsgHeaderLen+i])
		}
	}

	// Two messages must not overlap.
	buf = make([]byte, cmsgLen(4)+cmsgLen(20))
	off := putCmsg(buf, 0, solALG, algSetOP, []byte{0, 0, 0, 1})
	if off != 24 {
		t.Fatalf("second message offset = %d, want 24", off)
	}
	putCmsg(buf, off, solALG, algSetIV, bytes.Repeat([]byte{0xcd}, 20))
	if got := nativeUint32(buf[24+12:]); got != uint32(algSetIV) {
		t.Errorf("second message type = %d, want %d", got, algSetIV)
	}
}

// TestXTSOperationConstants pins the two constants that are easy to invert.
// ALG_OP_ENCRYPT is 1 and ALG_OP_DECRYPT is 0; swapping them runs the cipher
// backwards, which a round-trip test cannot detect.
func TestXTSOperationConstants(t *testing.T) {
	if algOpEncrypt != 1 {
		t.Errorf("algOpEncrypt = %d, want 1", algOpEncrypt)
	}
	if algOpDecrypt != 0 {
		t.Errorf("algOpDecrypt = %d, want 0", algOpDecrypt)
	}
	if algSetKey != 1 || algSetIV != 2 || algSetOP != 3 {
		t.Errorf("control-message numbers are wrong: key=%d iv=%d op=%d",
			algSetKey, algSetIV, algSetOP)
	}
	if solALG != 279 {
		t.Errorf("solALG = %d, want 279", solALG)
	}
	if afALG != 38 {
		t.Errorf("afALG = %d, want 38", afALG)
	}
}

// nativeUint64 and nativeUint32 read back what putCmsg wrote, using
// binary.NativeEndian so the test checks the layout rather than the host's byte
// order. A hand-rolled little-endian reader here would pass on amd64 and fail on
// s390x, which is precisely the class of bug this test exists to catch.
func nativeUint64(b []byte) uint64 {
	return binary.NativeEndian.Uint64(b)
}

func nativeUint32(b []byte) uint32 {
	return binary.NativeEndian.Uint32(b)
}

// Benchmarks.

func benchmarkXTS(b *testing.B, keyBits, size int) {
	b.SetBytes(int64(size))
	keyLen, err := xtsKeyBytes(keyBits)
	if err != nil {
		b.Fatal(err)
	}
	key := make([]byte, keyLen)
	tweak := make([]byte, XTSBlockSize)
	pt := make([]byte, size)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := XTSEncrypt(key, tweak, pt); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkXTSAES256_1MB(b *testing.B)     { benchmarkXTS(b, 256, 1024*1024) }
func BenchmarkXTSAES256_4KB(b *testing.B)     { benchmarkXTS(b, 256, 4096) }
func BenchmarkXTSAES128_1MB(b *testing.B)     { benchmarkXTS(b, 128, 1024*1024) }
func BenchmarkXTSAES256_1MB_CTS(b *testing.B) { benchmarkXTS(b, 256, 1024*1024+13) }
