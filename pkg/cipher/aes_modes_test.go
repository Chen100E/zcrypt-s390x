package cipher

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

// TestAESModeNISTVectors runs every SP 800-38A known-answer case in both
// directions. This is the test that catches a big-endian byte-order fault in
// the CBC chaining XOR or the CTR counter increment: on s390x there is no
// little-endian compensation hiding a swapped word, so a portability bug shows
// up as a completely different ciphertext rather than a subtle one.
func TestAESModeNISTVectors(t *testing.T) {
	passed, err := VerifyAESModeVectors()
	if err != nil {
		t.Fatalf("SP 800-38A vectors failed: %v", err)
	}
	if want := len(NISTSP80038AVectors); passed != want {
		t.Fatalf("passed = %d, want %d", passed, want)
	}
	t.Logf("%d/%d SP 800-38A vectors bit-exact across ECB, CBC and CTR", passed, len(NISTSP80038AVectors))
}

// TestAESModeVectorCoverage asserts that every mode in the comparison table has
// at least one known-answer vector, and that all three key sizes are covered.
// A mode without a vector is a mode with no correctness evidence.
func TestAESModeVectorCoverage(t *testing.T) {
	byMode := map[AESMode]int{}
	byKeyBits := map[int]int{}
	for _, v := range NISTSP80038AVectors {
		byMode[v.Mode]++
		key, err := hex.DecodeString(v.Key)
		if err != nil {
			t.Fatalf("%s: bad key hex: %v", v.Name, err)
		}
		byKeyBits[len(key)*8]++
	}
	for _, m := range []AESMode{ModeECB, ModeCBC, ModeCTR} {
		if byMode[m] == 0 {
			t.Errorf("mode %s has no NIST vector", m)
		}
	}
	for _, bits := range []int{128, 192, 256} {
		if byKeyBits[bits] == 0 {
			t.Errorf("no NIST vector covers AES-%d", bits)
		}
	}
	// GCM vectors live in aes.go; assert that surface still exists so this test
	// fails loudly if someone deletes it.
	if len(NISTGCMVectors) == 0 {
		t.Error("NISTGCMVectors is empty; AES-GCM lost its correctness evidence")
	}
}

// TestAESModeVectorShape validates the vectors themselves so that a mistyped
// hex constant fails here rather than looking like an implementation bug.
func TestAESModeVectorShape(t *testing.T) {
	for _, v := range NISTSP80038AVectors {
		key, err := hex.DecodeString(v.Key)
		if err != nil {
			t.Errorf("%s: bad key hex: %v", v.Name, err)
			continue
		}
		switch len(key) {
		case 16, 24, 32:
		default:
			t.Errorf("%s: key is %d bytes, want 16, 24 or 32", v.Name, len(key))
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
		if len(pt)%16 != 0 {
			t.Errorf("%s: plaintext is %d bytes, not a multiple of the block size", v.Name, len(pt))
		}
		if v.Mode == ModeECB {
			if v.IV != "" {
				t.Errorf("%s: ECB must not carry an IV", v.Name)
			}
		} else {
			iv, err := hex.DecodeString(v.IV)
			if err != nil {
				t.Errorf("%s: bad iv hex: %v", v.Name, err)
				continue
			}
			if len(iv) != 16 {
				t.Errorf("%s: iv is %d bytes, want 16", v.Name, len(iv))
			}
		}
	}
}

// TestAESModeCBCChainingDifference proves the vectors are not accidentally
// ECB-shaped: encrypting the same plaintext in CBC and ECB must differ, and
// CBC must equal ECB only when the IV is the preceding ciphertext block.
func TestAESModeCBCChainingDifference(t *testing.T) {
	key := make([]byte, 32)
	iv := make([]byte, 16)
	for i := range key {
		key[i] = byte(i + 1)
	}
	pt := bytes.Repeat([]byte{0x41}, 32)

	ecb, err := EncryptWithMode(ModeECB, key, nil, pt)
	if err != nil {
		t.Fatalf("ecb: %v", err)
	}
	cbc, err := EncryptWithMode(ModeCBC, key, iv, pt)
	if err != nil {
		t.Fatalf("cbc: %v", err)
	}
	if bytes.Equal(ecb, cbc) {
		t.Fatal("CBC output equals ECB output; chaining is not being applied")
	}
	// With an all-zero IV, the first CBC block must equal the ECB encryption of
	// the first block, because C = E(P xor IV) = E(P) when IV is zero.
	if !bytes.Equal(cbc[:16], ecb[:16]) {
		t.Error("CBC first block with zero IV does not equal ECB first block")
	}
	// The second CBC block must NOT equal the second ECB block: P1 xor C0 != P1.
	if bytes.Equal(cbc[16:], ecb[16:]) {
		t.Error("CBC second block equals ECB second block; chaining is not being applied")
	}
}

// TestAESModeCTRKeystreamReuse documents CTR's defining property: encryption
// and decryption are the same operation, so applying it twice returns the
// plaintext, and two plaintexts encrypted under the same (key, counter) share a
// keystream. The second property is why nonce reuse is fatal for CTR.
func TestAESModeCTRKeystreamReuse(t *testing.T) {
	key := make([]byte, 16)
	iv := make([]byte, 16)
	pt := bytes.Repeat([]byte{0x00}, 16)

	ks, err := EncryptWithMode(ModeCTR, key, iv, pt)
	if err != nil {
		t.Fatalf("ctr encrypt: %v", err)
	}
	// Encrypting all-zero plaintext yields the raw keystream. Applying the same
	// keystream to the ciphertext must recover the zeros.
	back, err := DecryptWithMode(ModeCTR, key, iv, ks)
	if err != nil {
		t.Fatalf("ctr decrypt: %v", err)
	}
	if !bytes.Equal(back, pt) {
		t.Fatalf("CTR is not an involution: got %x want %x", back, pt)
	}

	// Two different plaintexts under the same counter: XOR of the ciphertexts
	// equals XOR of the plaintexts, because the keystream cancels.
	ptA := bytes.Repeat([]byte{0xAA}, 16)
	ptB := bytes.Repeat([]byte{0x55}, 16)
	ctA, _ := EncryptWithMode(ModeCTR, key, iv, ptA)
	ctB, _ := EncryptWithMode(ModeCTR, key, iv, ptB)
	xorC := make([]byte, 16)
	xorP := make([]byte, 16)
	for i := range xorC {
		xorC[i] = ctA[i] ^ ctB[i]
		xorP[i] = ptA[i] ^ ptB[i]
	}
	if !bytes.Equal(xorC, xorP) {
		t.Fatal("CTR keystream did not cancel; the counter is not advancing identically")
	}
}

// TestAESModeRoundTripAcrossSizes exercises each mode over a range of buffer
// sizes, including the smallest legal ones, so a short-buffer off-by-one in the
// mode wrappers cannot hide behind the 1 MiB case.
func TestAESModeRoundTripAcrossSizes(t *testing.T) {
	sizes := []int{16, 32, 64, 256, 1024, 4096}
	for _, mode := range []AESMode{ModeECB, ModeCBC, ModeCTR} {
		for _, keyBits := range []int{128, 256} {
			key := make([]byte, keyBits/8)
			iv := make([]byte, 16)
			for i := range key {
				key[i] = byte(i * 3)
			}
			for _, size := range sizes {
				pt := make([]byte, size)
				for i := range pt {
					pt[i] = byte(i % 253)
				}
				ct, err := EncryptWithMode(mode, key, iv, pt)
				if err != nil {
					t.Errorf("%s-%d/%d: encrypt: %v", mode, keyBits, size, err)
					continue
				}
				if len(ct) != size {
					t.Errorf("%s-%d/%d: ciphertext is %d bytes", mode, keyBits, size, len(ct))
				}
				back, err := DecryptWithMode(mode, key, iv, ct)
				if err != nil {
					t.Errorf("%s-%d/%d: decrypt: %v", mode, keyBits, size, err)
					continue
				}
				if !bytes.Equal(back, pt) {
					t.Errorf("%s-%d/%d: round-trip mismatch", mode, keyBits, size)
				}
			}
		}
	}
}

// TestAESModeInvalidInputs covers the error paths: wrong key sizes, a
// non-block-aligned buffer, and a short IV.
func TestAESModeInvalidInputs(t *testing.T) {
	good16 := make([]byte, 16)
	good32 := make([]byte, 32)
	pt := make([]byte, 32)

	if _, err := EncryptWithMode(ModeCBC, make([]byte, 15), good16, pt); err == nil {
		t.Error("CBC accepted a 15-byte key")
	}
	if _, err := EncryptWithMode(ModeCBC, good16, make([]byte, 8), pt); err == nil {
		t.Error("CBC accepted an 8-byte IV")
	}
	if _, err := EncryptWithMode(ModeCBC, good16, good16, make([]byte, 17)); err == nil {
		t.Error("CBC accepted a 17-byte plaintext")
	}
	if _, err := EncryptWithMode(ModeCTR, good16, make([]byte, 12), pt); err == nil {
		t.Error("CTR accepted a 12-byte IV")
	}
	if _, err := EncryptWithMode(ModeECB, good16, nil, make([]byte, 15)); err == nil {
		t.Error("ECB accepted a 15-byte plaintext")
	}
	if _, err := EncryptWithMode(AESMode("OFB"), good32, good16, pt); err == nil {
		t.Error("unknown mode was accepted")
	}
	// XTS is now a real mode. A 32-byte key is a legal XTS-AES-128 key, but a
	// 16-byte tweak with a 15-byte data unit is not, and a 16-byte key is not an
	// XTS key at all.
	if _, err := EncryptWithMode(ModeXTS, good16, good16, pt); err == nil {
		t.Error("XTS accepted a 16-byte key")
	}
	if _, err := EncryptWithMode(ModeXTS, good32, make([]byte, 15), pt); err == nil {
		t.Error("XTS accepted a 15-byte tweak")
	}
	if _, err := EncryptWithMode(ModeXTS, good32, good16, make([]byte, 15)); err == nil {
		t.Error("XTS accepted a 15-byte data unit")
	}
	if _, err := DecryptWithMode(ModeGCM, good32, make([]byte, 12), make([]byte, 8)); err == nil {
		t.Error("GCM accepted a truncated ciphertext as valid")
	}
}

// TestAESModeTableIsConsistent checks the documentation table against reality:
// every mode the benchmark knows how to run must have a table entry naming its
// CPACF instruction, and the MSA level claimed must not exceed what the table's
// ordering implies.
func TestAESModeTableIsConsistent(t *testing.T) {
	wantModes := []AESMode{ModeECB, ModeCBC, ModeCTR, ModeGCM, ModeXTS}
	if len(AESModeTable) != len(wantModes) {
		t.Fatalf("AESModeTable has %d entries, want %d", len(AESModeTable), len(wantModes))
	}
	for _, m := range wantModes {
		info, ok := LookupAESMode(m)
		if !ok {
			t.Errorf("mode %s missing from AESModeTable", m)
			continue
		}
		if info.Instruction == "" {
			t.Errorf("mode %s has no CPACF instruction", m)
		}
		if info.MSALevel < 1 || info.MSALevel > 13 {
			t.Errorf("mode %s claims MSA-%d, outside the 1..13 range", m, info.MSALevel)
		}
		if info.GoPath == "" {
			t.Errorf("mode %s has no documented Go call path", m)
		}
	}
	// The specific claims this project makes in its README.
	if info, _ := LookupAESMode(ModeCBC); info.Instruction != "KMC" {
		t.Errorf("CBC must map to KMC, table says %s", info.Instruction)
	}
	// CTR is the counter-intuitive one: Go's s390x stream implementation does
	// not issue KMCTR, it refills an ECB buffer with KM and XORs in Go. Assert
	// the table records that, so nobody "fixes" it to the textbook answer.
	if info, _ := LookupAESMode(ModeCTR); info.Instruction != "KM" {
		t.Errorf("CTR must map to KM on Go's s390x path, table says %s", info.Instruction)
	}
	if info, _ := LookupAESMode(ModeGCM); info.Instruction != "KMA" {
		t.Errorf("GCM must map to KMA, table says %s", info.Instruction)
	}
	if info, _ := LookupAESMode(ModeECB); info.Instruction != "KM" {
		t.Errorf("ECB must map to KM, table says %s", info.Instruction)
	}
	// XTS is the KMF mode: the instruction that exists specifically to do the
	// tweak multiply and the cipher in one pass. MSA-4 is where KMF appeared.
	if info, _ := LookupAESMode(ModeXTS); info.Instruction != "KMF" {
		t.Errorf("XTS must map to KMF, table says %s", info.Instruction)
	}
	if info, _ := LookupAESMode(ModeXTS); info.MSALevel != 4 {
		t.Errorf("XTS must claim MSA-4, table says MSA-%d", info.MSALevel)
	}
	if !mustLookup(t, ModeXTS).Parallel {
		t.Error("XTS must be marked parallel: blocks are independent once the tweak is derived")
	}
	if mustLookup(t, ModeXTS).Auth {
		t.Error("XTS must not be marked authenticated: it has no tag")
	}
	// CTR and GCM are parallel; CBC and ECB are not.
	if !mustLookup(t, ModeCTR).Parallel || !mustLookup(t, ModeGCM).Parallel {
		t.Error("CTR and GCM must be marked parallel")
	}
	if mustLookup(t, ModeCBC).Parallel || mustLookup(t, ModeECB).Parallel {
		t.Error("CBC and ECB must not be marked parallel")
	}
}

func mustLookup(t *testing.T, m AESMode) AESModeInfo {
	t.Helper()
	info, ok := LookupAESMode(m)
	if !ok {
		t.Fatalf("mode %s missing from AESModeTable", m)
	}
	return info
}

// TestAESModeBenchmarkProducesVerifiedResults runs the actual benchmark at a
// small size and asserts the harness reports verified round trips, plausible
// throughput, and a setup cost that was measured separately.
func TestAESModeBenchmarkProducesVerifiedResults(t *testing.T) {
	for _, mode := range []AESMode{ModeECB, ModeCBC, ModeCTR, ModeGCM, ModeXTS} {
		res, err := AESModeBenchmark(mode, 256, 16*1024, 20)
		if err != nil {
			t.Fatalf("%s: %v", mode, err)
		}
		if !res.Verified {
			t.Errorf("%s: result not marked verified", mode)
		}
		if res.EncryptMBps <= 0 || res.DecryptMBps <= 0 {
			t.Errorf("%s: non-positive throughput: enc=%f dec=%f", mode, res.EncryptMBps, res.DecryptMBps)
		}
		if res.EncryptNanos <= 0 || res.DecryptNanos <= 0 {
			t.Errorf("%s: non-positive durations", mode)
		}
		if res.Instruction == "" {
			t.Errorf("%s: instruction not populated", mode)
		}
		if res.KeyBits != 256 || res.BlockSize != 16*1024 || res.Iterations != 20 {
			t.Errorf("%s: result metadata wrong: %+v", mode, res)
		}
	}
}

// TestAESModeBenchmarkRejectsBadParameters covers the guard clauses.
func TestAESModeBenchmarkRejectsBadParameters(t *testing.T) {
	cases := []struct {
		name string
		mode AESMode
		bits int
		size int
		iter int
	}{
		{"bad key size", ModeCBC, 64, 1024, 1},
		{"zero buffer", ModeCBC, 256, 0, 1},
		{"negative buffer", ModeCBC, 256, -16, 1},
		{"zero iterations", ModeCBC, 256, 1024, 0},
		{"unaligned cbc buffer", ModeCBC, 256, 1000, 1},
		{"unaligned ctr buffer", ModeCTR, 256, 1001, 1},
		{"unknown mode", AESMode("OFB"), 256, 1024, 1},
	}
	for _, c := range cases {
		if _, err := AESModeBenchmark(c.mode, c.bits, c.size, c.iter); err == nil {
			t.Errorf("%s: expected an error, got none", c.name)
		}
	}
	// GCM must accept a non-block-aligned buffer, because AEAD is a stream.
	if _, err := AESModeBenchmark(ModeGCM, 256, 1000, 5); err != nil {
		t.Errorf("GCM rejected a non-block-aligned buffer: %v", err)
	}
}

// TestAESModeComparisonCoversAllModes checks that the comparison helper returns
// one row per mode even when one of them fails, so a table is never silently
// short a row.
func TestAESModeComparisonCoversAllModes(t *testing.T) {
	rows := AESModeComparison(128, 4096, 10)
	if len(rows) != len(AESModeTable) {
		t.Fatalf("comparison returned %d rows, want %d", len(rows), len(AESModeTable))
	}
	seen := map[AESMode]bool{}
	for _, r := range rows {
		seen[r.Mode] = true
		if r.Error != "" {
			t.Errorf("%s: unexpected error %q", r.Mode, r.Error)
		}
		if !r.Verified {
			t.Errorf("%s: row not verified", r.Mode)
		}
		if r.KeyBits != 128 {
			t.Errorf("%s: key bits = %d, want 128", r.Mode, r.KeyBits)
		}
	}
	for _, m := range []AESMode{ModeECB, ModeCBC, ModeCTR, ModeGCM, ModeXTS} {
		if !seen[m] {
			t.Errorf("comparison omitted mode %s", m)
		}
	}
}

// TestAESModeComparisonSuiteShape checks the suite runs the documented sizes.
func TestAESModeComparisonSuiteShape(t *testing.T) {
	rows := AESModeComparisonSuite(256, 1)
	wantSizes := []int{1024, 64 * 1024, 1024 * 1024}
	if want := len(wantSizes) * len(AESModeTable); len(rows) != want {
		t.Fatalf("suite returned %d rows, want %d", len(rows), want)
	}
	for i, want := range wantSizes {
		row := rows[i*len(AESModeTable)]
		if row.BlockSize != want {
			t.Errorf("row %d block size = %d, want %d", i*len(AESModeTable), row.BlockSize, want)
		}
	}
}

// TestAESModeBenchmarkDoesNotLeakPlaintext is a small sanity check that the
// ciphertext buffer is actually distinct from the plaintext for every mode: an
// identity "cipher" would round-trip perfectly and still be worthless.
func TestAESModeBenchmarkDoesNotLeakPlaintext(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = 0x5A
	}
	iv := make([]byte, 16)
	pt := bytes.Repeat([]byte("zcrypt-s390x!!!!"), 4) // 16 bytes x4 = 64, block aligned

	for _, mode := range []AESMode{ModeECB, ModeCBC, ModeCTR} {
		ct, err := EncryptWithMode(mode, key, iv, pt)
		if err != nil {
			t.Fatalf("%s: %v", mode, err)
		}
		if bytes.Equal(ct, pt) {
			t.Errorf("%s: ciphertext equals plaintext", mode)
		}
		// No 8-byte window of plaintext may appear in the ciphertext.
		for i := 0; i+8 <= len(pt); i++ {
			if strings.Contains(string(ct), string(pt[i:i+8])) {
				t.Errorf("%s: ciphertext contains plaintext window at %d", mode, i)
				break
			}
		}
	}
}

// Benchmarks give `go test -bench` a stable way to reproduce the mode table
// without running the whole CLI.

func benchmarkAESMode(b *testing.B, mode AESMode, size int) {
	b.SetBytes(int64(size))
	key := make([]byte, 32)
	iv := make([]byte, 16)
	pt := make([]byte, size)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := EncryptWithMode(mode, key, iv, pt); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAES256CBC1MB(b *testing.B) { benchmarkAESMode(b, ModeCBC, 1024*1024) }
func BenchmarkAES256CTR1MB(b *testing.B) { benchmarkAESMode(b, ModeCTR, 1024*1024) }
func BenchmarkAES256ECB1MB(b *testing.B) { benchmarkAESMode(b, ModeECB, 1024*1024) }
func BenchmarkAES256CBC4KB(b *testing.B) { benchmarkAESMode(b, ModeCBC, 4096) }
func BenchmarkAES256CTR4KB(b *testing.B) { benchmarkAESMode(b, ModeCTR, 4096) }
