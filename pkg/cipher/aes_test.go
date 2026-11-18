package cipher

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestAESGCMNISTVectors runs the known-answer suite in both directions. This is
// the test that would catch a big-endian byte-order fault in GHASH or in the
// counter increment, which is the whole reason the project targets s390x.
func TestAESGCMNISTVectors(t *testing.T) {
	passed, err := VerifyAESGCMVectors()
	if err != nil {
		t.Fatalf("AES-256-GCM NIST vectors failed: %v", err)
	}
	if passed != len(NISTGCMVectors) {
		t.Fatalf("passed = %d, want %d", passed, len(NISTGCMVectors))
	}
	t.Logf("%d/%d AES-256-GCM NIST vectors bit-exact", passed, len(NISTGCMVectors))
}

// TestAESGCMVectorShape validates the vectors themselves: key length, nonce
// length and ciphertext length must all be self-consistent, so a mistyped hex
// constant fails here rather than looking like an implementation bug.
func TestAESGCMVectorShape(t *testing.T) {
	for _, v := range NISTGCMVectors {
		key, err := hex.DecodeString(v.Key)
		if err != nil {
			t.Errorf("%s: bad key hex: %v", v.Name, err)
			continue
		}
		if len(key) != 32 {
			t.Errorf("%s: key is %d bytes, want 32", v.Name, len(key))
		}
		nonce, err := hex.DecodeString(v.Nonce)
		if err != nil {
			t.Errorf("%s: bad nonce hex: %v", v.Name, err)
			continue
		}
		if len(nonce) != 12 {
			t.Errorf("%s: nonce is %d bytes, want 12", v.Name, len(nonce))
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
		if len(ct) != len(pt)+16 {
			t.Errorf("%s: ciphertext is %d bytes, want plaintext %d + 16-byte tag",
				v.Name, len(ct), len(pt))
		}
	}
}

func TestAESGCMRoundTrip(t *testing.T) {
	for _, size := range []int{0, 1, 15, 16, 17, 1024, 64 * 1024} {
		key, err := RandomKey()
		if err != nil {
			t.Fatalf("RandomKey: %v", err)
		}
		c, err := NewAES256GCM(key)
		if err != nil {
			t.Fatalf("NewAES256GCM: %v", err)
		}
		plaintext := bytes.Repeat([]byte{0xA5}, size)
		nonce := make([]byte, c.AEAD.NonceSize())
		for i := range nonce {
			nonce[i] = byte(i)
		}
		aad := []byte("zcrypt-s390x")

		sealed := c.AEAD.Seal(nil, nonce, plaintext, aad)
		if len(sealed) != size+c.AEAD.Overhead() {
			t.Errorf("size %d: sealed length %d, want %d", size, len(sealed), size+c.AEAD.Overhead())
		}
		opened, err := c.AEAD.Open(nil, nonce, sealed, aad)
		if err != nil {
			t.Fatalf("size %d: Open: %v", size, err)
		}
		if !bytes.Equal(opened, plaintext) {
			t.Errorf("size %d: round-trip mismatch", size)
		}
	}
}

// TestAESGCMRejectsTampering proves authentication is actually enforced rather
// than merely computed: flipping a ciphertext bit, a tag bit, or the AAD must
// all make Open fail.
func TestAESGCMRejectsTampering(t *testing.T) {
	key, err := RandomKey()
	if err != nil {
		t.Fatalf("RandomKey: %v", err)
	}
	c, err := NewAES256GCM(key)
	if err != nil {
		t.Fatalf("NewAES256GCM: %v", err)
	}
	nonce := make([]byte, c.AEAD.NonceSize())
	aad := []byte("header")
	plaintext := []byte("the quick brown fox jumps over the lazy dog")
	sealed := c.AEAD.Seal(nil, nonce, plaintext, aad)

	flipCiphertext := append([]byte(nil), sealed...)
	flipCiphertext[0] ^= 0x80
	if _, err := c.AEAD.Open(nil, nonce, flipCiphertext, aad); err == nil {
		t.Error("Open accepted a ciphertext with a flipped bit")
	}

	flipTag := append([]byte(nil), sealed...)
	flipTag[len(flipTag)-1] ^= 0x01
	if _, err := c.AEAD.Open(nil, nonce, flipTag, aad); err == nil {
		t.Error("Open accepted a tampered tag")
	}

	if _, err := c.AEAD.Open(nil, nonce, sealed, []byte("different")); err == nil {
		t.Error("Open accepted a mismatched AAD")
	}

	wrongNonce := append([]byte(nil), nonce...)
	wrongNonce[0] ^= 0xFF
	if _, err := c.AEAD.Open(nil, wrongNonce, sealed, aad); err == nil {
		t.Error("Open accepted a mismatched nonce")
	}

	if _, err := c.AEAD.Open(nil, nonce, sealed[:len(sealed)-1], aad); err == nil {
		t.Error("Open accepted a truncated ciphertext")
	}
}

func TestNewAES256GCMRejectsWrongKeyLength(t *testing.T) {
	for _, n := range []int{0, 16, 24, 31, 33} {
		if _, err := NewAES256GCM(make([]byte, n)); err == nil {
			t.Errorf("NewAES256GCM accepted a %d-byte key, want an error", n)
		}
	}
	if _, err := NewAES256GCM(make([]byte, 32)); err != nil {
		t.Errorf("NewAES256GCM rejected a valid 32-byte key: %v", err)
	}
}

func TestAESGCMBenchmarkValidation(t *testing.T) {
	key := make([]byte, 32)
	if _, err := AESGCMBenchmark(key, 0, 1); err == nil {
		t.Error("AESGCMBenchmark accepted a zero block size")
	}
	if _, err := AESGCMBenchmark(key, 1024, 0); err == nil {
		t.Error("AESGCMBenchmark accepted zero iterations")
	}
	if _, err := AESGCMBenchmark(make([]byte, 16), 1024, 1); err == nil {
		t.Error("AESGCMBenchmark accepted a 16-byte key")
	}
}

func TestAESGCMBenchmarkSuite(t *testing.T) {
	key, err := RandomKey()
	if err != nil {
		t.Fatalf("RandomKey: %v", err)
	}
	results, err := AESGCMBenchmarkSuite(key, 1)
	if err != nil {
		t.Fatalf("AESGCMBenchmarkSuite: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("got %d results, want 3 (1 KiB, 64 KiB, 1 MiB)", len(results))
	}
	wantSizes := []int{1024, 65536, 1048576}
	for i, r := range results {
		if r.BlockSize != wantSizes[i] {
			t.Errorf("result %d: BlockSize = %d, want %d", i, r.BlockSize, wantSizes[i])
		}
		if r.Iterations <= 0 {
			t.Errorf("result %d: Iterations = %d, want > 0", i, r.Iterations)
		}
		if r.EncryptMBps <= 0 || r.DecryptMBps <= 0 {
			t.Errorf("result %d: non-positive throughput enc=%.2f dec=%.2f",
				i, r.EncryptMBps, r.DecryptMBps)
		}
	}
}

// TestPutUint32BE pins the GCM counter byte order explicitly. GCM increments
// the low 32 bits of the nonce as a big-endian integer, so getting this wrong
// on a big-endian host would silently produce a non-standard counter block.
func TestPutUint32BE(t *testing.T) {
	buf := make([]byte, 4)
	putUint32BE(buf, 0x01020304)
	want := []byte{0x01, 0x02, 0x03, 0x04}
	if !bytes.Equal(buf, want) {
		t.Errorf("putUint32BE = %x, want %x", buf, want)
	}
	putUint32BE(buf, 0)
	if !bytes.Equal(buf, []byte{0, 0, 0, 0}) {
		t.Errorf("putUint32BE(0) = %x, want 00000000", buf)
	}
	putUint32BE(buf, 0xFFFFFFFF)
	if !bytes.Equal(buf, []byte{0xFF, 0xFF, 0xFF, 0xFF}) {
		t.Errorf("putUint32BE(max) = %x, want ffffffff", buf)
	}
}

func TestDetectAESImplementation(t *testing.T) {
	impl := DetectAESImplementation()
	if impl.Arch == "" {
		t.Error("Arch must be populated")
	}
	if impl.Description == "" {
		t.Error("Description must be populated")
	}
	if impl.Endianness == "" {
		t.Error("Endianness must be populated")
	}
	// AssemblyPath and PureGoBuild are mutually exclusive by construction.
	if impl.AssemblyPath == impl.PureGoBuild {
		t.Errorf("AssemblyPath=%v and PureGoBuild=%v must differ",
			impl.AssemblyPath, impl.PureGoBuild)
	}
}

func TestBenchmarkDigest(t *testing.T) {
	sha256MBps, sha512MBps := BenchmarkDigest(64*1024, 8)
	if sha256MBps <= 0 || sha512MBps <= 0 {
		t.Fatalf("non-positive digest throughput: sha256=%.2f sha512=%.2f",
			sha256MBps, sha512MBps)
	}
	t.Logf("SHA-256 %.2f MB/s, SHA-512 %.2f MB/s on 64 KiB buffers", sha256MBps, sha512MBps)
}
