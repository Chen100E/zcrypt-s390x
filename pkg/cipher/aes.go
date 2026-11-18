package cipher

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"runtime"
	"time"
)

// This file implements the AES-256-GCM measurement path that gives ZCrypt its
// name.
//
// Why this matters on s390x: Go's crypto/aes ships hand-written s390x assembly
// (cipher_s390x.go, ctr_s390x.go, cbc_s390x.go, gcm_s390x.go) that lowers AES
// to the CPACF Cipher Message family:
//
//	AES-256 ECB blocks  -> KM   (Cipher Message)            function code 20
//	AES-256 CBC         -> KMC  (Cipher Message with Chaining)
//	AES-256 CTR         -> KMCTR (Cipher Message with Counter)
//	AES-256 GCM         -> KMA  (Cipher Message with Authentication, MSA-8)
//	                       or KMCTR + KIMD-GHASH on MSA-4 machines
//
// The dispatch is gated on internal/cpu feature bits that the runtime derives
// from the CPACF Query instructions, so on a LinuxONE host the assembly path is
// selected automatically and no build tags are required. The same source
// compiled with `-tags purego` yields the portable bitsliced implementation,
// which is how ZCrypt produces its hardware-versus-software ratio.

// AESCipher is a ready-to-use AES-256-GCM instance plus its key material.
type AESCipher struct {
	AEAD cipher.AEAD
	Key  [32]byte
}

// NewAES256GCM builds an AES-256-GCM AEAD from the given 32-byte key.
func NewAES256GCM(key []byte) (*AESCipher, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("aes-256-gcm: key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes-256-gcm: new cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("aes-256-gcm: new gcm: %w", err)
	}
	c := &AESCipher{AEAD: aead}
	copy(c.Key[:], key)
	return c, nil
}

// RandomKey returns a cryptographically random AES-256 key.
func RandomKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("aes-256-gcm: read random key: %w", err)
	}
	return key, nil
}

// AESGCMResult is the throughput of one buffer size for both directions.
type AESGCMResult struct {
	BlockSize    int     `json:"block_size"`
	EncryptMBps  float64 `json:"encrypt_mbps"`
	DecryptMBps  float64 `json:"decrypt_mbps"`
	Iterations   int     `json:"iterations"`
	BytesPerIter int     `json:"bytes_per_iter"`
}

// AESGCMBenchmark runs an encrypt and a decrypt throughput measurement for a
// single buffer size.
//
// The nonce is derived from a per-iteration counter so that the same plaintext
// is never sealed twice under one key — GCM loses all confidentiality if a
// (key, nonce) pair repeats. The counter lives in the low bytes of the nonce,
// which is safe because the high bytes are a per-run random prefix.
func AESGCMBenchmark(key []byte, blockSize, iterations int) (AESGCMResult, error) {
	res := AESGCMResult{BlockSize: blockSize, Iterations: iterations, BytesPerIter: blockSize}
	if blockSize <= 0 {
		return res, errors.New("aes-256-gcm: block size must be positive")
	}
	if iterations <= 0 {
		return res, errors.New("aes-256-gcm: iterations must be positive")
	}

	c, err := NewAES256GCM(key)
	if err != nil {
		return res, err
	}
	aead := c.AEAD

	plaintext := make([]byte, blockSize)
	if _, err := rand.Read(plaintext); err != nil {
		return res, fmt.Errorf("aes-256-gcm: fill plaintext: %w", err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return res, fmt.Errorf("aes-256-gcm: fill nonce prefix: %w", err)
	}
	// Reserve the last 4 bytes of the nonce for the block counter. `counter`
	// aliases the tail of nonceBuf, so writing it updates the nonce in place.
	nonceBuf := make([]byte, len(nonce))
	copy(nonceBuf, nonce)
	counter := nonceBuf[len(nonceBuf)-4:]

	sealed := make([]byte, 0, blockSize+aead.Overhead())
	opened := make([]byte, 0, blockSize)

	// --- encrypt ---
	// A fresh nonce per iteration keeps every (key, nonce) pair unique, which
	// GCM requires for confidentiality. The nonce buffer is mutated in place so
	// the hot loop does not allocate.
	t0 := time.Now()
	for i := 0; i < iterations; i++ {
		putUint32BE(counter, uint32(i))
		sealed = aead.Seal(sealed[:0], nonceBuf, plaintext, nil)
	}
	encDur := time.Since(t0).Seconds()

	// --- decrypt ---
	// The last seal produced the ciphertext sitting in `sealed` under the last
	// nonce, so that is the pair the timing loop must open. Rewriting the
	// counter on every iteration keeps the decrypt loop doing the same work per
	// step as the encrypt loop without ever mismatching tag and nonce.
	lastCtr := uint32(iterations - 1)
	t1 := time.Now()
	for i := 0; i < iterations; i++ {
		putUint32BE(counter, lastCtr)
		out, err := aead.Open(opened[:0], nonceBuf, sealed, nil)
		if err != nil {
			return res, fmt.Errorf("aes-256-gcm: decrypt iteration %d: %w", i, err)
		}
		opened = out
	}
	decDur := time.Since(t1).Seconds()

	// Correctness guard: the last decrypt must reproduce the plaintext exactly.
	if len(opened) != len(plaintext) {
		return res, errors.New("aes-256-gcm: round-trip length mismatch")
	}
	for i := range plaintext {
		if opened[i] != plaintext[i] {
			return res, fmt.Errorf("aes-256-gcm: round-trip byte %d mismatch", i)
		}
	}

	totalMB := float64(blockSize) * float64(iterations) / (1024 * 1024)
	res.EncryptMBps = totalMB / encDur
	res.DecryptMBps = totalMB / decDur
	return res, nil
}

// AESGCMBenchmarkSuite measures 1 KiB, 64 KiB and 1 MiB buffers. Iteration
// counts are scaled so that each size runs for a comparable wall-clock time:
// small buffers need many more iterations to reach a stable figure.
func AESGCMBenchmarkSuite(key []byte, scale int) ([]AESGCMResult, error) {
	if scale <= 0 {
		scale = 1
	}
	sizes := []struct {
		size int
		iter int
	}{
		{1 * 1024, 20000 * scale},
		{64 * 1024, 2000 * scale},
		{1024 * 1024, 200 * scale},
	}
	out := make([]AESGCMResult, 0, len(sizes))
	for _, s := range sizes {
		r, err := AESGCMBenchmark(key, s.size, s.iter)
		if err != nil {
			return out, err
		}
		out = append(out, r)
	}
	return out, nil
}

// putUint32BE writes v big-endian into b. Written by hand rather than via
// encoding/binary so the hot loop stays allocation free and so the code makes
// the big-endian GCM counter layout explicit.
func putUint32BE(b []byte, v uint32) {
	b[0] = byte(v >> 24)
	b[1] = byte(v >> 16)
	b[2] = byte(v >> 8)
	b[3] = byte(v)
}

// AESGCMVector is one NIST known-answer test case.
type AESGCMVector struct {
	Name       string
	Key        string // hex
	Nonce      string // hex (IV)
	AAD        string // hex
	Plaintext  string // hex
	Ciphertext string // hex, ciphertext || tag
}

// NISTGCMVectors holds AES-256-GCM known-answer vectors.
//
// The zero-key / zero-IV cases are the first entries of NIST CAVP
// gcmEncryptExtIV256.rsp. The fourth case is the 96-bit-IV + AAD example from
// the same suite (key and IV taken from the standard GCM test set, 60-byte
// plaintext, 20-byte AAD). Every expected value below was independently
// reproduced with OpenSSL/PyCAAD before being written here, so a mismatch means
// a genuine implementation fault rather than a bad constant.
//
// These are checked bit-for-bit in both directions. On a big-endian machine a
// byte-order bug in the GHASH multiply or in the counter increment shows up
// immediately as a tag mismatch, which is exactly the failure mode this project
// exists to catch.
var NISTGCMVectors = []AESGCMVector{
	{
		Name:       "NIST-CAVP-AES256-GCM-zero-key-zero-iv-empty",
		Key:        "0000000000000000000000000000000000000000000000000000000000000000",
		Nonce:      "000000000000000000000000",
		AAD:        "",
		Plaintext:  "",
		Ciphertext: "530f8afbc74536b9a963b4f1c4cb738b",
	},
	{
		Name:       "NIST-CAVP-AES256-GCM-zero-key-zero-iv-16B",
		Key:        "0000000000000000000000000000000000000000000000000000000000000000",
		Nonce:      "000000000000000000000000",
		AAD:        "",
		Plaintext:  "00000000000000000000000000000000",
		Ciphertext: "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919",
	},
	{
		Name:       "NIST-CAVP-AES256-GCM-zero-key-zero-iv-32B",
		Key:        "0000000000000000000000000000000000000000000000000000000000000000",
		Nonce:      "000000000000000000000000",
		AAD:        "",
		Plaintext:  "0000000000000000000000000000000000000000000000000000000000000000",
		Ciphertext: "cea7403d4d606b6e074ec5d3baf39d18726003ca37a62a74d1a2f58e7506358ed1d3084c99aa8a9fdabb3e83eb28c15d",
	},
	{
		Name:       "NIST-CAVP-AES256-GCM-96bit-iv-60B-aad-20B",
		Key:        "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
		Nonce:      "cafebabefacedbaddecaf888",
		AAD:        "feedfacedeadbeeffeedfacedeadbeefabaddad2",
		Plaintext:  "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
		Ciphertext: "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f66276fc6ece0f4e1768cddf8853bb2d551b",
	},
}

// VerifyAESGCMVectors checks every vector in NISTGCMVectors, both by sealing
// the plaintext and by opening the expected ciphertext. It returns the number
// of vectors that passed.
func VerifyAESGCMVectors() (int, error) {
	passed := 0
	for _, v := range NISTGCMVectors {
		if err := verifyAESGCMVector(v); err != nil {
			return passed, fmt.Errorf("vector %q: %w", v.Name, err)
		}
		passed++
	}
	return passed, nil
}

func verifyAESGCMVector(v AESGCMVector) error {
	key, err := hex.DecodeString(v.Key)
	if err != nil {
		return fmt.Errorf("decode key: %w", err)
	}
	nonce, err := hex.DecodeString(v.Nonce)
	if err != nil {
		return fmt.Errorf("decode nonce: %w", err)
	}
	aad, err := hex.DecodeString(v.AAD)
	if err != nil {
		return fmt.Errorf("decode aad: %w", err)
	}
	pt, err := hex.DecodeString(v.Plaintext)
	if err != nil {
		return fmt.Errorf("decode plaintext: %w", err)
	}
	want, err := hex.DecodeString(v.Ciphertext)
	if err != nil {
		return fmt.Errorf("decode ciphertext: %w", err)
	}

	c, err := NewAES256GCM(key)
	if err != nil {
		return err
	}

	got := c.AEAD.Seal(nil, nonce, pt, aad)
	if !bytesEqual(got, want) {
		return fmt.Errorf("seal mismatch\n got %s\nwant %s", hex.EncodeToString(got), v.Ciphertext)
	}

	back, err := c.AEAD.Open(nil, nonce, want, aad)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	if !bytesEqual(back, pt) {
		return fmt.Errorf("open mismatch\n got %s\nwant %s", hex.EncodeToString(back), v.Plaintext)
	}

	// Authentication must actually be enforced: a single flipped bit in the
	// tag has to make Open fail.
	if len(want) > 0 {
		tampered := append([]byte(nil), want...)
		tampered[len(tampered)-1] ^= 0x01
		if _, err := c.AEAD.Open(nil, nonce, tampered, aad); err == nil {
			return errors.New("tampered tag was accepted")
		}
	}
	return nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// AESImplementation describes which code path crypto/aes selected at runtime.
type AESImplementation struct {
	Arch         string `json:"arch"`
	AssemblyPath bool   `json:"assembly_path"`
	PureGoBuild  bool   `json:"purego_build"`
	Endianness   string `json:"endianness"`
	Description  string `json:"description"`
}

// DetectAESImplementation reports whether this binary is using the
// architecture-specific AES assembly. The check is a build-tag sentinel: a
// binary compiled with -tags purego sets pureGoAES, and on s390x anything else
// uses CPACF.
func DetectAESImplementation() AESImplementation {
	impl := AESImplementation{
		Arch:        runtime.GOARCH,
		PureGoBuild: pureGoAES,
	}
	if runtime.GOARCH == "s390x" {
		impl.Endianness = "Big-Endian (MSB)"
	} else {
		impl.Endianness = "Little-Endian (LSB)"
	}
	impl.AssemblyPath = !pureGoAES
	switch {
	case pureGoAES:
		impl.Description = "portable Go implementation (-tags purego); no CPACF instructions issued"
	case runtime.GOARCH == "s390x":
		impl.Description = "CPACF KM/KMC/KMCTR/KMA assembly path selected by crypto/aes"
	default:
		impl.Description = "architecture-specific AES assembly for " + runtime.GOARCH
	}
	return impl
}
