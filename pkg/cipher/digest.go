package cipher

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"hash"
	"time"
)

// NISTKnownVector validates that big-endian execution does not invert hash
// outputs.
//
// SHA-256 and SHA-512 process their message schedule and produce their digest
// as a big-endian byte string. On a little-endian host a missing byte swap is
// often masked by a compensating swap elsewhere; on s390x there is no
// compensation to hide behind, so a portability bug surfaces as a completely
// different digest. These constants are the canonical reference values for the
// pangram below.
const (
	NISTTestInput     = "The quick brown fox jumps over the lazy dog"
	ExpectedSHA256Hex = "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
	ExpectedSHA512Hex = "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6"

	// ExpectedSHA1Hex is included because CPACF KIMD-SHA-1 is the baseline
	// digest function present on every machine that has MSA at all.
	ExpectedSHA1Hex = "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"
)

// VerifyNISTVectors verifies hashing correctness against canonical reference
// hashes.
func VerifyNISTVectors() error {
	h256 := sha256.Sum256([]byte(NISTTestInput))
	if hex.EncodeToString(h256[:]) != ExpectedSHA256Hex {
		return errors.New("SHA256 NIST vector mismatch on s390x")
	}

	h512 := sha512.Sum512([]byte(NISTTestInput))
	if hex.EncodeToString(h512[:]) != ExpectedSHA512Hex {
		return errors.New("SHA512 NIST vector mismatch on s390x")
	}

	return nil
}

// DigestResult is the measured throughput for one hash and buffer size.
type DigestResult struct {
	Algorithm  string  `json:"algorithm"`
	BlockSize  int     `json:"block_size"`
	MBps       float64 `json:"mbps"`
	Iterations int     `json:"iterations"`
}

// BenchmarkDigest measures throughput in MB/sec for a given block size and
// iterations.
func BenchmarkDigest(blockSize int, iterations int) (sha256MBps float64, sha512MBps float64) {
	data := make([]byte, blockSize)
	for i := range data {
		data[i] = byte(i % 256)
	}

	t0 := time.Now()
	for i := 0; i < iterations; i++ {
		_ = sha256.Sum256(data)
	}
	dur256 := time.Since(t0).Seconds()

	t1 := time.Now()
	for i := 0; i < iterations; i++ {
		_ = sha512.Sum512(data)
	}
	dur512 := time.Since(t1).Seconds()

	totalMB := float64(blockSize*iterations) / (1024.0 * 1024.0)
	sha256MBps = totalMB / dur256
	sha512MBps = totalMB / dur512

	return sha256MBps, sha512MBps
}

// BenchmarkHash measures the throughput of an arbitrary hash constructor.
//
// It feeds the data through hash.Hash.Write rather than calling a one-shot
// Sum function so that the measurement covers the same streaming code path a
// real caller (TLS record layer, object storage checksum, log integrity chain)
// would exercise. Sum256/Sum512 are thin wrappers that reach the identical
// KIMD/KLMD block function, so the numbers stay comparable.
func BenchmarkHash(newHash func() hash.Hash, blockSize, iterations int) (float64, error) {
	if blockSize <= 0 || iterations <= 0 {
		return 0, errors.New("cipher: block size and iterations must be positive")
	}
	data := make([]byte, blockSize)
	for i := range data {
		data[i] = byte((i * 7) % 251)
	}

	h := newHash()
	t0 := time.Now()
	for i := 0; i < iterations; i++ {
		h.Reset()
		_, _ = h.Write(data)
		_ = h.Sum(nil)
	}
	dur := time.Since(t0).Seconds()

	totalMB := float64(blockSize) * float64(iterations) / (1024 * 1024)
	return totalMB / dur, nil
}
