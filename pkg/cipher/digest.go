package cipher

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"time"
)

// NISTKnownVector validates that big-endian execution does not invert hash outputs.
const (
	NISTTestInput     = "The quick brown fox jumps over the lazy dog"
	ExpectedSHA256Hex = "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
	ExpectedSHA512Hex = "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6"
)

// VerifyNISTVectors verifies hashing correctness against canonical reference hashes.
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

// BenchmarkDigest measures throughput in MB/sec for a given block size and iterations.
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
