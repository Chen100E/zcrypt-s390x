package cipher

// GHASH: the GF(2^128) universal hash that GCM is built on (NIST SP 800-38D,
// §6.4). It is exposed here as a standalone primitive for three reasons.
//
// First, localisation. The AES-256-GCM vectors in aes.go exercise GHASH only
// fused inside the hardware's KMA instruction (or inside crypto/cipher's GCM),
// so when a tag mismatches there is no way to tell whether the fault is in the
// reduction polynomial, in the length block, or in the counter increment. A
// standalone GHASH with its own known-answer vectors splits that failure space
// in two: if the GHASH vectors pass and the GCM vectors fail, the bug is not in
// the field arithmetic.
//
// Second, the length block. GHASH is defined over the message
//
//	pad16(A) || pad16(C) || [len(A)]_64 || [len(C)]_64
//
// where the two trailing words are the AAD and ciphertext lengths *in bits*,
// big-endian. That encoding is the single most common place to introduce a bug,
// because it is the one part of the construction that is neither a block cipher
// nor a field operation, and because getting it wrong still produces a stable,
// plausible-looking tag. GHASHMessage below builds exactly that message and is
// tested on its own, separately from the field arithmetic.
//
// Third, J0. When the IV is not 96 bits, GCM derives the pre-counter block from
// GHASH rather than by appending 0^31||1, which is a second, distinct use of
// the same primitive. gcm.go covers that path with NIST CAVP vectors.
//
// The multiply below is a bit-at-a-time shift-and-xor loop. It is a reference
// implementation, not a hot path: it runs at tens of MB/s where the kernel's
// ghash-s390 driver (CPACF KIMD-GHASH, function code 65) runs at gigabytes per
// second. That asymmetry is the point of the project, and keeping the reference
// obviously-correct matters more than making it fast. It is also written without
// data-dependent branches on the operands, so it does not leak the hash key
// through timing the way a table-driven implementation would.

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

const (
	// ghashBlockSize is the GHASH block size in bytes. GHASH is defined over
	// 128-bit blocks, which is also the size of its output.
	ghashBlockSize = 16

	// ghashReduction is the low byte of the reduction polynomial
	// R = 0xe1 || 0^120. Because the GCM multiply shifts its accumulator
	// right, the polynomial enters as an XOR of 0xe1 into the *high* byte
	// after each right shift, not as a low-byte mask.
	ghashReduction = 0xe1
)

// GHASH is a streaming GHASH instance, keyed by H = E_K(0^128).
//
// The streaming semantics match a hash: Write buffers a trailing partial block
// and only folds complete 16-byte blocks into the accumulator, and Sum reports
// the digest of everything written so far without consuming the state. Sum
// therefore zero-pads a trailing partial block, which is what the GCM message
// construction does anyway (both the AAD and the ciphertext are padded to a
// 16-byte boundary before the length block).
type GHASH struct {
	h   [ghashBlockSize]byte // the hash subkey H = E_K(0^128)
	y   [ghashBlockSize]byte // the accumulator Y_i
	buf [ghashBlockSize]byte // pending partial block
	n   int                  // bytes pending in buf, 0 <= n < 16
}

// NewGHASH returns a GHASH instance keyed with H, which must be the 16-byte
// value E_K(0^128) for the AES key K.
//
// H is supplied rather than derived because GHASH is a universal hash, not a
// cipher: it has no notion of a key schedule. Callers that have an AES key can
// get H with GCMHashSubkey.
func NewGHASH(h []byte) (*GHASH, error) {
	if len(h) != ghashBlockSize {
		return nil, fmt.Errorf("ghash: hash subkey H must be %d bytes, got %d", ghashBlockSize, len(h))
	}
	g := &GHASH{}
	copy(g.h[:], h)
	return g, nil
}

// Write folds p into the accumulator, buffering any trailing partial block.
func (g *GHASH) Write(p []byte) (int, error) {
	total := len(p)

	if g.n > 0 {
		c := copy(g.buf[g.n:], p)
		g.n += c
		p = p[c:]
		if g.n == ghashBlockSize {
			g.absorb(g.buf[:])
			g.n = 0
		}
	}

	// Whole blocks are folded straight out of the caller's slice: no copy.
	for len(p) >= ghashBlockSize {
		g.absorb(p[:ghashBlockSize])
		p = p[ghashBlockSize:]
	}

	if len(p) > 0 {
		g.n = copy(g.buf[:], p)
	}
	return total, nil
}

// absorb applies one complete block: Y = (Y xor block) * H.
func (g *GHASH) absorb(block []byte) {
	for i := 0; i < ghashBlockSize; i++ {
		g.y[i] ^= block[i]
	}
	g.y = gcmMul(&g.y, &g.h)
}

// Sum returns the 16-byte GHASH of everything written since the last Reset.
//
// The state is not consumed: a trailing partial block is zero-padded into a
// temporary copy of the accumulator, so a subsequent Write continues where it
// left off. This is the same contract as hash.Hash.Sum, minus the appending
// form, because GHASH output is always exactly 16 bytes.
func (g *GHASH) Sum() []byte {
	y := g.y
	if g.n > 0 {
		var tail [ghashBlockSize]byte
		copy(tail[:], g.buf[:g.n])
		for i := 0; i < ghashBlockSize; i++ {
			y[i] ^= tail[i]
		}
		y = gcmMul(&y, &g.h)
	}
	out := make([]byte, ghashBlockSize)
	copy(out, y[:])
	return out
}

// Reset clears the accumulator and the pending partial block.
func (g *GHASH) Reset() {
	g.y = [ghashBlockSize]byte{}
	g.buf = [ghashBlockSize]byte{}
	g.n = 0
}

// Size reports the GHASH output length in bytes.
func (g *GHASH) Size() int { return ghashBlockSize }

// BlockSize reports the GHASH block size in bytes.
func (g *GHASH) BlockSize() int { return ghashBlockSize }

// GHASHSum returns GHASH_H(data) in one shot, or nil when h is not 16 bytes.
//
// The nil return keeps the one-shot helper allocation-free of error handling at
// call sites that already hold a known-good H. Callers that need the error
// should use NewGHASH.
func GHASHSum(h, data []byte) []byte {
	g, err := NewGHASH(h)
	if err != nil {
		return nil
	}
	_, _ = g.Write(data)
	return g.Sum()
}

// GHASHMessage builds the GCM GHASH input for a ciphertext and its associated
// data: pad16(aad) || pad16(ct) || [len(aad)*8]_64 || [len(ct)*8]_64.
//
// The lengths are in bits and big-endian. On s390x that is also the native byte
// order, which makes the encoding easy to get right by accident and easy to
// break by "optimising" it into a native-endian store; the vectors in
// ghash_test.go pin the byte order explicitly.
func GHASHMessage(aad, ct []byte) []byte {
	msg := make([]byte, 0, paddedLen(len(aad))+paddedLen(len(ct))+16)
	msg = appendPadded(msg, aad)
	msg = appendPadded(msg, ct)

	var lenBlock [16]byte
	binary.BigEndian.PutUint64(lenBlock[0:8], uint64(len(aad))*8)
	binary.BigEndian.PutUint64(lenBlock[8:16], uint64(len(ct))*8)
	return append(msg, lenBlock[:]...)
}

// paddedLen is the length of b rounded up to a multiple of the block size.
func paddedLen(n int) int {
	if r := n % ghashBlockSize; r != 0 {
		return n + ghashBlockSize - r
	}
	return n
}

// appendPadded appends b followed by the zero padding that rounds it up to a
// block boundary.
func appendPadded(dst, b []byte) []byte {
	dst = append(dst, b...)
	for i := len(b); i < paddedLen(len(b)); i++ {
		dst = append(dst, 0)
	}
	return dst
}

// gcmMul returns x * y in GF(2^128) under the GCM convention of SP 800-38D §6.3.
//
// The convention is worth spelling out because it is where implementations
// disagree: the bits of a block are numbered from the most significant bit of
// byte 0 (bit 0) to the least significant bit of byte 15 (bit 127), and
// multiplication is defined by a right shift of the operand with the reduction
// polynomial R = 0xe1 || 0^120 folded in whenever a 1 is shifted off the bottom.
// This is the mirror image of the "left shift, R = 0^120 || 0x87" convention
// used by GCM's AES-only relatives, and mixing the two up yields a multiply that
// is still commutative and associative but is not GCM's.
//
// The loop is data-independent in the operands: it always performs 128
// iterations and uses a mask rather than a branch to apply the polynomial, so
// the running time depends only on the (public) block length.
func gcmMul(x, y *[ghashBlockSize]byte) [ghashBlockSize]byte {
	var z [ghashBlockSize]byte
	v := *y

	for i := 0; i < 128; i++ {
		// Bit i of x, counted from the MSB of byte 0.
		mask := byte(0) - ((x[i/8] >> (7 - uint(i%8))) & 1)
		for j := 0; j < ghashBlockSize; j++ {
			z[j] ^= v[j] & mask
		}

		// v >>= 1, and fold in R when the bit shifted out was 1.
		carry := byte(0) - (v[ghashBlockSize-1] & 1)
		for j := ghashBlockSize - 1; j > 0; j-- {
			v[j] = v[j]>>1 | v[j-1]<<7
		}
		v[0] = v[0]>>1 ^ (ghashReduction & carry)
	}
	return z
}

// GHASHVector is one standalone GHASH known-answer case. H is given explicitly
// rather than derived from a key, because GHASH is keyed by H and deriving it
// would only add an AES step to every failure message.
type GHASHVector struct {
	Name string
	H    string // hex, 16 bytes
	AAD  string // hex
	CT   string // hex
	Sum  string // hex, 16 bytes
}

// NISTGHASHVectors holds the standalone GHASH known-answer cases.
//
// Every expected value was produced by two independent implementations on the
// target host and agreed bit for bit: the kernel's ghash-s390 driver through
// AF_ALG (CPACF KIMD-GHASH, function code 65), and a from-scratch bit-by-bit
// GHASH in Python. H itself was derived with AES-256-ECB over a zero block via
// Python's cryptography package, so the H constants are not taken on trust
// either. A mismatch here is therefore an implementation fault, not a bad
// constant.
//
// The first case is the AES-256-GCM example from the standard GCM test set, with
// H, AAD and ciphertext taken from it. The remaining cases use the all-zero
// AES-256 key, which gives the smallest non-trivial H and makes an
// implementation that accidentally ignores H fail loudly rather than subtly.
var NISTGHASHVectors = []GHASHVector{
	{
		Name: "GCM-test-set-AES256-H-20B-aad-60B-ct",
		H:    "acbef20579b4b8ebce889bac8732dad7",
		AAD:  "feedfacedeadbeeffeedfacedeadbeefabaddad2",
		CT: "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa" +
			"8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f66276fc6ece" +
			"0f4e1768cddf8853bb2d551b",
		Sum: "f2197f4660ba455523e7a683319afb27",
	},
	{
		Name: "zero-H-empty-message",
		H:    "dc95c078a2408989ad48a21492842087",
		AAD:  "",
		CT:   "",
		Sum:  "00000000000000000000000000000000",
	},
	{
		Name: "zero-H-16B-zero-ct",
		H:    "dc95c078a2408989ad48a21492842087",
		AAD:  "",
		CT:   "00000000000000000000000000000000",
		Sum:  "fb7bda2ab46e3c03e44adfd64230a492",
	},
	{
		Name: "zero-H-32B-zero-ct",
		H:    "dc95c078a2408989ad48a21492842087",
		AAD:  "",
		CT:   "0000000000000000000000000000000000000000000000000000000000000000",
		Sum:  "34f7b45568dc7807c895bfac84614925",
	},
	{
		Name: "three-block-ct-no-aad",
		H:    "acbef20579b4b8ebce889bac8732dad7",
		AAD:  "",
		CT: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
			"202122232425262728292a2b2c2d2e2f",
		Sum: "2beca5cf87c126c062967e53333706bf",
	},
	{
		Name: "5B-aad-16B-ct",
		H:    "acbef20579b4b8ebce889bac8732dad7",
		AAD:  "0001020304",
		CT:   "00112233445566778899aabbccddeeff",
		Sum:  "851eeed2dd945a45b9500da66bf3dff7",
	},
	{
		Name: "20B-aad-only",
		H:    "dc95c078a2408989ad48a21492842087",
		AAD:  "feedfacedeadbeeffeedfacedeadbeefabaddad2",
		CT:   "",
		Sum:  "350a30770495d33fe7eeb011bf37f8bd",
	},
	{
		Name: "1B-aad-17B-ct-unaligned",
		H:    "acbef20579b4b8ebce889bac8732dad7",
		AAD:  "0a",
		CT:   "000102030405060708090a0b0c0d0e0f10",
		Sum:  "02b0b6262180381121a1931978e4f6be",
	},
}

// VerifyGHASHVectors checks every standalone GHASH vector and returns the number
// that passed.
func VerifyGHASHVectors() (int, error) {
	passed := 0
	for _, v := range NISTGHASHVectors {
		if err := verifyGHASHVector(v); err != nil {
			return passed, err
		}
		passed++
	}
	return passed, nil
}

func verifyGHASHVector(v GHASHVector) error {
	h, err := hex.DecodeString(v.H)
	if err != nil {
		return fmt.Errorf("ghash vector %s: decode H: %w", v.Name, err)
	}
	aad, err := hex.DecodeString(v.AAD)
	if err != nil {
		return fmt.Errorf("ghash vector %s: decode aad: %w", v.Name, err)
	}
	ct, err := hex.DecodeString(v.CT)
	if err != nil {
		return fmt.Errorf("ghash vector %s: decode ct: %w", v.Name, err)
	}
	want, err := hex.DecodeString(v.Sum)
	if err != nil {
		return fmt.Errorf("ghash vector %s: decode sum: %w", v.Name, err)
	}

	got := GHASHSum(h, GHASHMessage(aad, ct))
	if !bytes.Equal(got, want) {
		return fmt.Errorf("ghash vector %s: got %s want %s",
			v.Name, hex.EncodeToString(got), v.Sum)
	}
	return nil
}

// ghashBenchData returns the deterministic buffer both benchmarks hash.
//
// The two paths share it so that the Sum field of a GHASHResult can be compared
// across backends: identical data must give an identical GHASH, which makes the
// report's two rows a cross-check rather than two unrelated numbers.
func ghashBenchData(blockSize int) []byte {
	data := make([]byte, paddedLen(blockSize))
	for i := range data {
		data[i] = byte((i * 7) % 251)
	}
	return data
}

// GHASHResult is the measured throughput of one GHASH implementation.
type GHASHResult struct {
	Backend    string  `json:"backend"`
	BlockSize  int     `json:"block_size"`
	Iterations int     `json:"iterations"`
	MBps       float64 `json:"mbps"`
	Sum        string  `json:"sum"`
	Error      string  `json:"error,omitempty"`
}

// GHASHSoftwareBenchmark measures the pure-Go reference implementation.
//
// The measured quantity is the hash of a blockSize message, which is the same
// work the AF_ALG path performs, so the two figures in the report are directly
// comparable.
func GHASHSoftwareBenchmark(h []byte, blockSize, iterations int) (GHASHResult, error) {
	res := GHASHResult{Backend: "pure-go", BlockSize: blockSize, Iterations: iterations}
	if blockSize <= 0 || iterations <= 0 {
		return res, errors.New("ghash: block size and iterations must be positive")
	}
	g, err := NewGHASH(h)
	if err != nil {
		return res, err
	}
	data := ghashBenchData(blockSize)

	t0 := time.Now()
	var sum []byte
	for i := 0; i < iterations; i++ {
		g.Reset()
		_, _ = g.Write(data)
		sum = g.Sum()
	}
	dur := time.Since(t0).Seconds()

	totalMB := float64(len(data)) * float64(iterations) / (1024 * 1024)
	res.MBps = totalMB / dur
	res.Sum = hexEncode(sum)
	return res, nil
}
