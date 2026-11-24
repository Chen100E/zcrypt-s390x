package cipher

// SHAKE128 and SHAKE256, the FIPS 202 extendable-output functions (XOFs).
//
// A XOF is not a hash with a longer digest, and the difference is the whole
// reason this file exists. A truncated hash produces N bytes and stops; a XOF
// produces an unbounded stream, and every prefix of that stream is the answer
// for the corresponding output length. Concretely:
//
//	SHAKE128("") first 200 bytes == SHAKE128("") first 32 bytes ++ next 168 bytes
//	                              == the first 200 bytes of the infinite stream
//
// So the squeeze is a state machine, not a memcpy: once the rate (168 bytes for
// SHAKE128, 136 for SHAKE256) has been handed out, the permutation runs again
// and another rate worth of output becomes available. Reading 200 bytes from
// SHAKE128 therefore costs two permutations, and reading it in chunks of 32 and
// then 168 must produce exactly the same bytes as one 200-byte read. Getting
// that wrong is the classic XOF bug — an implementation that re-pads or
// re-permutes between reads still looks like a hash, and still passes any test
// whose output length fits in one block.
//
// The domain separation is the other half. SHAKE pads with 0x1F ... 0x80 where
// SHA-3 pads with 0x06 ... 0x80, so the two families never collide even though
// they share the permutation and the rate arithmetic. That shared machinery is
// the `sponge` type in sha3.go; this file supplies the suffix and the squeeze
// loop, and nothing else.
//
// There is no CPACF path here on purpose. The hardware has it — KIMD/KLMD
// function codes 36 and 37 are SHAKE128 and SHAKE256 (MSA-6), and the Query
// bitmap on this machine reports both — but the Linux kernel registers no
// shake128/shake256 algorithm with the crypto API (grep -c shake /proc/crypto
// returns 0), so there is no AF_ALG driver to reach the instruction through.
// Reporting a hardware number would mean writing an out-of-line CPACF caller in
// assembly, which is a different piece of work; inventing one here would be
// worse than not having it.

import (
	"errors"
	"fmt"
	"time"
)

// shakeDomainSuffix is the FIPS 202 domain-separation suffix for the
// extendable-output functions: the four-bit suffix 1111 followed by the first
// padding bit, i.e. 0x1F. SHA-3 uses 0x06 instead; see sha3DomainSuffix.
const shakeDomainSuffix = 0x1F

// SHAKEVariant identifies one of the two standardised XOF security levels.
type SHAKEVariant int

const (
	SHAKE128 SHAKEVariant = 128
	SHAKE256 SHAKEVariant = 256
)

// rate returns the sponge rate in bytes: 200 minus twice the security strength.
// SHAKE128 is 168 bytes and SHAKE256 is 136, matching SHA3-224 and SHA3-256
// respectively because the rate depends only on the capacity.
func (v SHAKEVariant) rate() int { return 200 - 2*int(v)/8 }

// SecurityStrength returns the security strength in bits (128 or 256).
func (v SHAKEVariant) SecurityStrength() int { return int(v) }

// Size returns the conventional output length in bytes: 32 for SHAKE128 and 64
// for SHAKE256, i.e. twice the security strength.
//
// This is NOT a hash.Hash size, because a SHAKE output is unbounded — there is
// no fixed digest length to report. It is the length a caller should use when
// they want a drop-in replacement for a hash of the matching security level
// (SHAKE128 -> SHA3-256's 32 bytes, SHAKE256 -> SHA3-512's 64 bytes), and it is
// what Sum(nil-length) would default to if it had a default. Sum and Squeeze
// always take an explicit length.
func (v SHAKEVariant) Size() int { return int(v) / 4 }

// String returns "SHAKE128" or "SHAKE256".
func (v SHAKEVariant) String() string {
	switch v {
	case SHAKE128:
		return "SHAKE128"
	case SHAKE256:
		return "SHAKE256"
	}
	return fmt.Sprintf("SHAKE%d", int(v))
}

// KernelName returns the /proc/crypto name for this XOF, or "" if the variant is
// not one of the two standardised ones.
//
// The name is the join key the rest of the project uses to look a variant up in
// the kernel crypto report. On current kernels the lookup simply misses for
// SHAKE, which is the finding SHAKEKernelInfo records rather than an error.
func (v SHAKEVariant) KernelName() string {
	switch v {
	case SHAKE128:
		return "shake128"
	case SHAKE256:
		return "shake256"
	}
	return ""
}

// ErrSHAKESqueezing is returned by Write once output has been read from the
// sponge.
//
// Absorbing and squeezing share the same state and the same buffer, and the
// padding step is destructive, so interleaving them cannot produce a defined
// result. FIPS 202 defines a SHAKE computation as "absorb everything, then
// squeeze"; refusing the interleaving is more useful than silently returning
// bytes that belong to neither message.
var ErrSHAKESqueezing = errors.New("shake: cannot absorb after squeezing has started; call Reset")

// SHAKE is a pure-Go extendable-output function. It streams its output through
// Read (io.Reader) or Squeeze, and Sum produces output without consuming any of
// the stream.
type SHAKE struct {
	sp      sponge
	variant SHAKEVariant

	// squeezing is set once the domain separation has been applied and the
	// state has been permuted for the last time; from then on the sponge only
	// produces output.
	squeezing bool
	// outPos is how much of the current output block in sp.buf has been handed
	// out. When it reaches sp.rate the block is exhausted and the next read
	// permutes the state to get a fresh one.
	outPos int
}

// NewSHAKE returns a SHAKE for the requested variant.
func NewSHAKE(v SHAKEVariant) *SHAKE {
	return &SHAKE{sp: sponge{rate: v.rate()}, variant: v}
}

// NewSHAKE128 returns a SHAKE128 XOF: 128-bit security, 168-byte rate.
func NewSHAKE128() *SHAKE { return NewSHAKE(SHAKE128) }

// NewSHAKE256 returns a SHAKE256 XOF: 256-bit security, 136-byte rate.
func NewSHAKE256() *SHAKE { return NewSHAKE(SHAKE256) }

// Variant returns the security level this instance was built for.
func (s *SHAKE) Variant() SHAKEVariant { return s.variant }

// Size returns the conventional output length in bytes for this variant; see
// SHAKEVariant.Size. It is not an upper bound on how much Read can produce.
func (s *SHAKE) Size() int { return s.variant.Size() }

// BlockSize returns the sponge rate in bytes: 168 for SHAKE128, 136 for
// SHAKE256. It is the absorb block size and also the output block size, because
// both are the rate.
func (s *SHAKE) BlockSize() int { return s.sp.rate }

// String returns the variant name.
func (s *SHAKE) String() string { return s.variant.String() }

// Reset returns the XOF to the empty-message state, ready to absorb a new
// message.
func (s *SHAKE) Reset() {
	s.sp.reset()
	s.squeezing = false
	s.outPos = 0
}

// Write absorbs p into the sponge.
//
// It returns ErrSHAKESqueezing if output has already been read: the padded
// state cannot take more input. Call Reset to start a new message.
func (s *SHAKE) Write(p []byte) (int, error) {
	if s.squeezing {
		return 0, ErrSHAKESqueezing
	}
	s.sp.write(p)
	return len(p), nil
}

// startSqueeze applies the domain separation and padding, then makes the first
// output block available.
//
// The padding step permutes the state, so that permutation is the one that
// produces the first output block — no extra permutation is needed or wanted.
// outPos starts at 0 to say "this block is fresh and untouched".
func (s *SHAKE) startSqueeze() {
	if s.squeezing {
		return
	}
	s.sp.pad(shakeDomainSuffix)
	s.sp.squeezeBlock()
	s.squeezing = true
	s.outPos = 0
}

// read fills dst from the output stream, permuting as each rate-sized block is
// exhausted.
func (s *SHAKE) read(dst []byte) {
	if len(dst) == 0 {
		return
	}
	s.startSqueeze()
	for len(dst) > 0 {
		if s.outPos == s.sp.rate {
			// The block has been handed out in full; only now is a new
			// permutation due. Doing it eagerly on the last byte of the block
			// would still be correct, but it would also burn a permutation for
			// callers that read exactly one block.
			keccakF1600(&s.sp.state)
			s.sp.squeezeBlock()
			s.outPos = 0
		}
		n := copy(dst, s.sp.buf[s.outPos:s.sp.rate])
		s.outPos += n
		dst = dst[n:]
	}
}

// Read fills p with the next len(p) bytes of the output stream.
//
// A SHAKE stream never ends, so Read never returns io.EOF and always returns
// len(p). That makes io.ReadFull and io.Copy work directly, and it means a
// caller asking for more output than they need is not an error. Reading in
// chunks of any size produces the same bytes as one large read.
func (s *SHAKE) Read(p []byte) (int, error) {
	s.read(p)
	return len(p), nil
}

// Squeeze returns the next n bytes of the output stream and advances the
// stream, so two consecutive calls return consecutive slices of the same
// output. n may be any non-negative length, including 0 and lengths that are
// not multiples of the rate or of the 8-byte lane size.
func (s *SHAKE) Squeeze(n int) []byte {
	if n < 0 {
		return nil
	}
	out := make([]byte, n)
	s.read(out)
	return out
}

// Sum returns n bytes of output without advancing the stream: the state is
// copied first, so a caller can Write, Sum, Write again and Sum again, exactly
// as hash.Hash.Sum allows for a fixed-output digest.
//
// Calling Sum after Read continues from the current position in the stream
// rather than restarting it, because that is the same "peek without consuming"
// rule applied to a stream.
func (s *SHAKE) Sum(n int) []byte {
	if n < 0 {
		return nil
	}
	dup := *s
	return dup.Squeeze(n)
}

// SHAKESum is the one-shot helper: absorb msg, squeeze n bytes.
func SHAKESum(v SHAKEVariant, msg []byte, n int) []byte {
	s := NewSHAKE(v)
	_, _ = s.Write(msg)
	return s.Squeeze(n)
}

// SHAKEVector is one known-answer case for a SHAKE XOF.
//
// OutLen is explicit because it is part of the test vector: the same message at
// two output lengths is two different expectations, and a XOF that ignored the
// length would pass one and fail the other.
type SHAKEVector struct {
	Variant SHAKEVariant
	Name    string
	// Input is a hex string, except when Repeat > 0, in which case the input is
	// the single byte in RepeatByte repeated Repeat times. The million-'a'
	// cases follow the same convention as NISTSHA3Vectors so that the table does
	// not carry a 1 MB literal.
	Input      string
	RepeatByte byte
	Repeat     int
	// OutLen is how many bytes of the output stream the case asserts.
	OutLen int
	// Output is the expected hex of those OutLen bytes.
	Output string
}

// NISTSHAKEVectors holds the FIPS 202 SHAKE known-answer cases.
//
// Every value below was generated twice on the target machine before being
// committed: once with Python's hashlib and once with `openssl dgst
// -shake128/-shake256 -xoflen N` (OpenSSL 3.0.2). Two independent
// implementations agreeing rules out a transcription error; a failure here
// therefore points at the squeeze state machine or the 0x1F suffix, not at a
// mistyped constant.
//
// The 200-byte SHAKE128 case is the important one structurally: it is longer
// than the 168-byte rate, so it cannot be satisfied by a single permutation and
// a truncation. It is what distinguishes an XOF from a hash.
var NISTSHAKEVectors = []SHAKEVector{
	{
		Variant: SHAKE128, Name: "SHAKE128(empty, 32 bytes)", OutLen: 32,
		Output: "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26",
	},
	{
		Variant: SHAKE128, Name: "SHAKE128(abc, 16 bytes)", Input: "616263", OutLen: 16,
		Output: "5881092dd818bf5cf8a3ddb793fbcba7",
	},
	{
		Variant: SHAKE128, Name: "SHAKE128(abc, 64 bytes)", Input: "616263", OutLen: 64,
		Output: "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8" +
			"44c50af32acd3f2cdd066568706f509bc1bdde58295dae3f891a9a0fca578378",
	},
	{
		Variant: SHAKE256, Name: "SHAKE256(empty, 32 bytes)", OutLen: 32,
		Output: "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f",
	},
	{
		Variant: SHAKE256, Name: "SHAKE256(abc, 64 bytes)", Input: "616263", OutLen: 64,
		Output: "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739" +
			"d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4",
	},
	{
		// Longer than the 168-byte rate: forces a second permutation during
		// squeeze, and is the vector that fails first if the squeeze loop
		// forgets to permute between blocks.
		Variant: SHAKE128, Name: "SHAKE128(empty, 200 bytes > rate)", OutLen: 200,
		Output: "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26" +
			"3cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e2" +
			"35b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2" +
			"badfd6dfaac359a5efbb7bcc4b59d538df9a04302e10c8bc1cbf1a0b3a5120ea" +
			"17cda7cfad765f5623474d368ccca8af0007cd9f5e4c849f167a580b14aabdef" +
			"aee7eef47cb0fca9767be1fda69419dfb927e9df07348b196691abaeb580b32d" +
			"ef58538b8d23f877",
	},
	{
		// Longer than the 136-byte SHAKE256 rate, so both XOFs are anchored by
		// an external vector that crosses a permutation boundary during squeeze.
		Variant: SHAKE256, Name: "SHAKE256(empty, 200 bytes > rate)", OutLen: 200,
		Output: "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f" +
			"d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be" +
			"141e96616fb13957692cc7edd0b45ae3dc07223c8e92937bef84bc0eab862853" +
			"349ec75546f58fb7c2775c38462c5010d846c185c15111e595522a6bcd16cf86" +
			"f3d122109e3b1fdd943b6aec468a2d621a7c06c6a957c62b54dafc3be87567d6" +
			"77231395f6147293b68ceab7a9e0c58d864e8efde4e1b9a46cbe854713672f5c" +
			"aaae314ed9083dab",
	},
	{
		Variant: SHAKE128, Name: "SHAKE128(1,000,000 x 'a', 32 bytes)",
		RepeatByte: 'a', Repeat: 1000000, OutLen: 32,
		Output: "9d222c79c4ff9d092cf6ca86143aa411e369973808ef97093255826c5572ef58",
	},
	{
		Variant: SHAKE256, Name: "SHAKE256(1,000,000 x 'a', 64 bytes)",
		RepeatByte: 'a', Repeat: 1000000, OutLen: 64,
		Output: "3578a7a4ca9137569cdf76ed617d31bb994fca9c1bbf8b184013de8234dfd13a" +
			"3fd124d4df76c0a539ee7dd2f6e1ec346124c815d9410e145eb561bcd97b18ab",
	},
}

// VectorInput materialises the message bytes for a SHAKE vector.
func (v SHAKEVector) VectorInput() []byte {
	return vectorInput(v.Input, v.RepeatByte, v.Repeat)
}

// VerifySHAKEVectors checks every known-answer case against the pure-Go XOF and
// returns the number that passed.
func VerifySHAKEVectors() (int, error) {
	passed := 0
	for _, v := range NISTSHAKEVectors {
		got := SHAKESum(v.Variant, v.VectorInput(), v.OutLen)
		if hexEncode(got) != v.Output {
			return passed, fmt.Errorf("%s: got %s want %s", v.Name, hexEncode(got), v.Output)
		}
		passed++
	}
	return passed, nil
}

// SHAKEDigestResult is the measured throughput for one XOF.
type SHAKEDigestResult struct {
	Variant    string  `json:"variant"`
	BlockSize  int     `json:"block_size"`
	OutLen     int     `json:"out_len"`
	MBps       float64 `json:"mbps"`
	Iterations int     `json:"iterations"`
	Backend    string  `json:"backend"`
	Error      string  `json:"error,omitempty"`
}

// BenchmarkSHAKE measures pure-Go SHAKE throughput for one variant.
//
// It measures the same thing BenchmarkSHA3 measures for a fixed-output digest:
// absorb blockSize bytes, then squeeze a conventional digest's worth of output
// (32 bytes for SHAKE128, 64 for SHAKE256). That keeps the number directly
// comparable to the SHA-3 rows, which squeeze their own digest length.
//
// There is no AF_ALG counterpart. KIMD function codes 36/37 exist in the
// hardware, but the kernel registers no shake128/shake256 algorithm, so
// there is no kernel path to measure — see the file comment.
func BenchmarkSHAKE(v SHAKEVariant, blockSize, iterations int) (SHAKEDigestResult, error) {
	res := SHAKEDigestResult{
		Variant:    v.String(),
		BlockSize:  blockSize,
		OutLen:     v.Size(),
		Iterations: iterations,
		Backend:    "pure-go",
	}
	if blockSize <= 0 || iterations <= 0 {
		return res, errors.New("shake: block size and iterations must be positive")
	}

	data := make([]byte, blockSize)
	for i := range data {
		data[i] = byte((i * 7) % 251)
	}
	out := make([]byte, v.Size())

	s := NewSHAKE(v)
	t0 := time.Now()
	for i := 0; i < iterations; i++ {
		s.Reset()
		if _, err := s.Write(data); err != nil {
			return res, fmt.Errorf("shake: write: %w", err)
		}
		s.read(out)
	}
	dur := time.Since(t0).Seconds()

	totalMB := float64(blockSize) * float64(iterations) / (1024 * 1024)
	res.MBps = totalMB / dur
	return res, nil
}

// SHAKESuite measures both XOFs at one buffer size.
func SHAKESuite(blockSize, iterations int) []SHAKEDigestResult {
	variants := []SHAKEVariant{SHAKE128, SHAKE256}
	out := make([]SHAKEDigestResult, 0, len(variants))
	for _, v := range variants {
		r, err := BenchmarkSHAKE(v, blockSize, iterations)
		if err != nil {
			r.Error = err.Error()
		}
		out = append(out, r)
	}
	return out
}

// SHAKEKernelInfo reports whether the kernel exposes an AF_ALG algorithm for
// this XOF.
//
// It exists to record a negative result honestly. The CPACF instruction set has
// SHAKE (KIMD/KLMD function codes 36 and 37, MSA-6) and the Query bitmap can
// prove the silicon implements it, but userspace cannot reach it through AF_ALG
// unless the kernel registers a driver — and it does not. Keeping the check in
// code rather than in a comment means the day a kernel gains the driver, the
// report says so instead of repeating a stale claim.
type SHAKEKernelInfo struct {
	// KernelDriver is the /proc/crypto driver name, empty when none is
	// registered.
	KernelDriver string `json:"kernel_driver"`
	// KernelPriority is that driver's priority; CPACF drivers register at 300.
	KernelPriority int `json:"kernel_priority"`
	// Hardware is true when the driver name ends in "-s390", the naming
	// convention every CPACF crypto module follows.
	Hardware bool `json:"hardware"`
	// AFALGAvailable is true when a hash socket for the algorithm could be
	// opened and used.
	AFALGAvailable bool `json:"af_alg_available"`
	// Error explains a missing driver or a failed AF_ALG probe.
	Error string `json:"error,omitempty"`
}

// SHAKEKernelInfoFor reads /proc/crypto for one XOF and, when a driver is
// present, checks that AF_ALG can open a hash socket for it.
func SHAKEKernelInfoFor(v SHAKEVariant) SHAKEKernelInfo {
	info := SHAKEKernelInfo{}
	name := v.KernelName()
	if name == "" {
		info.Error = "unknown SHAKE variant"
		return info
	}

	report := detectKernelCryptoFor(name)
	alg, ok := report[name]
	if !ok {
		info.Error = "no driver registered for " + name
		return info
	}
	info.KernelDriver = alg.Driver
	info.KernelPriority = alg.Priority
	info.Hardware = alg.Hardware
	if !info.Hardware {
		return info
	}
	if err := probeAFALGHash(name); err != nil {
		info.Error = "AF_ALG probe: " + err.Error()
		return info
	}
	info.AFALGAvailable = true
	return info
}

// SHAKEKernelDrivers returns the kernel report for both XOFs.
func SHAKEKernelDrivers() []SHAKEKernelInfo {
	return []SHAKEKernelInfo{
		SHAKEKernelInfoFor(SHAKE128),
		SHAKEKernelInfoFor(SHAKE256),
	}
}
