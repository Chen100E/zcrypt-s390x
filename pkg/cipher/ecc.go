package cipher

// ECC signing for s390x.
//
// MSA-9 added the KDSA (Compute Digital Signature Authentication) instruction,
// which performs ECDSA and EdDSA sign/verify on chip. The target machine reports
// MSA-13, so every curve below takes the hardware path. This file measures that
// path and documents what Go actually does with it.
//
// The Go 1.23 wiring, read from crypto/ecdsa/ecdsa_s390x.go on the target
// machine:
//
//	crypto/ecdsa.Sign      -> signAsm  -> KDSA function code 9  (P-256) / 10 (P-384) / 11 (P-521)
//	crypto/ecdsa.Verify    -> verifyAsm -> KDSA function code 1  (P-256) /  2 (P-384) /  3 (P-521)
//	crypto/ed25519.Sign    -> KDSA function code 32 (Ed25519 sign)
//	crypto/ed25519.Verify  -> KDSA function code 33 (Ed25519 verify)
//
// The function codes are not symmetric between sign and verify: verify codes
// run 1..3 in curve order and sign codes run 9..11, and EdDSA sits at 32/33.
// That layout is why the CPACF Query bitmap has to be consulted per operation
// rather than per curve: a machine can implement KDSA-Verify-P256 without
// KDSA-Sign-P256.
//
// The dispatch is gated on internal/cpu.S390X.HasECDSA and HasEDDSA, which the
// runtime derives from the KDSA Query instruction. Where the bits are clear, Go
// falls back to the portable big.Int and edwards25519 code, which is roughly two
// orders of magnitude slower -- so a machine that quietly loses the facility
// bits shows up in these numbers immediately.

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/Chen100E/zcrypt-s390x/pkg/cpacf"
)

// CurveKind names an elliptic curve ZCrypt benchmarks.
type CurveKind string

const (
	CurveP256    CurveKind = "P-256"
	CurveP384    CurveKind = "P-384"
	CurveP521    CurveKind = "P-521"
	CurveEd25519 CurveKind = "Ed25519"
)

// CurveInfo documents how one curve maps onto KDSA.
type CurveInfo struct {
	Curve       CurveKind `json:"curve"`
	Algorithm   string    `json:"algorithm"`
	SignCode    uint      `json:"kdsa_sign_function_code"`
	VerifyCode  uint      `json:"kdsa_verify_function_code"`
	MSALevel    int       `json:"msa_level"`
	Digest      string    `json:"digest"`
	PublicBytes int       `json:"public_key_bytes"`
	PrivateBits int       `json:"private_key_bits"`
	Notes       string    `json:"notes"`
}

// CurveTable is the curve-to-KDSA-function-code mapping.
//
// The codes match cpacf.FuncKDSASignP256 and friends, and the Ed25519 entries
// are the values internal/cpu uses (32 sign, 33 verify) taken from the Go
// runtime's own table.
var CurveTable = []CurveInfo{
	{
		Curve:       CurveP256,
		Algorithm:   "ECDSA",
		SignCode:    cpacf.FuncKDSASignP256,
		VerifyCode:  cpacf.FuncKDSAVerifyP256,
		MSALevel:    9,
		Digest:      "SHA-256",
		PublicBytes: 64,
		PrivateBits: 256,
		Notes:       "one KDSA instruction per operation; the parameter block is 4096 bytes so the sign path zeroes it each call",
	},
	{
		Curve:       CurveP384,
		Algorithm:   "ECDSA",
		SignCode:    cpacf.FuncKDSASignP384,
		VerifyCode:  cpacf.FuncKDSAVerifyP384,
		MSALevel:    9,
		Digest:      "SHA-384",
		PublicBytes: 96,
		PrivateBits: 384,
		Notes:       "same instruction, wider parameter block",
	},
	{
		Curve:       CurveP521,
		Algorithm:   "ECDSA",
		SignCode:    cpacf.FuncKDSASignP521,
		VerifyCode:  cpacf.FuncKDSAVerifyP521,
		MSALevel:    9,
		Digest:      "SHA-512",
		PublicBytes: 132,
		PrivateBits: 521,
		Notes:       "521 bits is not a whole number of bytes, so the hash is truncated to 66 bytes before KDSA sees it",
	},
	{
		Curve:       CurveEd25519,
		Algorithm:   "EdDSA",
		SignCode:    cpacf.FuncKDSASignEd25519,
		VerifyCode:  cpacf.FuncKDSAVerifyEd25519,
		MSALevel:    9,
		Digest:      "SHA-512 (internal to Ed25519)",
		PublicBytes: 32,
		PrivateBits: 256,
		Notes:       "Ed25519 hashes internally, so there is no separate digest step to measure",
	},
}

// LookupCurve returns the documentation entry for a curve.
func LookupCurve(c CurveKind) (CurveInfo, bool) {
	for _, info := range CurveTable {
		if info.Curve == c {
			return info, true
		}
	}
	return CurveInfo{}, false
}

// SignatureResult is the measured cost of signing and verifying on one curve.
//
// The units are operations per second rather than bytes per second, because a
// signature is a fixed amount of work: there is no buffer size to sweep.
type SignatureResult struct {
	Curve        CurveKind `json:"curve"`
	Algorithm    string    `json:"algorithm"`
	SignPerSec   float64   `json:"sign_per_sec"`
	VerifyPerSec float64   `json:"verify_per_sec"`
	SignCount    int       `json:"sign_count"`
	VerifyCount  int       `json:"verify_count"`
	SignNanosOp  float64   `json:"sign_nanos_per_op"`
	VerifyNanos  float64   `json:"verify_nanos_per_op"`
	SignCode     uint      `json:"kdsa_sign_function_code"`
	VerifyCode   uint      `json:"kdsa_verify_function_code"`
	Verified     bool      `json:"round_trip_verified"`
	Error        string    `json:"error,omitempty"`
}

// SignBenchmark measures sign and verify throughput for one curve.
//
// Every signature produced is verified before its timing is counted, so a curve
// whose hardware path returns malformed signatures cannot post a fast number.
// The verify loop reuses one signature and one digest: the point is to measure
// the verification arithmetic, not key handling.
func SignBenchmark(curve CurveKind, iterations int) (SignatureResult, error) {
	res := SignatureResult{Curve: curve, SignCount: iterations, VerifyCount: iterations}
	info, ok := LookupCurve(curve)
	if !ok {
		return res, fmt.Errorf("ecc: unknown curve %q", curve)
	}
	res.Algorithm = info.Algorithm
	res.SignCode = info.SignCode
	res.VerifyCode = info.VerifyCode
	if iterations <= 0 {
		return res, errors.New("ecc: iterations must be positive")
	}

	switch curve {
	case CurveEd25519:
		return signBenchmarkEd25519(res, iterations)
	case CurveP256, CurveP384, CurveP521:
		return signBenchmarkECDSA(res, curve, iterations)
	}
	return res, fmt.Errorf("ecc: unhandled curve %q", curve)
}

// digestFor returns the message digest a curve signs, plus the message itself.
func digestFor(c CurveKind) (msg, digest []byte) {
	msg = []byte("zcrypt-s390x KDSA signature benchmark message, fixed length so the digest cost is constant")
	switch c {
	case CurveP256:
		d := sha256.Sum256(msg)
		return msg, d[:]
	case CurveP384:
		d := sha512.Sum384(msg)
		return msg, d[:]
	default: // P-521 and anything wider
		d := sha512.Sum512(msg)
		return msg, d[:]
	}
}

func signBenchmarkECDSA(res SignatureResult, curve CurveKind, iterations int) (SignatureResult, error) {
	var ec elliptic.Curve
	switch curve {
	case CurveP256:
		ec = elliptic.P256()
	case CurveP384:
		ec = elliptic.P384()
	case CurveP521:
		ec = elliptic.P521()
	}

	priv, err := ecdsa.GenerateKey(ec, rand.Reader)
	if err != nil {
		return res, fmt.Errorf("ecc: generate %s key: %w", curve, err)
	}
	_, digest := digestFor(curve)

	// --- sign ---
	// The digest is precomputed so the timing isolates the signature operation.
	// ecdsa.Sign takes the digest directly, which is exactly the KDSA call.
	var sig []byte
	t0 := time.Now()
	for i := 0; i < iterations; i++ {
		r, s, err := ecdsa.Sign(rand.Reader, priv, digest)
		if err != nil {
			return res, fmt.Errorf("ecc: sign %s iteration %d: %w", curve, i, err)
		}
		// Encode once on the last iteration only; the other iterations exist
		// purely to keep the pipeline hot. r and s are still computed every
		// time, so the KDSA instruction is issued on every pass.
		if i == iterations-1 {
			sig = encodeECDSASignature(r, s, curve)
		}
	}
	signDur := time.Since(t0)
	res.SignNanosOp = float64(signDur.Nanoseconds()) / float64(iterations)
	res.SignPerSec = float64(iterations) / signDur.Seconds()

	// Correctness gate: the signature must verify under the matching public key.
	if len(sig) == 0 {
		return res, errors.New("ecc: no signature produced")
	}
	if !verifyEncodedECDSA(&priv.PublicKey, digest, sig, curve) {
		return res, fmt.Errorf("ecc: %s signature failed to verify under its own public key", curve)
	}

	// --- verify ---
	t1 := time.Now()
	for i := 0; i < iterations; i++ {
		if !verifyEncodedECDSA(&priv.PublicKey, digest, sig, curve) {
			return res, fmt.Errorf("ecc: verify %s iteration %d failed", curve, i)
		}
	}
	verifyDur := time.Since(t1)
	res.VerifyNanos = float64(verifyDur.Nanoseconds()) / float64(iterations)
	res.VerifyPerSec = float64(iterations) / verifyDur.Seconds()
	res.Verified = true
	return res, nil
}

func signBenchmarkEd25519(res SignatureResult, iterations int) (SignatureResult, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return res, fmt.Errorf("ecc: generate Ed25519 key: %w", err)
	}
	msg := []byte("zcrypt-s390x KDSA signature benchmark message, fixed length so the digest cost is constant")

	var sig []byte
	t0 := time.Now()
	for i := 0; i < iterations; i++ {
		s := ed25519.Sign(priv, msg)
		if i == iterations-1 {
			sig = s
		}
	}
	signDur := time.Since(t0)
	res.SignNanosOp = float64(signDur.Nanoseconds()) / float64(iterations)
	res.SignPerSec = float64(iterations) / signDur.Seconds()

	if len(sig) != ed25519.SignatureSize {
		return res, fmt.Errorf("ecc: Ed25519 signature is %d bytes, want %d", len(sig), ed25519.SignatureSize)
	}
	if !ed25519.Verify(pub, msg, sig) {
		return res, errors.New("ecc: Ed25519 signature failed to verify under its own public key")
	}

	t1 := time.Now()
	for i := 0; i < iterations; i++ {
		if !ed25519.Verify(pub, msg, sig) {
			return res, fmt.Errorf("ecc: Ed25519 verify iteration %d failed", i)
		}
	}
	verifyDur := time.Since(t1)
	res.VerifyNanos = float64(verifyDur.Nanoseconds()) / float64(iterations)
	res.VerifyPerSec = float64(iterations) / verifyDur.Seconds()
	res.Verified = true
	return res, nil
}

// encodeECDSASignature serialises r and s as fixed-width big-endian integers.
//
// Fixed width matters: a variable-length encoding would make the signature size
// depend on the leading zero bytes of r and s, which is a real side channel and
// also makes "the signature is N bytes" untestable. The width is the curve's
// field size in bytes, so a P-256 signature is always 64 bytes and a P-521
// signature is always 132.
func encodeECDSASignature(r, s *big.Int, curve CurveKind) []byte {
	width := signatureWidth(curve)
	out := make([]byte, 2*width)
	r.FillBytes(out[:width])
	s.FillBytes(out[width:])
	return out
}

// verifyEncodedECDSA splits a fixed-width signature and verifies it.
func verifyEncodedECDSA(pub *ecdsa.PublicKey, digest, sig []byte, curve CurveKind) bool {
	width := signatureWidth(curve)
	if width == 0 || len(sig) != 2*width {
		return false
	}
	r := new(big.Int).SetBytes(sig[:width])
	s := new(big.Int).SetBytes(sig[width:])
	return ecdsa.Verify(pub, digest, r, s)
}

// signatureWidth returns the byte width of one ECDSA signature component.
func signatureWidth(c CurveKind) int {
	switch c {
	case CurveP256:
		return 32
	case CurveP384:
		return 48
	case CurveP521:
		return 66
	}
	return 0
}

// SignSuite benchmarks every curve in the table.
func SignSuite(iterations int) []SignatureResult {
	out := make([]SignatureResult, 0, len(CurveTable))
	for _, info := range CurveTable {
		r, err := SignBenchmark(info.Curve, iterations)
		if err != nil {
			r.Curve = info.Curve
			r.Algorithm = info.Algorithm
			r.SignCode = info.SignCode
			r.VerifyCode = info.VerifyCode
			r.Error = err.Error()
		}
		out = append(out, r)
	}
	return out
}

// ECCKeyPair is a generated key pair plus the signature round-trip result.
type ECCKeyPair struct {
	Curve      CurveKind `json:"curve"`
	PublicSize int       `json:"public_key_bytes"`
	PrivateOK  bool      `json:"private_key_generated"`
}

// GenerateKeyPair produces a key pair for a curve and reports the public key
// size, which is the number that matters for certificate and handshake budgets.
func GenerateKeyPair(c CurveKind) (ECCKeyPair, error) {
	out := ECCKeyPair{Curve: c}
	switch c {
	case CurveEd25519:
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return out, err
		}
		out.PublicSize = len(pub)
		out.PrivateOK = true
		return out, nil
	case CurveP256, CurveP384, CurveP521:
		var ec elliptic.Curve
		switch c {
		case CurveP256:
			ec = elliptic.P256()
		case CurveP384:
			ec = elliptic.P384()
		case CurveP521:
			ec = elliptic.P521()
		}
		priv, err := ecdsa.GenerateKey(ec, rand.Reader)
		if err != nil {
			return out, err
		}
		out.PublicSize = len(elliptic.Marshal(ec, priv.PublicKey.X, priv.PublicKey.Y))
		out.PrivateOK = priv.D != nil && priv.D.Sign() > 0
		return out, nil
	}
	return out, fmt.Errorf("ecc: unknown curve %q", c)
}

// ECCKernelInfo reports whether the kernel registers a hardware ECDSA driver.
//
// On this machine the answer is that it does not: /proc/crypto has no "ecdsa"
// entry at all, because the kernel's akcipher ECDSA support (added in 6.x)
// registers lazily and is not exercised by default. That is an honest negative
// result and the report says so rather than implying hardware acceleration for
// every operation.
//
// The KDSA acceleration that ZCrypt measures is in the Go userspace path, which
// issues the instruction directly. It does not need the kernel to register
// anything, so the absence of an ecdsa kernel driver does not mean the numbers
// are software.
type ECCKernelInfo struct {
	Curve         CurveKind `json:"curve"`
	KernelName    string    `json:"kernel_name"`
	KernelDriver  string    `json:"kernel_driver,omitempty"`
	KernelPresent bool      `json:"kernel_driver_present"`
	KDSAUsable    bool      `json:"kdsa_usable"`
	SignCode      uint      `json:"kdsa_sign_function_code"`
	VerifyCode    uint      `json:"kdsa_verify_function_code"`
	Notes         string    `json:"notes"`
}

// ECCKernelReport inspects /proc/crypto and the CPACF KDSA bitmap for every
// curve, so the report can distinguish "no kernel driver" from "no hardware".
func ECCKernelReport() []ECCKernelInfo {
	caps := cpacf.Detect()
	query := cpacf.ProbeQuery(caps)

	out := make([]ECCKernelInfo, 0, len(CurveTable))
	for _, info := range CurveTable {
		row := ECCKernelInfo{
			Curve:      info.Curve,
			SignCode:   info.SignCode,
			VerifyCode: info.VerifyCode,
		}
		// The kernel names its ECDSA implementations by curve, e.g. "ecdsa-nist-p256".
		switch info.Curve {
		case CurveP256:
			row.KernelName = "ecdsa-nist-p256"
		case CurveP384:
			row.KernelName = "ecdsa-nist-p384"
		case CurveEd25519:
			row.KernelName = "ed25519"
		}
		if row.KernelName != "" {
			if alg, ok := detectKernelCryptoFor(row.KernelName)[row.KernelName]; ok {
				row.KernelDriver = alg.Driver
				row.KernelPresent = true
			}
		}

		// KDSA usability comes from the CPACF Query bitmap, which is the
		// authoritative statement of what the chip implements. Both the sign
		// and verify function codes must be present for the pair to be usable.
		if query.Available {
			row.KDSAUsable = query.KDSA.Has(info.SignCode) && query.KDSA.Has(info.VerifyCode)
		}
		if row.KDSAUsable {
			row.Notes = "KDSA issues directly from the Go crypto/ecdsa path; no kernel driver needed"
		} else if query.Available {
			row.Notes = "KDSA function codes absent from the Query bitmap; Go uses the portable fallback"
		} else {
			row.Notes = "CPACF unavailable on this host"
		}
		out = append(out, row)
	}
	return out
}
