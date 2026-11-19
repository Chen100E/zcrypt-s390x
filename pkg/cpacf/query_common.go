package cpacf

// This file holds the platform-independent half of the CPACF Query machinery:
// the function-code constants, the bitmap type and the result struct. The
// instruction invocation itself lives in query_s390x.s / query_s390x.go, with a
// stub in query_other.go so that the package builds and tests on amd64/arm64.

// Function codes for the cipher-message family. The values are defined by
// z/Architecture Principles of Operation (SA22-7832) and are identical across
// KM, KMC, KMCTR, KMO and KMF for the AES entries. They were cross-checked
// against IBM s390-tools rust/cpacfinfo/src/msa.rs, the OpenSSL
// OPENSSL_s390xcap(3) manual page and the Go runtime's internal/cpu package.
const (
	FuncKMQuery  = 0  // Query function, valid for every instruction family
	FuncKMAES128 = 18 // KM/KMC/KMCTR/KMO/KMF-AES-128 (MSA-1)
	FuncKMAES192 = 19 // KM/KMC/KMCTR/KMO/KMF-AES-192 (MSA-2)
	FuncKMAES256 = 20 // KM/KMC/KMCTR/KMO/KMF-AES-256 (MSA-2)
	FuncKMXTS128 = 50 // KM-XTS-AES-128 (MSA-4)
	FuncKMXTS256 = 52 // KM-XTS-AES-256 (MSA-4)

	FuncKIMDSHA1     = 1  // KIMD/KLMD-SHA-1 (MSA)
	FuncKIMDSHA256   = 2  // KIMD/KLMD-SHA-256 (MSA)
	FuncKIMDSHA512   = 3  // KIMD/KLMD-SHA-512 (MSA)
	FuncKIMDSHA3_224 = 32 // KIMD/KLMD-SHA3-224 (MSA-6)
	FuncKIMDSHA3_256 = 33 // KIMD/KLMD-SHA3-256 (MSA-6)
	FuncKIMDSHA3_384 = 34 // KIMD/KLMD-SHA3-384 (MSA-6)
	FuncKIMDSHA3_512 = 35 // KIMD/KLMD-SHA3-512 (MSA-6)
	FuncKIMDSHAKE128 = 36 // KIMD/KLMD-SHAKE-128 (MSA-6)
	FuncKIMDSHAKE256 = 37 // KIMD/KLMD-SHAKE-256 (MSA-6)
	FuncKIMDGHASH    = 65 // KIMD-GHASH (MSA-4)

	FuncKMAAES128 = 18 // KMA-GCM-AES-128 (MSA-8)
	FuncKMAAES192 = 19 // KMA-GCM-AES-192 (MSA-8)
	FuncKMAAES256 = 20 // KMA-GCM-AES-256 (MSA-8)

	// KMCTR uses the same AES function codes as KM/KMC; the aliases exist only
	// so that call sites read clearly.
	FuncKMCTRAES128 = FuncKMAES128
	FuncKMCTRAES192 = FuncKMAES192
	FuncKMCTRAES256 = FuncKMAES256

	FuncKDSAVerifyP256 = 1  // KDSA-ECDSA-Verify-P256 (MSA-9)
	FuncKDSAVerifyP384 = 2  // KDSA-ECDSA-Verify-P384 (MSA-9)
	FuncKDSAVerifyP521 = 3  // KDSA-ECDSA-Verify-P521 (MSA-9)
	FuncKDSASignP256   = 9  // KDSA-ECDSA-Sign-P256 (MSA-9)
	FuncKDSASignP384   = 10 // KDSA-ECDSA-Sign-P384 (MSA-9)
	FuncKDSASignP521   = 11 // KDSA-ECDSA-Sign-P521 (MSA-9)

	// EdDSA codes. Unlike ECDSA, sign and verify are adjacent: 32 signs and 33
	// verifies Ed25519, 34/35 do the same for Ed448. The asymmetry with the
	// ECDSA layout (verify 1..3, sign 9..11) is a property of the instruction,
	// not a transcription error, which is why the query bitmap has to be
	// consulted per operation rather than per curve.
	FuncKDSASignEd25519   = 32 // KDSA-EdDSA-Sign-Ed25519 (MSA-9)
	FuncKDSAVerifyEd25519 = 33 // KDSA-EdDSA-Verify-Ed25519 (MSA-9)
	FuncKDSASignEd448     = 34 // KDSA-EdDSA-Sign-Ed448 (MSA-9)
	FuncKDSAVerifyEd448   = 35 // KDSA-EdDSA-Verify-Ed448 (MSA-9)

	FuncQAI = 127 // Query Authentication Information (MSA-13)
)

// FunctionBitmap is the 16-byte parameter block returned by a CPACF Query.
// Bit numbering follows z/Architecture: bit 0 is the leftmost bit of byte 0, so
// function code n lives in byte n/8 at mask 0x80>>(n%8).
type FunctionBitmap [16]byte

// Has reports whether the given function code is present in the bitmap.
func (b FunctionBitmap) Has(fc uint) bool {
	if fc >= 128 {
		return false
	}
	return b[fc/8]&(0x80>>(fc%8)) != 0
}

// Available reports whether the instruction itself is implemented, which is
// signalled by the Query function code (0) being present.
func (b FunctionBitmap) Available() bool {
	return b.Has(FuncKMQuery)
}

// Count returns the number of function codes set in the bitmap. It is used for
// the "N functions available" summary in the human-readable report.
func (b FunctionBitmap) Count() int {
	n := 0
	for _, v := range b {
		for v != 0 {
			n += int(v & 1)
			v >>= 1
		}
	}
	return n
}

// Query holds the live CPACF Query results for the instruction families that
// the Go assembler can encode.
type Query struct {
	Available bool   `json:"available"`
	Error     string `json:"error,omitempty"`

	KM    FunctionBitmap `json:"km"`
	KMC   FunctionBitmap `json:"kmc"`
	KMCTR FunctionBitmap `json:"kmctr"`
	KMA   FunctionBitmap `json:"kma"`
	KIMD  FunctionBitmap `json:"kimd"`
	KLMD  FunctionBitmap `json:"klmd"`
	KDSA  FunctionBitmap `json:"kdsa"`
}

// HasQAI reports whether the MSA-13 Query Authentication Information function
// is implemented, which is the marker for z17-class firmware.
func (q Query) HasQAI() bool {
	return q.KMA.Has(FuncQAI)
}
