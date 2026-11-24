package cipher

// AES-XTS: IEEE 1619-2007 / NIST SP 800-38E.
//
// XTS is the mode Linux uses for block-device encryption, so on a LinuxONE
// machine it is the mode that protects the disk of every guest. That is why it
// belongs in this suite even though Go's standard library does not implement
// it: crypto/cipher has no XTS, so there is no `cipher.NewXTS` to benchmark and
// the portable implementation below is genuinely new code rather than a thin
// wrapper.
//
// The two paths this file exposes are:
//
//	XTSEncrypt / XTSDecrypt   pure Go over crypto/aes. On s390x crypto/aes
//	                          lowers each AES block to CPACF KM, so this is
//	                          hardware AES driven by a software tweak loop.
//	XTSHardwareEncrypt/...    AF_ALG against "xts(aes)", which the kernel
//	                          dispatches to xts-aes-s390 at priority 402. That
//	                          driver issues KMF (Cipher Message with Fetch),
//	                          function codes 50 and 52, MSA-4.
//
// The difference between the two is exactly what this project measures: the
// first path pays for the tweak arithmetic in Go and hands the kernel one block
// at a time; the second path hands the kernel the whole data unit and KMF does
// the tweak multiply, the XOR and the cipher in one instruction.
//
// ## The tweak arithmetic is the part that is easy to get wrong
//
// XTS multiplies a 128-bit tweak by x in GF(2^128) modulo
// x^128 + x^7 + x^2 + x + 1 between blocks. The natural-looking implementation,
// a big-endian big.Int shift, is wrong: it produces correct output for
// single-block data units and wrong output for every multi-block one, because
// IEEE 1619 numbers the bits of the tweak from the least significant end of the
// 16-byte string while the cipher treats byte 0 as the most significant input
// byte. The form below is the one OpenSSL uses in crypto/modes/xts128.c
// (gf_mulx), and it is a shift *up* the byte array with the reduction constant
// XORed into byte 0.
//
// ## Ciphertext stealing
//
// A data unit that is not a multiple of 16 bytes is handled by stealing
// ciphertext from the last full block rather than by padding, so the ciphertext
// is exactly as long as the plaintext. For n full blocks and rem = len%16 > 0:
//
//	blocks 0 .. n-2   ordinary XTS blocks
//	CC      = E_k1(P_{n-1} xor T_{n-1}) xor T_{n-1}    (a full ciphertext block)
//	C*      = CC[0:rem]              (the FIRST rem bytes)
//	PP      = P_partial || CC[rem:16]
//	C_{n-1} = E_k1(PP xor T_n) xor T_n
//	output  = prefix || C_{n-1} || C*
//
// Two details are easy to get wrong and both are silent. First, CC carries the
// trailing tweak XOR: it is a ciphertext block, identical in form to every block
// the ordinary loop produces, not a raw AES output. Omitting that XOR still
// round-trips under a matching decryptor. Second, C* is the *head* of CC and it
// is written *after* C_{n-1} in the output. Getting either backwards also still
// round-trips. That is why the CAVP vectors in xts_test.go matter: a symmetric
// bug is invisible to a round-trip test and only an external vector finds it.

import (
	"crypto/aes"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

const (
	// XTSBlockSize is the AES block size, which is also the tweak size.
	XTSBlockSize = 16

	// XTSMinDataUnit is the shortest data unit XTS is defined for. A single
	// block is legal; shorter is not, because there would be nothing to steal
	// from and the construction degenerates.
	XTSMinDataUnit = XTSBlockSize

	// XTSMaxDataUnit is the largest data unit IEEE 1619 allows: 2^20 AES
	// blocks, i.e. 16 MiB. The limit exists because the tweak sequence must not
	// wrap within one data unit; dm-crypt therefore splits larger extents.
	XTSMaxDataUnit = (1 << 20) * XTSBlockSize
)

// XTSKeyInfo reports how a key is split into its two halves.
//
// XTS takes two independent AES keys: k1 encrypts the data and k2 encrypts the
// tweak. They are concatenated, so a 32-byte key is XTS-AES-128 and a 64-byte
// key is XTS-AES-256. Note the off-by-one that trips people up: XTS-AES-128 uses
// a 256-bit key. The "128" names the AES key size of each half, not the total.
type XTSKeyInfo struct {
	KeyBytes int `json:"key_bytes"`
	AESBits  int `json:"aes_bits"`
}

// XTSKeySize describes the two supported key lengths, keyed by total key bytes.
var xtsKeySizes = map[int]int{
	32: 128, // two 16-byte AES-128 keys
	64: 256, // two 32-byte AES-256 keys
}

// xtsSplitKey validates the key length and returns the two halves.
//
// XTS is defined for any pair of keys, including two identical halves, so this
// deliberately does not reject k1 == k2. OpenSSL and the kernel's skcipher layer
// refuse identical halves at their API boundary because it weakens the
// construction, but the raw algorithm has no such precondition and the NIST CAVP
// vectors do not respect it. Enforcing it here would reject valid vectors and
// make the test suite disagree with the standard, so the restriction is left to
// the caller and documented instead.
func xtsSplitKey(key []byte) (k1, k2 []byte, bits int, err error) {
	bits, ok := xtsKeySizes[len(key)]
	if !ok {
		return nil, nil, 0, fmt.Errorf(
			"xts: key must be 32 bytes (XTS-AES-128) or 64 bytes (XTS-AES-256), got %d",
			len(key))
	}
	half := len(key) / 2
	return key[:half], key[half:], bits, nil
}

// gfMulX multiplies the 16-byte tweak by x in GF(2^128) modulo
// x^128 + x^7 + x^2 + x + 1, in place.
//
// This is OpenSSL's gf_mulx from crypto/modes/xts128.c. The shift walks *up* the
// array (byte 15 is the low end of the polynomial) and the reduction constant
// 0x87 = x^7 + x^2 + x + 1 is XORed into byte 0. A big-endian big.Int shift
// looks equivalent and is not: it agrees only for one-block data units.
func gfMulX(t []byte) {
	carry := t[15] >> 7
	for i := 15; i > 0; i-- {
		t[i] = t[i]<<1 | t[i-1]>>7
	}
	t[0] <<= 1
	if carry != 0 {
		t[0] ^= 0x87
	}
}

// xorBlock writes a^b into dst. dst may alias a or b.
func xorBlock(dst, a, b []byte) {
	for i := 0; i < XTSBlockSize; i++ {
		dst[i] = a[i] ^ b[i]
	}
}

// xtsCrypt is the single implementation behind both directions.
//
// Encryption and decryption differ only in which primitive is applied to the
// tweaked block; the tweak schedule and the ciphertext-stealing layout are
// identical, which is why they share a body. Keeping one copy means a fix to the
// CTS layout cannot land in one direction only.
func xtsCrypt(key, tweak, in []byte, decrypt bool) ([]byte, error) {
	if len(tweak) != XTSBlockSize {
		return nil, fmt.Errorf("xts: tweak must be %d bytes, got %d", XTSBlockSize, len(tweak))
	}
	if len(in) < XTSMinDataUnit {
		return nil, fmt.Errorf("xts: data unit must be at least %d bytes, got %d",
			XTSMinDataUnit, len(in))
	}
	if len(in) > XTSMaxDataUnit {
		return nil, fmt.Errorf("xts: data unit of %d bytes exceeds the %d-byte maximum",
			len(in), XTSMaxDataUnit)
	}
	k1, k2, _, err := xtsSplitKey(key)
	if err != nil {
		return nil, err
	}
	c1, err := aes.NewCipher(k1)
	if err != nil {
		return nil, fmt.Errorf("xts: data key: %w", err)
	}
	c2, err := aes.NewCipher(k2)
	if err != nil {
		return nil, fmt.Errorf("xts: tweak key: %w", err)
	}

	// T_0 is the tweak encrypted under k2, not the tweak itself.
	var t [16]byte
	c2.Encrypt(t[:], tweak)

	out := make([]byte, len(in))
	n := len(in) / XTSBlockSize
	rem := len(in) % XTSBlockSize

	// With a partial tail, the last *full* block is consumed by the
	// ciphertext-stealing step below, so the ordinary loop stops one short.
	full := n
	if rem != 0 {
		full = n - 1
	}

	var ks, blk [16]byte
	for i := 0; i < full; i++ {
		off := i * XTSBlockSize
		xorBlock(ks[:], in[off:off+XTSBlockSize], t[:])
		if decrypt {
			c1.Decrypt(blk[:], ks[:])
		} else {
			c1.Encrypt(blk[:], ks[:])
		}
		xorBlock(out[off:off+XTSBlockSize], blk[:], t[:])
		gfMulX(t[:])
	}
	if rem == 0 {
		return out, nil
	}

	// --- ciphertext stealing on the final partial block ---
	//
	// At this point t holds T_{n-1}; T_n is one more doubling. Both are needed,
	// so the previous value is saved before the multiply.
	off := (n - 1) * XTSBlockSize
	var tPrev [16]byte
	copy(tPrev[:], t[:])
	gfMulX(t[:])

	if !decrypt {
		// CC is the *full* ciphertext block: E(P_{n-1} xor T_{n-1}) xor T_{n-1}.
		// The trailing XOR is not optional — the ordinary block loop above ends
		// with `out = E(in xor T) xor T`, and the stolen-ciphertext block has to
		// be the same object, because C* is a prefix of it.
		xorBlock(ks[:], in[off:off+XTSBlockSize], tPrev[:])
		c1.Encrypt(blk[:], ks[:])               // E(P_{n-1} xor T_{n-1})
		xorBlock(blk[:], blk[:], tPrev[:])      // CC = ... xor T_{n-1}
		copy(out[off+XTSBlockSize:], blk[:rem]) // C* is the head of CC, written last
		copy(ks[:rem], in[off+XTSBlockSize:])   // P_partial
		copy(ks[rem:], blk[rem:])               // CC[rem:]
		xorBlock(ks[:], ks[:], t[:])            // PP xor T_n
		c1.Encrypt(out[off:off+XTSBlockSize], ks[:])
		xorBlock(out[off:off+XTSBlockSize], out[off:off+XTSBlockSize], t[:])
		return out, nil
	}

	// PP = D(C_{n-1} xor T_n) xor T_n; P_partial = PP[:rem]; CC = C* || PP[rem:]
	xorBlock(ks[:], in[off:off+XTSBlockSize], t[:])
	c1.Decrypt(blk[:], ks[:])               // D(C_{n-1} xor T_n)
	xorBlock(blk[:], blk[:], t[:])          // PP
	copy(out[off+XTSBlockSize:], blk[:rem]) // P_partial
	copy(ks[:rem], in[off+XTSBlockSize:])   // C*
	copy(ks[rem:], blk[rem:])               // PP[rem:]
	xorBlock(ks[:], ks[:], tPrev[:])        // CC xor T_{n-1}
	c1.Decrypt(out[off:off+XTSBlockSize], ks[:])
	xorBlock(out[off:off+XTSBlockSize], out[off:off+XTSBlockSize], tPrev[:])
	return out, nil
}

// XTSEncrypt encrypts one data unit under XTS.
//
// key is 32 bytes (XTS-AES-128) or 64 bytes (XTS-AES-256); tweak is the 16-byte
// data-unit tweak, which is normally the little-endian block number for
// dm-crypt and the sector address for a disk; plaintext is the data unit and
// must be at least 16 bytes. The result is exactly len(plaintext) bytes, using
// ciphertext stealing when the length is not a multiple of 16.
//
// The tweak must be unique per (key, data unit). Reusing one leaks the XOR of
// the two plaintexts, exactly as with CTR; the function cannot detect that, so
// it is the caller's contract.
func XTSEncrypt(key, tweak, plaintext []byte) ([]byte, error) {
	return xtsCrypt(key, tweak, plaintext, false)
}

// XTSDecrypt is the inverse of XTSEncrypt.
func XTSDecrypt(key, tweak, ciphertext []byte) ([]byte, error) {
	return xtsCrypt(key, tweak, ciphertext, true)
}

// ---------------------------------------------------------------------------
// AF_ALG hardware path
// ---------------------------------------------------------------------------

// XTSKernelAlgorithm is the kernel algorithm name to bind an AF_ALG socket to.
const XTSKernelAlgorithm = "xts(aes)"

// xtsAlgorithm is the name xtsHardware binds to. It is a variable rather than a
// constant so the test suite can point it at a name the kernel does not have and
// assert the ErrXTSHardwareUnavailable contract on a host where the real
// algorithm *is* present. Relying on the absence of xts(aes) to test the absence
// path means the test only runs on the CI machines least able to say anything
// about s390x.
var xtsAlgorithm = XTSKernelAlgorithm

// ErrXTSHardwareUnavailable reports that the kernel XTS path could not be used.
var ErrXTSHardwareUnavailable = errors.New("xts: AF_ALG hardware path unavailable")

// xtsHardware runs one data unit through the kernel's xts(aes) skcipher, which
// on s390x is xts-aes-s390 and lowers to KMF.
func xtsHardware(key, tweak, in []byte, encrypt bool) ([]byte, error) {
	if len(in) < XTSMinDataUnit {
		return nil, fmt.Errorf("xts: data unit must be at least %d bytes, got %d",
			XTSMinDataUnit, len(in))
	}
	_, k2, _, err := xtsSplitKey(key)
	if err != nil {
		return nil, err
	}
	if len(tweak) != XTSBlockSize {
		return nil, fmt.Errorf("xts: tweak must be %d bytes, got %d", XTSBlockSize, len(tweak))
	}
	c, err := newAFALGSkcipher(xtsAlgorithm, key)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrXTSHardwareUnavailable, err)
	}
	defer c.Close()

	out := make([]byte, len(in))
	if err := xtsHardwareChunked(c, k2, out, in, tweak, encrypt); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrXTSHardwareUnavailable, err)
	}
	return out, nil
}

// XTSHardwareEncrypt encrypts one data unit through the kernel's xts(aes)
// driver. On s390x that is xts-aes-s390 at priority 402, issuing KMF.
//
// It returns an error wrapping ErrXTSHardwareUnavailable when AF_ALG is absent,
// the family is blocked, or no xts(aes) implementation is registered — the same
// conditions under which the caller should fall back to XTSEncrypt.
func XTSHardwareEncrypt(key, tweak, plaintext []byte) ([]byte, error) {
	return xtsHardware(key, tweak, plaintext, true)
}

// XTSHardwareDecrypt is the inverse of XTSHardwareEncrypt.
func XTSHardwareDecrypt(key, tweak, ciphertext []byte) ([]byte, error) {
	return xtsHardware(key, tweak, ciphertext, false)
}

// XTSHardwareInfo reports whether the kernel exposes a CPACF-backed XTS driver
// and whether AF_ALG can reach it.
//
// The two facts answer different questions, exactly as for SHA-3: /proc/crypto
// says which driver the kernel will use for dm-crypt, and the AF_ALG probe says
// whether this process can drive that driver itself.
type XTSHardwareInfo struct {
	// KernelDriver is the winning driver name from /proc/crypto, e.g.
	// "xts-aes-s390".
	KernelDriver string `json:"kernel_driver"`
	// KernelPriority is that driver's priority. xts-aes-s390 registers at 402;
	// the generic software fallback sits at 100.
	KernelPriority int `json:"kernel_priority"`
	// Hardware is true when the winning driver name denotes a CPACF-backed
	// implementation (the kernel names every one of them *-s390).
	Hardware bool `json:"hardware"`
	// AFALGAvailable is true when a real XTS operation through AF_ALG
	// succeeded, which is stronger than "the socket bound".
	AFALGAvailable bool `json:"af_alg_available"`
	// Alternatives lists every registered driver for xts(aes), highest
	// priority first, so the dispatch claim is auditable.
	Alternatives []string `json:"alternatives,omitempty"`
	Error        string   `json:"error,omitempty"`
}

// probeXTSSkcipher proves the AF_ALG XTS path works by encrypting and then
// decrypting one block and checking the round trip.
//
// Binding alone is not enough: on a machine where xts(aes) exists only as a
// template that cannot be instantiated, bind succeeds and the first sendmsg
// fails. The probe therefore performs a real operation, which is what
// AFALGAvailable claims.
func probeXTSSkcipher() error {
	key := make([]byte, 64)
	for i := range key {
		key[i] = byte(i*7 + 1)
	}
	tweak := make([]byte, XTSBlockSize)
	for i := range tweak {
		tweak[i] = byte(i*3 + 9)
	}
	pt := make([]byte, XTSBlockSize)
	for i := range pt {
		pt[i] = byte(i ^ 0xa5)
	}

	c, err := newAFALGSkcipher(xtsAlgorithm, key)
	if err != nil {
		return err
	}
	defer c.Close()

	ct := make([]byte, len(pt))
	if _, err := c.Crypt(ct, pt, tweak, true); err != nil {
		return err
	}
	back := make([]byte, len(pt))
	if _, err := c.Crypt(back, ct, tweak, false); err != nil {
		return err
	}
	if !bytesEqual(back, pt) {
		return errors.New("xts: AF_ALG probe round trip mismatch")
	}
	return nil
}

// XTSKernelInfo reads /proc/crypto for xts(aes) and probes the AF_ALG path.
func XTSKernelInfo() XTSHardwareInfo {
	info := XTSHardwareInfo{}
	alg, ok := detectKernelCryptoFor(XTSKernelAlgorithm)[XTSKernelAlgorithm]
	if !ok {
		info.Error = "no xts(aes) implementation registered in /proc/crypto"
	} else {
		info.KernelDriver = alg.Driver
		info.KernelPriority = alg.Priority
		info.Hardware = alg.Hardware
		info.Alternatives = alg.Alternatives
	}
	if err := probeXTSSkcipher(); err != nil {
		info.AFALGAvailable = false
		if info.Error == "" {
			info.Error = err.Error()
		}
	} else {
		info.AFALGAvailable = true
	}
	return info
}

// ---------------------------------------------------------------------------
// Known-answer tests
// ---------------------------------------------------------------------------

// XTSVector is one AES-XTS known-answer case.
type XTSVector struct {
	Name       string
	Key        string // hex, 32 or 64 bytes
	Tweak      string // hex, 16 bytes
	Plaintext  string // hex
	Ciphertext string // hex, same length as Plaintext
	// Source records where the expected ciphertext came from, so a reader can
	// tell a published NIST case from one this project generated and verified
	// against two independent implementations.
	Source string
}

// XTSVectors holds the AES-XTS known-answer cases.
//
// The first four are NIST CAVP cases taken from the official
// XTSTestVectors.zip (the "tweak value input" format, AES-XTS 128 and 256). The
// rest are ciphertext-stealing cases generated here at data-unit lengths the
// published set does not cover densely, and each was confirmed against *both*
// OpenSSL (via Python's cryptography package) and the kernel's xts-aes-s390
// driver before being committed. A vector that only agrees with this
// implementation proves nothing about this implementation.
//
// Every case below was additionally checked in the decrypt direction against
// both oracles. The 25-, 30- and 17-byte cases exist specifically to pin the
// ciphertext-stealing layout: C* is the head of CC and it is written after
// C_{n-1}, and a self-consistent mistake in either of those still round-trips.
var XTSVectors = []XTSVector{
	{
		Name:       "CAVP-XTS-AES256-32B",
		Key:        "1ea661c58d943a0e4801e42f4b0947149e7f9f8e3e68d0c7505210bd311a0e7cd6e13ffdf2418d8d1911c004cda58da3d619b7e2b9141e58318eea392cf41b08",
		Tweak:      "adf8d92627464ad2f0428e84a9f87564",
		Plaintext:  "2eedea52cd8215e1acc647e810bbc3642e87287f8d2e57e36c0a24fbc12a202e",
		Ciphertext: "cbaad0e2f6cea3f50b37f934d46a9b130b9d54f07e34f36af793e86f73c6d7db",
		Source:     "NIST CAVP XTSTestVectors.zip",
	},
	{
		Name:       "CAVP-XTS-AES256-48B",
		Key:        "266c336b3b01489f3267f52835fd92f674374b88b4e1ebd2d36a5f457581d9d042c3eef7b0b7e5137b086496b4d9e6ac658d7196a23f23f036172fdb8faee527",
		Tweak:      "06b209a7a22f486ecbfadb0f3137ba42",
		Plaintext:  "ca7d65ef8d3dfad345b61ccddca1ad81de830b9e86c7b426d76cb7db766852d981c6b21409399d78f42cc0b33a7bbb06",
		Ciphertext: "c73256870cc2f4dd57acc74b5456dbd776912a128bc1f77d72cdebbf270044b7a43ceed29025e1e8be211fa3c3ed002d",
		Source:     "NIST CAVP XTSTestVectors.zip",
	},
	{
		Name:       "CAVP-XTS-AES128-32B",
		Key:        "b7b93f516aef295eff3a29d837cf1f135347e8a21dae616ff5062b2e8d78ce5e",
		Tweak:      "873edea653b643bd8bcf51403197ed14",
		Plaintext:  "236f8a5b58dd55f6194ed70c4ac1a17f1fe60ec9a6c454d087ccb77d6b638c47",
		Ciphertext: "22e6a3c6379dcf7599b052b5a749c7f78ad8a11b9f1aa9430cf3aef445682e19",
		Source:     "NIST CAVP XTSTestVectors.zip",
	},
	{
		Name:       "CAVP-XTS-AES128-25B-CTS",
		Key:        "394c97881abd989d29c703e48a72b397a7acf51b59649eeea9b33274d8541df4",
		Tweak:      "4b15c684a152d485fe9937d39b168c29",
		Plaintext:  "2f3b9dcfbae729583b1d1ffdd16bb6fe2757329435662a78f0",
		Ciphertext: "f3473802e38a3ffef4d4fb8e6aa266ebde553a64528a06463e",
		Source:     "NIST CAVP XTSTestVectors.zip",
	},
	{
		Name:       "XTS-AES128-17B-CTS",
		Key:        "f1f8ff060d141b222930373e454c535a61686f767d848b9299a0a7aeb5bcc3ca",
		Tweak:      "fe050c131a21282f363d444b52596067",
		Plaintext:  "0b121920272e353c434a51585f666d747b",
		Ciphertext: "e28e44100b6a42329ecfeaff6b6bc8c2c3",
		Source:     "generated; agreed by OpenSSL and xts-aes-s390",
	},
	{
		Name:       "XTS-AES128-25B-CTS",
		Key:        "373e454c535a61686f767d848b9299a0a7aeb5bcc3cad1d8dfe6edf4fb020910",
		Tweak:      "444b525960676e757c838a91989fa6ad",
		Plaintext:  "51585f666d747b828990979ea5acb3bac1c8cfd6dde4ebf2f9",
		Ciphertext: "34fd788f198270b6576984dfcde85018f40375af7b261d3fe2",
		Source:     "generated; agreed by OpenSSL and xts-aes-s390",
	},
	{
		Name:       "XTS-AES128-30B-CTS",
		Key:        "141b222930373e454c535a61686f767d848b9299a0a7aeb5bcc3cad1d8dfe6ed",
		Tweak:      "21282f363d444b525960676e757c838a",
		Plaintext:  "2e353c434a51585f666d747b828990979ea5acb3bac1c8cfd6dde4ebf2f9",
		Ciphertext: "436e9ffca5369cd1c12851f021522b6c2216f11f78cb9625d97be980e69b",
		Source:     "generated; agreed by OpenSSL and xts-aes-s390",
	},
	{
		Name:       "XTS-AES128-64B",
		Key:        "1f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dce3eaf1f8",
		Tweak:      "2c333a41484f565d646b727980878e95",
		Plaintext:  "3940474e555c636a71787f868d949ba2a9b0b7bec5ccd3dae1e8eff6fd040b121920272e353c434a51585f666d747b828990979ea5acb3bac1c8cfd6dde4ebf2",
		Ciphertext: "ddd576f9eb6abc175d88198ebcfbf2bb98f5ace08be17a38c1ed32bc1bd4ca66995e10d5a3feb2c0129baf5f31246a29e2189873c0a3f82d36fcfc76fed21e3b",
		Source:     "generated; agreed by OpenSSL and xts-aes-s390",
	},
	{
		Name:       "XTS-AES256-16B",
		Key:        "424950575e656c737a81888f969da4abb2b9c0c7ced5dce3eaf1f8ff060d141b222930373e454c535a61686f767d848b9299a0a7aeb5bcc3cad1d8dfe6edf4fb",
		Tweak:      "4f565d646b727980878e959ca3aab1b8",
		Plaintext:  "5c636a71787f868d949ba2a9b0b7bec5",
		Ciphertext: "ebe989de86a2baa78e22ed0f388b7fb0",
		Source:     "generated; agreed by OpenSSL and xts-aes-s390",
	},
	{
		Name:       "XTS-AES256-17B-CTS",
		Key:        "888f969da4abb2b9c0c7ced5dce3eaf1f8ff060d141b222930373e454c535a61686f767d848b9299a0a7aeb5bcc3cad1d8dfe6edf4fb020910171e252c333a41",
		Tweak:      "959ca3aab1b8bfc6cdd4dbe2e9f0f7fe",
		Plaintext:  "a2a9b0b7bec5ccd3dae1e8eff6fd040b12",
		Ciphertext: "31e9f967ac26690b331262efadccce5de8",
		Source:     "generated; agreed by OpenSSL and xts-aes-s390",
	},
	{
		Name:       "XTS-AES256-25B-CTS",
		Key:        "ced5dce3eaf1f8ff060d141b222930373e454c535a61686f767d848b9299a0a7aeb5bcc3cad1d8dfe6edf4fb020910171e252c333a41484f565d646b72798087",
		Tweak:      "dbe2e9f0f7fe050c131a21282f363d44",
		Plaintext:  "e8eff6fd040b121920272e353c434a51585f666d747b828990",
		Ciphertext: "d0167c3d0207879e3b141f6f47f2c77d4e6ec0af4585e41667",
		Source:     "generated; agreed by OpenSSL and xts-aes-s390",
	},
	{
		Name:       "XTS-AES256-30B-CTS",
		Key:        "abb2b9c0c7ced5dce3eaf1f8ff060d141b222930373e454c535a61686f767d848b9299a0a7aeb5bcc3cad1d8dfe6edf4fb020910171e252c333a41484f565d64",
		Tweak:      "b8bfc6cdd4dbe2e9f0f7fe050c131a21",
		Plaintext:  "c5ccd3dae1e8eff6fd040b121920272e353c434a51585f666d747b828990",
		Ciphertext: "36ecc99fdfa14375ec3e72701a217fb15078e5f36bae1cf4ed6d5c2f7720",
		Source:     "generated; agreed by OpenSSL and xts-aes-s390",
	},
}

// VerifyXTSVectors checks every vector in both directions and returns the number
// that passed.
func VerifyXTSVectors() (int, error) {
	passed := 0
	for _, v := range XTSVectors {
		if err := verifyXTSVector(v); err != nil {
			return passed, fmt.Errorf("vector %q: %w", v.Name, err)
		}
		passed++
	}
	return passed, nil
}

func verifyXTSVector(v XTSVector) error {
	key, err := hex.DecodeString(v.Key)
	if err != nil {
		return fmt.Errorf("decode key: %w", err)
	}
	tweak, err := hex.DecodeString(v.Tweak)
	if err != nil {
		return fmt.Errorf("decode tweak: %w", err)
	}
	pt, err := hex.DecodeString(v.Plaintext)
	if err != nil {
		return fmt.Errorf("decode plaintext: %w", err)
	}
	want, err := hex.DecodeString(v.Ciphertext)
	if err != nil {
		return fmt.Errorf("decode ciphertext: %w", err)
	}

	got, err := XTSEncrypt(key, tweak, pt)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}
	if !bytesEqual(got, want) {
		return fmt.Errorf("encrypt mismatch\n got %s\nwant %s",
			hex.EncodeToString(got), v.Ciphertext)
	}

	back, err := XTSDecrypt(key, tweak, want)
	if err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}
	if !bytesEqual(back, pt) {
		return fmt.Errorf("decrypt mismatch\n got %s\nwant %s",
			hex.EncodeToString(back), v.Plaintext)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

// XTSResult is the throughput of one (key size, buffer size) measurement.
//
// EncryptMBps and DecryptMBps always describe the pure-Go path, so a row is
// always comparable with the AES mode table. When the kernel path is reachable
// the HardwareMBps, HardwareDecryptMBps and Speedup fields are filled in as
// well; when it is not they stay zero and HardwareError says why, because a
// missing row is less useful than a row that explains itself.
type XTSResult struct {
	KeyBits      int     `json:"key_bits"`
	KeyBytes     int     `json:"key_bytes"`
	BlockSize    int     `json:"block_size"`
	Iterations   int     `json:"iterations"`
	EncryptMBps  float64 `json:"encrypt_mbps"`
	DecryptMBps  float64 `json:"decrypt_mbps"`
	EncryptNanos int64   `json:"encrypt_nanos"`
	DecryptNanos int64   `json:"decrypt_nanos"`
	// Verified is true when the decrypt pass reproduced the plaintext exactly.
	Verified bool `json:"round_trip_verified"`

	HardwareMBps        float64 `json:"hardware_encrypt_mbps,omitempty"`
	HardwareDecryptMBps float64 `json:"hardware_decrypt_mbps,omitempty"`
	// Speedup is HardwareMBps / EncryptMBps. Zero when hardware is absent.
	Speedup       float64 `json:"hardware_speedup,omitempty"`
	HardwarePath  string  `json:"hardware_path,omitempty"`
	HardwareError string  `json:"hardware_error,omitempty"`
	Error         string  `json:"error,omitempty"`
}

// xtsFill deterministically fills a buffer so both paths measure the same bytes
// and a round-trip mismatch is reproducible rather than random.
func xtsFill(b []byte, seed byte) {
	for i := range b {
		b[i] = byte(i*31) ^ seed
	}
}

// xtsKeyBytes maps an AES key size in bits to the XTS key length in bytes.
func xtsKeyBytes(keyBits int) (int, error) {
	switch keyBits {
	case 128:
		return 32, nil // two AES-128 keys
	case 256:
		return 64, nil // two AES-256 keys
	}
	return 0, fmt.Errorf("xts: key size must be 128 or 256 bits, got %d", keyBits)
}

// XTSBenchmark measures the pure-Go XTS path at one buffer size.
//
// blockSize is the data-unit length in bytes. Unlike the CBC/CTR benchmark this
// does not require a multiple of 16: a non-aligned size is legal for XTS and
// exercises ciphertext stealing, which is slower per byte and is therefore worth
// measuring rather than excluding.
func XTSBenchmark(keyBits, blockSize, iterations int) (XTSResult, error) {
	res := XTSResult{
		KeyBits:    keyBits,
		BlockSize:  blockSize,
		Iterations: iterations,
	}
	if iterations <= 0 {
		return res, errors.New("xts: iterations must be positive")
	}
	if blockSize < XTSMinDataUnit {
		return res, fmt.Errorf("xts: block size must be at least %d bytes", XTSMinDataUnit)
	}
	if blockSize > XTSMaxDataUnit {
		return res, fmt.Errorf("xts: block size exceeds the %d-byte maximum", XTSMaxDataUnit)
	}
	keyLen, err := xtsKeyBytes(keyBits)
	if err != nil {
		return res, err
	}
	res.KeyBytes = keyLen

	key := make([]byte, keyLen)
	xtsFill(key, 0x11)
	tweak := make([]byte, XTSBlockSize)
	xtsFill(tweak, 0x22)
	pt := make([]byte, blockSize)
	xtsFill(pt, 0x33)

	totalMB := float64(blockSize) * float64(iterations) / (1024 * 1024)

	t0 := time.Now()
	var ct []byte
	for i := 0; i < iterations; i++ {
		ct, err = XTSEncrypt(key, tweak, pt)
		if err != nil {
			return res, fmt.Errorf("xts: encrypt iteration %d: %w", i, err)
		}
	}
	encDur := time.Since(t0)
	res.EncryptNanos = encDur.Nanoseconds()
	res.EncryptMBps = totalMB / encDur.Seconds()

	t1 := time.Now()
	var back []byte
	for i := 0; i < iterations; i++ {
		back, err = XTSDecrypt(key, tweak, ct)
		if err != nil {
			return res, fmt.Errorf("xts: decrypt iteration %d: %w", i, err)
		}
	}
	decDur := time.Since(t1)
	res.DecryptNanos = decDur.Nanoseconds()
	res.DecryptMBps = totalMB / decDur.Seconds()

	if !bytesEqual(back, pt) {
		return res, errors.New("xts: round-trip mismatch")
	}
	res.Verified = true
	return res, nil
}

// XTSHardwareBenchmark measures the same operation through AF_ALG, which on
// s390x reaches xts-aes-s390 and therefore KMF.
//
// It returns ErrXTSHardwareUnavailable (wrapped) when the kernel path is not
// reachable, so callers can fall back without string matching.
func XTSHardwareBenchmark(keyBits, blockSize, iterations int) (XTSResult, error) {
	res := XTSResult{
		KeyBits:      keyBits,
		BlockSize:    blockSize,
		Iterations:   iterations,
		HardwarePath: XTSKernelAlgorithm,
	}
	if iterations <= 0 {
		return res, errors.New("xts: iterations must be positive")
	}
	if blockSize < XTSMinDataUnit {
		return res, fmt.Errorf("xts: block size must be at least %d bytes", XTSMinDataUnit)
	}
	keyLen, err := xtsKeyBytes(keyBits)
	if err != nil {
		return res, err
	}
	res.KeyBytes = keyLen

	key := make([]byte, keyLen)
	xtsFill(key, 0x11)
	tweak := make([]byte, XTSBlockSize)
	xtsFill(tweak, 0x22)
	pt := make([]byte, blockSize)
	xtsFill(pt, 0x33)

	c, err := newAFALGSkcipher(xtsAlgorithm, key)
	if err != nil {
		return res, fmt.Errorf("%w: %v", ErrXTSHardwareUnavailable, err)
	}
	defer c.Close()

	totalMB := float64(blockSize) * float64(iterations) / (1024 * 1024)
	ct := make([]byte, blockSize)
	back := make([]byte, blockSize)

	_, k2, _, err := xtsSplitKey(key)
	if err != nil {
		return res, err
	}

	t0 := time.Now()
	for i := 0; i < iterations; i++ {
		if err := xtsHardwareChunked(c, k2, ct, pt, tweak, true); err != nil {
			return res, fmt.Errorf("%w: %v", ErrXTSHardwareUnavailable, err)
		}
	}
	encDur := time.Since(t0)
	res.EncryptNanos = encDur.Nanoseconds()
	res.EncryptMBps = totalMB / encDur.Seconds()

	t1 := time.Now()
	for i := 0; i < iterations; i++ {
		if err := xtsHardwareChunked(c, k2, back, ct, tweak, false); err != nil {
			return res, fmt.Errorf("%w: %v", ErrXTSHardwareUnavailable, err)
		}
	}
	decDur := time.Since(t1)
	res.DecryptNanos = decDur.Nanoseconds()
	res.DecryptMBps = totalMB / decDur.Seconds()

	if !bytesEqual(back, pt) {
		return res, errors.New("xts: AF_ALG round-trip mismatch")
	}
	res.Verified = true
	return res, nil
}

// XTSComparison measures the pure-Go path and, when reachable, the kernel path,
// and folds them into one row with a speedup ratio.
//
// The Go result is authoritative: a hardware failure is recorded in
// HardwareError and never turns the row into an error, because the portable
// number is still valid and still worth reporting on a machine with no KMF.
func XTSComparison(keyBits, blockSize, iterations int) XTSResult {
	res, err := XTSBenchmark(keyBits, blockSize, iterations)
	if err != nil {
		res.KeyBits = keyBits
		res.BlockSize = blockSize
		res.Iterations = iterations
		res.Error = err.Error()
		return res
	}

	hw, err := XTSHardwareBenchmark(keyBits, blockSize, iterations)
	if err != nil {
		res.HardwareError = err.Error()
		return res
	}
	res.HardwareMBps = hw.EncryptMBps
	res.HardwareDecryptMBps = hw.DecryptMBps
	res.HardwarePath = hw.HardwarePath
	if res.EncryptMBps > 0 {
		res.Speedup = hw.EncryptMBps / res.EncryptMBps
	}
	return res
}

// XTSSuite runs the comparison at the three sizes the rest of the suite uses,
// so the XTS rows line up with the AES-GCM and mode-comparison tables.
//
// Iteration counts scale down with buffer size so every row runs for a
// comparable wall-clock time, matching AESGCMBenchmarkSuite.
func XTSSuite(keyBits, scale int) []XTSResult {
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
	out := make([]XTSResult, 0, len(sizes))
	for _, s := range sizes {
		out = append(out, XTSComparison(keyBits, s.size, s.iter))
	}
	return out
}
