package cipher

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// This file extends the AES measurement surface from GCM-only to the three
// modes that matter on a mainframe: CBC, CTR and GCM.
//
// The interesting part on s390x is not the throughput number itself but which
// CPACF instruction each Go API actually issues. The mapping below was read out
// of the Go 1.23 crypto/aes source on the target machine rather than assumed,
// because two of the four entries are not what the textbook answer suggests:
//
//	ECB (single block)  -> KM    Cipher Message                       (MSA-1)
//	CBC                 -> KMC   Cipher Message with Chaining         (MSA-1)
//	CTR                 -> KM    via an ECB refill buffer, XOR in Go   (MSA-1)
//	GCM                 -> KMA   Cipher Message with Authentication   (MSA-8)
//	                       or KMCTR + KIMD-GHASH below MSA-8
//	XTS                 -> KMF   Cipher Message with Fetch            (MSA-4)
//
// The CTR entry is the surprising one. crypto/aes/ctr_s390x.go does not issue
// KMCTR: it keeps a 512-byte buffer of ECB-encrypted counter blocks, refills it
// with cryptBlocks() (that is KM), and XORs the keystream into the caller's
// buffer in Go. KMCTR is only used inside the AES-GCM implementation, on
// machines without MSA-8. This is why the CTR row below is slower than CBC even
// though counter mode is the more parallel construction — the hardware
// instruction that would exploit that parallelism is not on this code path.
//
// CBC beats CTR for the same reason: crypto/aes/cbc_s390x.go calls KMC once for
// the whole buffer, so the chaining happens on-chip and the CPU never touches
// the data. On decrypt KMC also handles the whole buffer in one instruction,
// which is why CBC decrypt is the fastest of the four on this machine.
//
// The numbers in docs/benchmarks/buffer-size-sweep.md bear all of this out, and
// the mode table is what makes the claim auditable rather than folklore.

// AESMode names a block-cipher mode of operation.
type AESMode string

const (
	// ModeCBC is cipher block chaining: serial by construction, because every
	// block is XORed with the previous ciphertext block.
	ModeCBC AESMode = "CBC"
	// ModeCTR is counter mode: fully parallel, no chaining dependency.
	ModeCTR AESMode = "CTR"
	// ModeGCM is Galois/Counter mode: CTR for confidentiality plus GHASH for
	// authentication.
	ModeGCM AESMode = "GCM"
	// ModeECB is included for the NIST known-answer vectors and as the pure
	// per-block cost baseline. It must never be used for real data: identical
	// plaintext blocks produce identical ciphertext blocks.
	ModeECB AESMode = "ECB"
	// ModeXTS is XEX-based tweaked codebook with ciphertext stealing (IEEE
	// 1619-2007, NIST SP 800-38E). It is the mode dm-crypt/LUKS uses, and the
	// only one in this table that Go's standard library does not implement.
	ModeXTS AESMode = "XTS"
)

// AESModeInfo documents how one mode maps onto CPACF hardware.
type AESModeInfo struct {
	Mode        AESMode `json:"mode"`
	Instruction string  `json:"cpacf_instruction"`
	MSALevel    int     `json:"msa_level"`
	GoPath      string  `json:"go_path"`
	Parallel    bool    `json:"parallel"`
	Auth        bool    `json:"authenticated"`
	Notes       string  `json:"notes"`
}

// AESModeTable is the mode-to-instruction mapping, ordered from least to most
// parallel. It is rendered by `zcrypt` and by the README, and it is the single
// source of truth for the claim "CBC goes through KMC, CTR through KMCTR".
var AESModeTable = []AESModeInfo{
	{
		Mode:        ModeECB,
		Instruction: "KM",
		MSALevel:    1,
		GoPath:      "crypto/aes.(*aesCipherAsm).Encrypt",
		Parallel:    false,
		Auth:        false,
		Notes:       "one block per instruction; reference cost only, never for data",
	},
	{
		Mode:        ModeCBC,
		Instruction: "KMC",
		MSALevel:    1,
		GoPath:      "crypto/aes.(*aesCipherAsm).NewCBCEncrypter -> kmc()",
		Parallel:    false,
		Auth:        false,
		Notes:       "chaining value lives in the instruction parameter block, so the IV never round-trips through memory",
	},
	{
		Mode:        ModeCTR,
		Instruction: "KM",
		MSALevel:    1,
		GoPath:      "crypto/aes.(*aesctr).refill -> cryptBlocks(KM) + Go-side xorBytes",
		Parallel:    true,
		Auth:        false,
		Notes:       "Go refills a 512-byte ECB keystream buffer and XORs in software; KMCTR is NOT issued on this path",
	},
	{
		Mode:        ModeGCM,
		Instruction: "KMA",
		MSALevel:    8,
		GoPath:      "crypto/aes.(*aesCipherAsm).NewGCM -> gcmKMA (KMA) or gcmAsm (KMCTR + KIMD-GHASH)",
		Parallel:    true,
		Auth:        true,
		Notes:       "AES rounds and GHASH fused in one instruction; KMCTR + KIMD-GHASH is the MSA-4..7 fallback",
	},
	{
		Mode:        ModeXTS,
		Instruction: "KMF",
		MSALevel:    4,
		GoPath:      "pure Go (crypto/aes blocks -> KM); AF_ALG xts(aes) -> xts-aes-s390 -> kmf()",
		Parallel:    true,
		Auth:        false,
		Notes:       "Go's stdlib has no XTS, so the portable path is this package's own Go code over KM blocks; the kernel path is KMF (function codes 50/52), which does the tweak multiply, XOR and cipher in one instruction. Tweak arithmetic stays in Go on the portable path, which is why it is slower per byte than CBC despite being parallel.",
	},
}

// LookupAESMode returns the documentation entry for a mode.
func LookupAESMode(m AESMode) (AESModeInfo, bool) {
	for _, info := range AESModeTable {
		if info.Mode == m {
			return info, true
		}
	}
	return AESModeInfo{}, false
}

// AESModeResult is the throughput of one (mode, key size, buffer size) triple.
type AESModeResult struct {
	Mode         AESMode `json:"mode"`
	KeyBits      int     `json:"key_bits"`
	BlockSize    int     `json:"block_size"`
	EncryptMBps  float64 `json:"encrypt_mbps"`
	DecryptMBps  float64 `json:"decrypt_mbps"`
	Iterations   int     `json:"iterations"`
	Instruction  string  `json:"cpacf_instruction"`
	Verified     bool    `json:"round_trip_verified"`
	Error        string  `json:"error,omitempty"`
	SetupNanos   int64   `json:"setup_nanos"`
	EncryptNanos int64   `json:"encrypt_nanos"`
	DecryptNanos int64   `json:"decrypt_nanos"`
}

// AESModeBenchmark measures one mode at one buffer size.
//
// Setup (key schedule, IV/nonce allocation, mode construction) is timed
// separately and excluded from the throughput figure, because a caller that
// encrypts a single 1 KiB record cares about setup while a caller streaming a
// 4 MiB object does not. Reporting both keeps the number honest.
//
// The returned result is only marked Verified when the decrypt pass reproduced
// the original plaintext byte for byte. A benchmark that measures a broken
// implementation quickly is worse than no benchmark at all.
func AESModeBenchmark(mode AESMode, keyBits, blockSize, iterations int) (AESModeResult, error) {
	res := AESModeResult{
		Mode:       mode,
		KeyBits:    keyBits,
		BlockSize:  blockSize,
		Iterations: iterations,
	}
	if info, ok := LookupAESMode(mode); ok {
		res.Instruction = info.Instruction
	}
	if keyBits != 128 && keyBits != 192 && keyBits != 256 {
		return res, fmt.Errorf("aes: key size must be 128, 192 or 256 bits, got %d", keyBits)
	}
	if blockSize <= 0 {
		return res, errors.New("aes: block size must be positive")
	}
	if iterations <= 0 {
		return res, errors.New("aes: iterations must be positive")
	}

	// XTS is measured by its own benchmark, which supports ciphertext stealing
	// and therefore accepts buffer sizes the other modes cannot. Delegating here
	// rather than duplicating keeps AESModeComparison and AESModeComparisonSuite
	// uniform over AESModeTable: one row per mode, no special cases at the call
	// site.
	if mode == ModeXTS {
		xr, err := XTSBenchmark(keyBits, blockSize, iterations)
		if err != nil {
			return res, err
		}
		res.KeyBits = xr.KeyBits
		res.BlockSize = xr.BlockSize
		res.Iterations = xr.Iterations
		res.EncryptMBps = xr.EncryptMBps
		res.DecryptMBps = xr.DecryptMBps
		res.EncryptNanos = xr.EncryptNanos
		res.DecryptNanos = xr.DecryptNanos
		res.Verified = xr.Verified
		return res, nil
	}

	if mode != ModeGCM && blockSize%aes.BlockSize != 0 {
		return res, fmt.Errorf("aes-%s: buffer size %d is not a multiple of the %d-byte block",
			mode, blockSize, aes.BlockSize)
	}

	key := make([]byte, keyBits/8)
	if _, err := rand.Read(key); err != nil {
		return res, fmt.Errorf("aes: read key: %w", err)
	}

	plaintext := make([]byte, blockSize)
	if _, err := rand.Read(plaintext); err != nil {
		return res, fmt.Errorf("aes: fill plaintext: %w", err)
	}
	ciphertext := make([]byte, blockSize)
	scratch := make([]byte, blockSize)

	setupStart := time.Now()

	block, err := aes.NewCipher(key)
	if err != nil {
		return res, fmt.Errorf("aes: new cipher: %w", err)
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return res, fmt.Errorf("aes: read iv: %w", err)
	}

	var aead cipher.AEAD
	var nonce []byte
	if mode == ModeGCM {
		aead, err = cipher.NewGCM(block)
		if err != nil {
			return res, fmt.Errorf("aes-gcm: new gcm: %w", err)
		}
		// GCM loses all confidentiality if a (key, nonce) pair ever repeats, so
		// the hot loop derives a fresh nonce from a counter rather than reusing
		// one. The counter occupies the low 4 bytes of a random per-run prefix,
		// which keeps every nonce unique within the run and unpredictable
		// across runs.
		nonce = make([]byte, aead.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			return res, fmt.Errorf("aes-gcm: read nonce prefix: %w", err)
		}
	}
	switch mode {
	case ModeECB, ModeCBC, ModeCTR, ModeGCM:
	default:
		return res, fmt.Errorf("aes: unknown mode %q", mode)
	}

	res.SetupNanos = time.Since(setupStart).Nanoseconds()

	totalMB := float64(blockSize) * float64(iterations) / (1024 * 1024)

	// --- encrypt ---
	//
	// The mode object is rebuilt inside the loop for CBC and CTR. That is not
	// an artefact: a block-mode object consumes its IV on the first
	// CryptBlocks call and continues from the last ciphertext block afterwards,
	// so reusing one object across iterations would chain message N into
	// message N+1 and stop measuring "encrypt one buffer". Rebuilding costs a
	// 16-byte copy, which is below the noise floor at every buffer size here.
	var sealed []byte
	if mode == ModeGCM {
		sealed = make([]byte, 0, blockSize+aead.Overhead())
	}

	t0 := time.Now()
	switch mode {
	case ModeECB:
		for i := 0; i < iterations; i++ {
			for off := 0; off < blockSize; off += aes.BlockSize {
				block.Encrypt(ciphertext[off:off+aes.BlockSize], plaintext[off:off+aes.BlockSize])
			}
		}
	case ModeCBC:
		for i := 0; i < iterations; i++ {
			cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, plaintext)
		}
	case ModeCTR:
		for i := 0; i < iterations; i++ {
			cipher.NewCTR(block, iv).XORKeyStream(ciphertext, plaintext)
		}
	case ModeGCM:
		counter := nonce[len(nonce)-4:]
		for i := 0; i < iterations; i++ {
			putUint32BE(counter, uint32(i))
			sealed = aead.Seal(sealed[:0], nonce, plaintext, nil)
		}
	}
	encDur := time.Since(t0)
	res.EncryptNanos = encDur.Nanoseconds()
	res.EncryptMBps = totalMB / encDur.Seconds()

	// --- decrypt ---
	t1 := time.Now()
	switch mode {
	case ModeECB:
		for i := 0; i < iterations; i++ {
			for off := 0; off < blockSize; off += aes.BlockSize {
				block.Decrypt(scratch[off:off+aes.BlockSize], ciphertext[off:off+aes.BlockSize])
			}
		}
	case ModeCBC:
		for i := 0; i < iterations; i++ {
			cipher.NewCBCDecrypter(block, iv).CryptBlocks(scratch, ciphertext)
		}
	case ModeCTR:
		for i := 0; i < iterations; i++ {
			cipher.NewCTR(block, iv).XORKeyStream(scratch, ciphertext)
		}
	case ModeGCM:
		// `sealed` holds the output of the last seal, under the last counter
		// value, so that is the (nonce, ciphertext) pair to open.
		counter := nonce[len(nonce)-4:]
		last := uint32(iterations - 1)
		for i := 0; i < iterations; i++ {
			putUint32BE(counter, last)
			out, err := aead.Open(scratch[:0], nonce, sealed, nil)
			if err != nil {
				return res, fmt.Errorf("aes-gcm: decrypt iteration %d: %w", i, err)
			}
			scratch = out
		}
	}
	decDur := time.Since(t1)
	res.DecryptNanos = decDur.Nanoseconds()
	res.DecryptMBps = totalMB / decDur.Seconds()

	// --- verify ---
	// A benchmark that measures a broken implementation quickly is worse than
	// no benchmark, so the decrypt result must reproduce the plaintext exactly.
	for i := 0; i < blockSize; i++ {
		if scratch[i] != plaintext[i] {
			return res, fmt.Errorf("aes-%s: round-trip mismatch at byte %d", mode, i)
		}
	}
	res.Verified = true
	return res, nil
}

// AESModeComparison runs every mode at one buffer size with one key size, so
// the caller gets a like-for-like table. A failure in one mode does not abort
// the others: it is recorded in that row's Error field, because a comparison
// table with one missing row is still useful, and on a machine below MSA-8 the
// GCM row legitimately behaves differently.
func AESModeComparison(keyBits, blockSize, iterations int) []AESModeResult {
	modes := []AESMode{ModeECB, ModeCBC, ModeCTR, ModeGCM, ModeXTS}
	out := make([]AESModeResult, 0, len(modes))
	for _, m := range modes {
		r, err := AESModeBenchmark(m, keyBits, blockSize, iterations)
		if err != nil {
			r.Mode = m
			r.KeyBits = keyBits
			r.BlockSize = blockSize
			r.Error = err.Error()
			if info, ok := LookupAESMode(m); ok {
				r.Instruction = info.Instruction
			}
		}
		out = append(out, r)
	}
	return out
}

// AESModeComparisonSuite runs the comparison at several buffer sizes. Iteration
// counts scale down with buffer size so every row runs for a comparable wall
// clock time.
func AESModeComparisonSuite(keyBits int, scale int) []AESModeResult {
	if scale <= 0 {
		scale = 1
	}
	sizes := []struct {
		size int
		iter int
	}{
		{1024, 4000 * scale},
		{64 * 1024, 400 * scale},
		{1024 * 1024, 40 * scale},
	}
	var out []AESModeResult
	for _, s := range sizes {
		out = append(out, AESModeComparison(keyBits, s.size, s.iter)...)
	}
	return out
}

// AESModeVector is one NIST SP 800-38A known-answer case.
type AESModeVector struct {
	Name       string
	Mode       AESMode
	Key        string
	IV         string
	Plaintext  string
	Ciphertext string
}

// NISTSP80038AVectors holds the AES-128/192/256 CBC, CTR and ECB cases from
// NIST SP 800-38A, Appendix F.
//
// F.1.x is ECB, F.2.x is CBC and F.5.x is CTR. Every expected ciphertext below
// was reproduced independently with `openssl enc -aes-{128,192,256}-{cbc,ctr,ecb}
// -nopad` on the target machine before being committed, so a mismatch here means
// the Go s390x assembly path disagrees with OpenSSL's CPACF path — which is a
// real finding, not a typo.
//
// The four-block plaintext is the standard SP 800-38A message:
//
//	6bc1bee22e409f96e93d7e117393172a ae2d8a571e03ac9c9eb76fac45af8e51
//	30c81c46a35ce411e5fbc1191a0a52ef f69f2445df4f9b17ad2b417be66c3710
var NISTSP80038AVectors = []AESModeVector{
	{
		Name:       "SP800-38A-F.1.1-AES128-ECB",
		Mode:       ModeECB,
		Key:        "2b7e151628aed2a6abf7158809cf4f3c",
		IV:         "",
		Plaintext:  "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
		Ciphertext: "3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4",
	},
	{
		Name:       "SP800-38A-F.1.5-AES256-ECB",
		Mode:       ModeECB,
		Key:        "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
		IV:         "",
		Plaintext:  "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
		Ciphertext: "f3eed1bdb5d2a03c064b5a7e3db181f8591ccb10d410ed26dc5ba74a31362870b6ed21b99ca6f4f9f153e7b1beafed1d23304b7a39f9f3ff067d8d8f9e24ecc7",
	},
	{
		Name:       "SP800-38A-F.2.1-AES128-CBC",
		Mode:       ModeCBC,
		Key:        "2b7e151628aed2a6abf7158809cf4f3c",
		IV:         "000102030405060708090a0b0c0d0e0f",
		Plaintext:  "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
		Ciphertext: "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7",
	},
	{
		Name:       "SP800-38A-F.2.3-AES192-CBC",
		Mode:       ModeCBC,
		Key:        "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
		IV:         "000102030405060708090a0b0c0d0e0f",
		Plaintext:  "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
		Ciphertext: "4f021db243bc633d7178183a9fa071e8b4d9ada9ad7dedf4e5e738763f69145a571b242012fb7ae07fa9baac3df102e008b0e27988598881d920a9e64f5615cd",
	},
	{
		Name:       "SP800-38A-F.2.5-AES256-CBC",
		Mode:       ModeCBC,
		Key:        "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
		IV:         "000102030405060708090a0b0c0d0e0f",
		Plaintext:  "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
		Ciphertext: "f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b",
	},
	{
		Name:       "SP800-38A-F.5.1-AES128-CTR",
		Mode:       ModeCTR,
		Key:        "2b7e151628aed2a6abf7158809cf4f3c",
		IV:         "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
		Plaintext:  "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
		Ciphertext: "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee",
	},
	{
		Name:       "SP800-38A-F.5.3-AES192-CTR",
		Mode:       ModeCTR,
		Key:        "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
		IV:         "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
		Plaintext:  "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
		Ciphertext: "1abc932417521ca24f2b0459fe7e6e0b090339ec0aa6faefd5ccc2c6f4ce8e941e36b26bd1ebc670d1bd1d665620abf74f78a7f6d29809585a97daec58c6b050",
	},
	{
		Name:       "SP800-38A-F.5.5-AES256-CTR",
		Mode:       ModeCTR,
		Key:        "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
		IV:         "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
		Plaintext:  "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
		Ciphertext: "601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c52b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6",
	},
}

// EncryptWithMode applies one NIST vector's mode to the given plaintext. It is
// the shared helper behind both the vector check and the mode round-trip tests,
// so there is exactly one place where "how do I drive this mode" is decided.
//
// For XTS the key argument is the concatenated 32- or 64-byte XTS key and the iv
// argument is the 16-byte tweak, because that is what those two parameters mean
// for that mode. XTS is dispatched before aes.NewCipher is called: a 64-byte key
// is not an AES key, so the generic constructor would reject it.
func EncryptWithMode(mode AESMode, key, iv, plaintext []byte) ([]byte, error) {
	if mode == ModeXTS {
		return XTSEncrypt(key, iv, plaintext)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}
	if mode != ModeGCM && len(plaintext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("plaintext length %d is not a multiple of %d", len(plaintext), aes.BlockSize)
	}
	out := make([]byte, len(plaintext))
	switch mode {
	case ModeECB:
		for off := 0; off < len(plaintext); off += aes.BlockSize {
			block.Encrypt(out[off:off+aes.BlockSize], plaintext[off:off+aes.BlockSize])
		}
	case ModeCBC:
		if len(iv) != aes.BlockSize {
			return nil, fmt.Errorf("cbc: iv must be %d bytes, got %d", aes.BlockSize, len(iv))
		}
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, plaintext)
	case ModeCTR:
		if len(iv) != aes.BlockSize {
			return nil, fmt.Errorf("ctr: iv must be %d bytes, got %d", aes.BlockSize, len(iv))
		}
		cipher.NewCTR(block, iv).XORKeyStream(out, plaintext)
	case ModeGCM:
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("new gcm: %w", err)
		}
		out = aead.Seal(out[:0], iv, plaintext, nil)
	default:
		return nil, fmt.Errorf("unknown mode %q", mode)
	}
	return out, nil
}

// DecryptWithMode is the inverse of EncryptWithMode.
func DecryptWithMode(mode AESMode, key, iv, ciphertext []byte) ([]byte, error) {
	if mode == ModeXTS {
		return XTSDecrypt(key, iv, ciphertext)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}
	out := make([]byte, len(ciphertext))
	switch mode {
	case ModeECB:
		if len(ciphertext)%aes.BlockSize != 0 {
			return nil, fmt.Errorf("ecb: ciphertext length %d is not a multiple of %d", len(ciphertext), aes.BlockSize)
		}
		for off := 0; off < len(ciphertext); off += aes.BlockSize {
			block.Decrypt(out[off:off+aes.BlockSize], ciphertext[off:off+aes.BlockSize])
		}
	case ModeCBC:
		if len(ciphertext)%aes.BlockSize != 0 {
			return nil, fmt.Errorf("cbc: ciphertext length %d is not a multiple of %d", len(ciphertext), aes.BlockSize)
		}
		if len(iv) != aes.BlockSize {
			return nil, fmt.Errorf("cbc: iv must be %d bytes, got %d", aes.BlockSize, len(iv))
		}
		cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, ciphertext)
	case ModeCTR:
		if len(iv) != aes.BlockSize {
			return nil, fmt.Errorf("ctr: iv must be %d bytes, got %d", aes.BlockSize, len(iv))
		}
		cipher.NewCTR(block, iv).XORKeyStream(out, ciphertext)
	case ModeGCM:
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("new gcm: %w", err)
		}
		plain, err := aead.Open(out[:0], iv, ciphertext, nil)
		if err != nil {
			return nil, fmt.Errorf("gcm open: %w", err)
		}
		return plain, nil
	default:
		return nil, fmt.Errorf("unknown mode %q", mode)
	}
	return out, nil
}

// VerifyAESModeVectors checks every SP 800-38A vector in both directions and
// returns the number that passed.
func VerifyAESModeVectors() (int, error) {
	passed := 0
	for _, v := range NISTSP80038AVectors {
		if err := verifyAESModeVector(v); err != nil {
			return passed, fmt.Errorf("vector %q: %w", v.Name, err)
		}
		passed++
	}
	return passed, nil
}

func verifyAESModeVector(v AESModeVector) error {
	key, err := hex.DecodeString(v.Key)
	if err != nil {
		return fmt.Errorf("decode key: %w", err)
	}
	iv, err := hex.DecodeString(v.IV)
	if err != nil {
		return fmt.Errorf("decode iv: %w", err)
	}
	pt, err := hex.DecodeString(v.Plaintext)
	if err != nil {
		return fmt.Errorf("decode plaintext: %w", err)
	}
	want, err := hex.DecodeString(v.Ciphertext)
	if err != nil {
		return fmt.Errorf("decode ciphertext: %w", err)
	}

	got, err := EncryptWithMode(v.Mode, key, iv, pt)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}
	if !bytesEqual(got, want) {
		return fmt.Errorf("encrypt mismatch\n got %s\nwant %s",
			hex.EncodeToString(got), v.Ciphertext)
	}

	back, err := DecryptWithMode(v.Mode, key, iv, want)
	if err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}
	if !bytesEqual(back, pt) {
		return fmt.Errorf("decrypt mismatch\n got %s\nwant %s",
			hex.EncodeToString(back), v.Plaintext)
	}
	return nil
}
