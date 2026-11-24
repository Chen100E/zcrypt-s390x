package cipher

// GCM over arbitrary-length IVs, built from the standalone GHASH primitive.
//
// crypto/cipher.NewGCM only accepts 96-bit nonces, and NewGCMWithNonceSize does
// accept other lengths, but neither exposes J0, the pre-counter block. Without
// J0 there is no way to check the one part of GCM that SP 800-38D defines twice:
//
//	IVlen == 96:  J0 = IV || 0^31 || 1
//	otherwise:    J0 = GHASH_H(IV || 0^s || [len(IV)]_64)
//
// where s = 128*ceil(len(IV)/128) - len(IV) and the length is in bits. The 96-bit
// branch is the one everybody implements and the one the existing NISTGCMVectors
// cover; the second branch is the one that silently breaks when the length block
// is encoded in bytes instead of bits, or little-endian, or when the padding is
// applied to the length field as well. NIST CAVP gcmEncryptExtIV256.rsp carries
// cases at IVlen = 8 and IVlen = 1024 bits specifically to test it, and they are
// reproduced in NISTGCMNonStdIVVectors below.
//
// The seal below is a direct transcription of SP 800-38D §7.1 (GCM-AE) and §6.1
// (GCTR), using crypto/aes only for the block cipher itself. It is a
// verification path, not the benchmarked one: the AES-256-GCM throughput figures
// in the report come from crypto/cipher, which on s390x fuses the AES rounds and
// GHASH into KMA. This file exists so the construction around GHASH is checkable
// independently of whatever the fused instruction does.

import (
	"crypto/aes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
)

// GCMHashSubkey returns H = E_K(0^128) for the given AES key.
//
// H is what GHASH is keyed with, and it is also the reason the same AES key must
// never be used with two different GCM implementations that disagree about
// endianness: H is a raw block-cipher output, so a byte-order fault shows up
// here before it shows up anywhere else.
func GCMHashSubkey(key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("gcm: new cipher: %w", err)
	}
	var zero [ghashBlockSize]byte
	h := make([]byte, ghashBlockSize)
	block.Encrypt(h, zero[:])
	return h, nil
}

// gcmJ0 derives the pre-counter block J0 for an IV of any length, per
// SP 800-38D §7.1 step 2.
func gcmJ0(h, iv []byte) ([]byte, error) {
	switch len(iv) {
	case 0:
		return nil, errors.New("gcm: IV must not be empty")
	case 12:
		// The common case, and the only one where GHASH is not involved.
		j0 := make([]byte, ghashBlockSize)
		copy(j0, iv)
		j0[15] = 1
		return j0, nil
	}

	// J0 = GHASH_H(IV || 0^s || [len(IV)]_64). Note that the IV is padded to a
	// block boundary with zeros, then a full zero block of 8 bytes is appended
	// before the length, and that the length is in BITS.
	msg := make([]byte, 0, paddedLen(len(iv))+16)
	msg = appendPadded(msg, iv)

	var lenBlock [16]byte
	binary.BigEndian.PutUint64(lenBlock[8:16], uint64(len(iv))*8)
	msg = append(msg, lenBlock[:]...)

	g, err := NewGHASH(h)
	if err != nil {
		return nil, err
	}
	if _, err := g.Write(msg); err != nil {
		return nil, err
	}
	return g.Sum(), nil
}

// GCMJ0 returns the pre-counter block for the given key and IV. It is exported
// so the IV-derivation path can be tested and reported on directly.
func GCMJ0(key, iv []byte) ([]byte, error) {
	h, err := GCMHashSubkey(key)
	if err != nil {
		return nil, err
	}
	return gcmJ0(h, iv)
}

// gcmInc32 increments the rightmost 32 bits of the counter block modulo 2^32,
// leaving the leftmost 96 bits untouched (SP 800-38D §6.1, inc32).
func gcmInc32(block []byte) {
	for i := ghashBlockSize - 1; i >= ghashBlockSize-4; i-- {
		block[i]++
		if block[i] != 0 {
			return
		}
	}
}

// gcmGCTR applies GCTR with the given initial counter block (SP 800-38D §6.1).
// The counter block is copied, so the caller's slice is never mutated.
func gcmGCTR(block interface {
	Encrypt(dst, src []byte)
}, icb, data []byte) []byte {
	out := make([]byte, len(data))
	if len(data) == 0 {
		return out
	}

	var ctr [ghashBlockSize]byte
	copy(ctr[:], icb)

	var ks [ghashBlockSize]byte
	for off := 0; off < len(data); off += ghashBlockSize {
		block.Encrypt(ks[:], ctr[:])
		n := len(data) - off
		if n > ghashBlockSize {
			n = ghashBlockSize
		}
		for i := 0; i < n; i++ {
			out[off+i] = data[off+i] ^ ks[i]
		}
		gcmInc32(ctr[:])
	}
	return out
}

// GCMSealWithIV implements GCM-AE for an IV of any length and returns
// ciphertext || tag, the same layout crypto/cipher's AEAD.Seal produces.
//
// A 12-byte IV takes the fast J0 = IV||0^31||1 branch; every other length goes
// through GHASH. Both are covered by known-answer vectors, and the 96-bit path is
// additionally checked against NISTGCMVectors so that adding this function
// cannot have changed the behaviour the rest of the project relies on.
func GCMSealWithIV(key, iv, aad, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("gcm: new cipher: %w", err)
	}

	var zero [ghashBlockSize]byte
	var h [ghashBlockSize]byte
	block.Encrypt(h[:], zero[:])

	j0, err := gcmJ0(h[:], iv)
	if err != nil {
		return nil, err
	}

	// C = GCTR_K(inc32(J0), P)
	icb := make([]byte, ghashBlockSize)
	copy(icb, j0)
	gcmInc32(icb)
	ct := gcmGCTR(block, icb, plaintext)

	// S = GHASH_H(pad16(A) || pad16(C) || [len(A)]_64 || [len(C)]_64)
	g, err := NewGHASH(h[:])
	if err != nil {
		return nil, err
	}
	if _, err := g.Write(GHASHMessage(aad, ct)); err != nil {
		return nil, err
	}
	s := g.Sum()

	// T = MSB_t(GCTR_K(J0, S)); the tag length is the full 128 bits here.
	var tagMask [ghashBlockSize]byte
	block.Encrypt(tagMask[:], j0)

	out := make([]byte, 0, len(ct)+ghashBlockSize)
	out = append(out, ct...)
	for i := 0; i < ghashBlockSize; i++ {
		out = append(out, s[i]^tagMask[i])
	}
	return out, nil
}

// GCMOpenWithIV is the inverse of GCMSealWithIV: it verifies the tag and returns
// the plaintext, or an error if the tag does not match. It exists so the vectors
// can be checked in both directions, the same way VerifyAESGCMVectors checks the
// crypto/cipher path.
func GCMOpenWithIV(key, iv, aad, sealed []byte) ([]byte, error) {
	if len(sealed) < ghashBlockSize {
		return nil, errors.New("gcm: ciphertext shorter than the tag")
	}
	ct := sealed[:len(sealed)-ghashBlockSize]
	want := sealed[len(sealed)-ghashBlockSize:]

	// Recomputing the tag means re-running the seal over the ciphertext, which
	// is the straightforward way to keep one implementation of the tag
	// computation. The counter block for the plaintext is derived from J0, so
	// decrypting is a GCTR with the same initial counter.
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("gcm: new cipher: %w", err)
	}
	var zero [ghashBlockSize]byte
	var h [ghashBlockSize]byte
	block.Encrypt(h[:], zero[:])

	j0, err := gcmJ0(h[:], iv)
	if err != nil {
		return nil, err
	}

	g, err := NewGHASH(h[:])
	if err != nil {
		return nil, err
	}
	if _, err := g.Write(GHASHMessage(aad, ct)); err != nil {
		return nil, err
	}
	s := g.Sum()

	var tagMask [ghashBlockSize]byte
	block.Encrypt(tagMask[:], j0)
	got := make([]byte, ghashBlockSize)
	for i := 0; i < ghashBlockSize; i++ {
		got[i] = s[i] ^ tagMask[i]
	}
	if !bytesEqualConstTime(got, want) {
		return nil, errors.New("gcm: authentication tag mismatch")
	}

	icb := make([]byte, ghashBlockSize)
	copy(icb, j0)
	gcmInc32(icb)
	return gcmGCTR(block, icb, ct), nil
}

// GCMNonStdIVVector is one GCM known-answer case whose IV is not 96 bits, so J0
// is derived through GHASH rather than by appending 0^31||1.
type GCMNonStdIVVector struct {
	Name       string
	Key        string // hex, AES-256
	IV         string // hex, any length except 12 bytes
	AAD        string // hex
	Plaintext  string // hex
	Ciphertext string // hex, ciphertext only
	Tag        string // hex
}

// NISTGCMNonStdIVVectors holds the CAVP gcmEncryptExtIV256.rsp cases that
// exercise the GHASH-derived J0 path.
//
// Both were extracted from the NIST file and independently reproduced three
// ways before being written here: by GCMSealWithIV, by Python's cryptography
// package (which takes the IV directly), and by a from-scratch J0/GCTR script
// over the same GHASH primitive. All three agree bit for bit.
//
// The 8-bit case is the smallest legal IV and pins the [len(IV)]_64 field to the
// value 8; the 1024-bit case is the longest IV GCM permits and forces the IV
// through GHASH as two full blocks plus the length block. A byte-length encoding
// bug or a little-endian length store breaks both, and a 96-bit-only
// implementation cannot express either.
var NISTGCMNonStdIVVectors = []GCMNonStdIVVector{
	{
		Name:       "NIST-CAVP-AES256-GCM-8bit-IV-16B",
		Key:        "9473c28f6e978eb15e1967b888282aa6b078d320034fe5f40f8bb68674f1ecda",
		IV:         "0a",
		AAD:        "",
		Plaintext:  "2d2e2798c10bcfcce742e92d3c390fef",
		Ciphertext: "c4e5ab2c6a4316e57c6c37d2c2acb42c",
		Tag:        "03337df7e1e68d77706abef9edaf5e07",
	},
	{
		Name: "NIST-CAVP-AES256-GCM-1024bit-IV-16B",
		Key:  "d0c267c19f30d80b8914bbbfb72f73b8d3cd5f6a787015848a7b30e38f16f18b",
		IV: "b6dcda95ac99777625ae87f8a3a9dd64d79bbd5f4a0e54ca1a9fa2e3f45f5fc2" +
			"cea7b614126ff0affd3e17356ea01609dda13fd8ddf3df4fcb1849b8b3692c5d" +
			"4fad309108bcbe24010fbe9cfb4f5d197f4c53b09590ac7b1f7ba099e1f34854" +
			"d0fca9cc91f81f9b6c9ae0dc63ea7d2a4a7da5ed6857276b68e0f2b851508d3d",
		AAD:        "",
		Plaintext:  "b8b6883644e234df243291074fe36f81",
		Ciphertext: "ff4fb3f3f9a251d482c2bef3e2d0eced",
		Tag:        "bd063809f7e1c4720ef2ea63db996c21",
	},
}

// VerifyGCMNonStdIVVectors checks every non-96-bit-IV vector in both directions
// and returns the number that passed.
func VerifyGCMNonStdIVVectors() (int, error) {
	passed := 0
	for _, v := range NISTGCMNonStdIVVectors {
		if err := verifyGCMNonStdIVVector(v); err != nil {
			return passed, fmt.Errorf("vector %q: %w", v.Name, err)
		}
		passed++
	}
	return passed, nil
}

func verifyGCMNonStdIVVector(v GCMNonStdIVVector) error {
	key, err := hex.DecodeString(v.Key)
	if err != nil {
		return fmt.Errorf("decode key: %w", err)
	}
	iv, err := hex.DecodeString(v.IV)
	if err != nil {
		return fmt.Errorf("decode iv: %w", err)
	}
	aad, err := hex.DecodeString(v.AAD)
	if err != nil {
		return fmt.Errorf("decode aad: %w", err)
	}
	pt, err := hex.DecodeString(v.Plaintext)
	if err != nil {
		return fmt.Errorf("decode plaintext: %w", err)
	}
	ct, err := hex.DecodeString(v.Ciphertext)
	if err != nil {
		return fmt.Errorf("decode ciphertext: %w", err)
	}
	tag, err := hex.DecodeString(v.Tag)
	if err != nil {
		return fmt.Errorf("decode tag: %w", err)
	}

	// A 12-byte IV would take the other branch and prove nothing about GHASH.
	if len(iv) == 12 {
		return fmt.Errorf("IV is 96 bits; this vector set is for the GHASH-derived J0 path")
	}

	want := append(append([]byte(nil), ct...), tag...)
	got, err := GCMSealWithIV(key, iv, aad, pt)
	if err != nil {
		return fmt.Errorf("seal: %w", err)
	}
	if !bytesEqual(got, want) {
		return fmt.Errorf("seal mismatch\n got %s\nwant %s", hexEncode(got), hexEncode(want))
	}

	back, err := GCMOpenWithIV(key, iv, aad, want)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	if !bytesEqual(back, pt) {
		return fmt.Errorf("open mismatch\n got %s\nwant %s", hexEncode(back), v.Plaintext)
	}

	// The tag must actually be checked, not just recomputed.
	tampered := append([]byte(nil), want...)
	tampered[len(tampered)-1] ^= 0x01
	if _, err := GCMOpenWithIV(key, iv, aad, tampered); err == nil {
		return errors.New("tampered tag was accepted")
	}
	return nil
}

// VerifyGCMStdIVVectorsWithGCMSeal re-checks the four 96-bit-IV vectors in
// NISTGCMVectors through GCMSealWithIV. It is the regression guard for adding
// the arbitrary-IV path: if the J0 branch or the counter handling changed, the
// existing vectors fail here even though VerifyAESGCMVectors (which goes through
// crypto/cipher) still passes.
func VerifyGCMStdIVVectorsWithGCMSeal() (int, error) {
	passed := 0
	for _, v := range NISTGCMVectors {
		key, err := hex.DecodeString(v.Key)
		if err != nil {
			return passed, fmt.Errorf("vector %q: decode key: %w", v.Name, err)
		}
		iv, err := hex.DecodeString(v.Nonce)
		if err != nil {
			return passed, fmt.Errorf("vector %q: decode iv: %w", v.Name, err)
		}
		aad, err := hex.DecodeString(v.AAD)
		if err != nil {
			return passed, fmt.Errorf("vector %q: decode aad: %w", v.Name, err)
		}
		pt, err := hex.DecodeString(v.Plaintext)
		if err != nil {
			return passed, fmt.Errorf("vector %q: decode plaintext: %w", v.Name, err)
		}
		want, err := hex.DecodeString(v.Ciphertext)
		if err != nil {
			return passed, fmt.Errorf("vector %q: decode ciphertext: %w", v.Name, err)
		}

		got, err := GCMSealWithIV(key, iv, aad, pt)
		if err != nil {
			return passed, fmt.Errorf("vector %q: seal: %w", v.Name, err)
		}
		if !bytesEqual(got, want) {
			return passed, fmt.Errorf("vector %q: got %s want %s", v.Name, hexEncode(got), v.Ciphertext)
		}
		passed++
	}
	return passed, nil
}
