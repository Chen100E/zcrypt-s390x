package cipher

// AF_ALG skcipher support.
//
// The hash interface above is one-shot: write the message, read the digest. The
// symmetric-cipher interface is shaped differently, because a single socket can
// encrypt any number of messages and each message carries its own per-call
// parameters:
//
//	bind(AF_ALG, "skcipher", "xts(aes)")   -> transformation socket
//	setsockopt(SOL_ALG, ALG_SET_KEY, key)  -> key, once per socket
//	accept()                               -> operation socket
//	sendmsg(data, cmsgs=[ALG_SET_OP, ALG_SET_IV])
//	read()                                 -> the transformed bytes
//
// The two control messages are what make this different from the hash path:
// the operation (encrypt or decrypt) and the IV/tweak travel out-of-band in the
// control buffer, not in the data stream. Their payloads are native-endian
// __u32 values, and ALG_SET_IV's payload is a length prefix followed by the IV
// itself.
//
// Two details are worth stating explicitly because getting either wrong
// produces plausible-looking output rather than an error:
//
//   - ALG_OP_ENCRYPT is 1 and ALG_OP_DECRYPT is 0. Swapping them silently runs
//     the cipher in the wrong direction, which for a round-trip test looks like
//     a pass and for a known-answer test looks like a broken implementation.
//   - The ALG_SET_IV length prefix is a native-endian uint32. On s390x that is
//     big-endian, so a little-endian constant would send a length of 0x10000000
//     and the kernel would reject the message with EMSGSIZE. binary.NativeEndian
//     is the correct choice and is what the code below uses.
//
// Everything degrades to an error rather than a panic: no AF_ALG in the kernel,
// a seccomp policy that blocks socket(AF_ALG), or no xts(aes) implementation
// registered all surface as a wrapped ErrXTSHardwareUnavailable from the caller.

import (
	"crypto/aes"
	"encoding/binary"
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

const (
	// solALG is SOL_ALG, the socket option level the kernel crypto API uses.
	solALG = 279

	// ALG_SET_KEY stores the key on a transformation socket.
	algSetKey = 1
	// ALG_SET_IV passes the per-message IV (the XTS tweak) in the control buffer.
	algSetIV = 2
	// ALG_SET_OP passes the operation (encrypt or decrypt).
	algSetOP = 3

	// ALG_OP_DECRYPT is 0 and ALG_OP_ENCRYPT is 1. These are not interchangeable
	// and the values are the opposite of the "obvious" ordering.
	algOpDecrypt = 0
	algOpEncrypt = 1

	// cmsgHeaderLen is sizeof(struct cmsghdr) on a 64-bit kernel: a size_t
	// length followed by two ints.
	cmsgHeaderLen = 16

	// cmsgAlign is the alignment CMSG_ALIGN rounds each header-plus-payload up
	// to, which is sizeof(size_t) on every Linux ABI Go targets.
	cmsgAlign = 8
)

// AFALGSkcipher is a bound AF_ALG symmetric-cipher socket.
//
// It is not a cipher.BlockMode or a cipher.AEAD: the kernel interface takes the
// whole message plus its IV in one call and returns the whole result, which is
// closer to a one-shot function than to a streaming object. Modeling it
// honestly keeps the callers from assuming an incremental API the socket does
// not offer.
type AFALGSkcipher struct {
	tfm  int // the bound transformation socket
	op   int // the accepted operation socket
	name string
	key  []byte
}

// newAFALGSkcipher binds an AF_ALG skcipher socket to name, installs the key,
// and accepts one operation socket.
func newAFALGSkcipher(name string, key []byte) (*AFALGSkcipher, error) {
	if name == "" {
		return nil, errors.New("af_alg: empty algorithm name")
	}
	if len(name) > 63 {
		return nil, fmt.Errorf("af_alg: algorithm name %q exceeds 63 bytes", name)
	}
	if len(key) == 0 {
		return nil, errors.New("af_alg: empty key")
	}

	fd, err := syscall.Socket(afALG, syscall.SOCK_SEQPACKET, 0)
	if err != nil {
		return nil, fmt.Errorf("af_alg: socket: %w", err)
	}

	if err := bindAFALG(fd, "skcipher", name); err != nil {
		syscall.Close(fd)
		return nil, err
	}

	// ALG_SET_KEY takes the raw key bytes with an explicit length, so it must go
	// through setsockopt directly rather than SetsockoptString, which would
	// append a NUL byte and change the key length.
	_, _, errno := syscall.Syscall6(syscall.SYS_SETSOCKOPT,
		uintptr(fd), solALG, algSetKey,
		uintptr(unsafe.Pointer(&key[0])), uintptr(len(key)), 0)
	if errno != 0 {
		syscall.Close(fd)
		return nil, fmt.Errorf("af_alg: setsockopt(ALG_SET_KEY) on %s: %w", name, errno)
	}

	op, _, errno := syscall.Syscall6(syscall.SYS_ACCEPT4,
		uintptr(fd), 0, 0, 0, 0, 0)
	if errno != 0 {
		syscall.Close(fd)
		return nil, fmt.Errorf("af_alg: accept4(%s): %w", name, errno)
	}

	// Keep a copy of the key: it is only needed to prove the socket was set up
	// with the length the caller asked for, but retaining it makes the struct
	// self-describing for the benchmark report.
	kcopy := make([]byte, len(key))
	copy(kcopy, key)

	return &AFALGSkcipher{tfm: fd, op: int(op), name: name, key: kcopy}, nil
}

// Name reports the kernel algorithm name.
func (c *AFALGSkcipher) Name() string { return c.name }

// KeyLen reports the key length installed on the socket.
func (c *AFALGSkcipher) KeyLen() int { return len(c.key) }

// cmsgLen returns the space one control message occupies, header and payload
// rounded up to the alignment the kernel expects.
func cmsgLen(payload int) int {
	n := cmsgHeaderLen + payload
	return (n + cmsgAlign - 1) &^ (cmsgAlign - 1)
}

// putCmsg writes one control message into buf at off and returns the offset of
// the next one. The caller has already sized buf with cmsgLen.
func putCmsg(buf []byte, off, level, typ int, payload []byte) int {
	// struct cmsghdr { size_t cmsg_len; int cmsg_level; int cmsg_type; }
	// cmsg_len counts the header and the payload but not the padding.
	binary.NativeEndian.PutUint64(buf[off:], uint64(cmsgHeaderLen+len(payload)))
	binary.NativeEndian.PutUint32(buf[off+8:], uint32(level))
	binary.NativeEndian.PutUint32(buf[off+12:], uint32(typ))
	copy(buf[off+cmsgHeaderLen:], payload)
	return off + cmsgLen(len(payload))
}

// afalgChunkSize is the largest payload submitted in one sendmsg.
//
// AF_ALG is a socket: the transformation socket has an SO_SNDBUF of 256 KiB, and
// a sendmsg larger than the buffer blocks forever because the kernel does not
// drain it until the reader starts, which the single-threaded caller has not
// done yet. 64 KiB is comfortably below that ceiling on every kernel this has
// been run against and is also the granularity dm-crypt uses in practice.
const afalgChunkSize = 64 * 1024

// advanceTweak applies n GF(2^128) doublings to the tweak in place.
func advanceTweak(t []byte, n int) {
	for i := 0; i < n; i++ {
		gfMulX(t)
	}
}

// xtsHardwareChunked runs one XTS data unit of arbitrary length through the
// kernel, splitting it into sendmsg-sized pieces.
//
// Chunking is required, not an optimisation: any data unit above SO_SNDBUF
// deadlocks otherwise. The subtlety is that the chunks are *not* independent.
// XTS derives block i's tweak as
//
//	T_i = mulx^i(E_k2(tweak))
//
// so the tweak advances in the *encrypted* domain, not in the raw domain.
// E_k2(mulx^i(tweak)) is not the same value, and passing the raw advanced tweak
// to a later chunk silently produces ciphertext that disagrees with the
// single-message path and with every other implementation. The kernel takes a
// raw tweak and encrypts it itself, so each chunk must be handed
// D_k2(T_i) — the value whose k2-encryption is the tweak the chunk needs. That
// is one AES block decrypt per chunk, which is free next to 64 KiB of KMF.
//
// The last 16+rem bytes are always submitted as a single message when the length
// is not a multiple of 16, so ciphertext stealing happens once, inside the
// kernel, over the same two blocks the unchunked call would have used.
func xtsHardwareChunked(c *AFALGSkcipher, k2, out, in, tweak []byte, encrypt bool) error {
	c2, err := aes.NewCipher(k2)
	if err != nil {
		return fmt.Errorf("xts: tweak key: %w", err)
	}

	// T is the encrypted tweak for the block the next chunk starts on.
	var t [16]byte
	c2.Encrypt(t[:], tweak)

	// A tail of 16+rem bytes is one CTS unit and must not be split.
	tail := 0
	if rem := len(in) % XTSBlockSize; rem != 0 {
		tail = XTSBlockSize + rem
	}
	body := len(in) - tail

	var iv [16]byte
	for off := 0; off < body; {
		n := body - off
		if n > afalgChunkSize {
			n = afalgChunkSize
		}
		// Hand the kernel the raw tweak whose k2-encryption is t.
		c2.Decrypt(iv[:], t[:])
		if _, err := c.Crypt(out[off:off+n], in[off:off+n], iv[:], encrypt); err != nil {
			return err
		}
		advanceTweak(t[:], n/XTSBlockSize)
		off += n
	}
	if tail > 0 {
		c2.Decrypt(iv[:], t[:])
		if _, err := c.Crypt(out[body:], in[body:], iv[:], encrypt); err != nil {
			return err
		}
	}
	return nil
}

// Crypt runs one data unit through the kernel.
//
// out and in must be the same length; out may not alias in, because the kernel
// writes the result while it still holds the input. The return value is out, so
// callers can chain the call.
//
// The payload must fit in the transformation socket's send buffer. The XTS
// caller never hits that limit because it goes through xtsHardwareChunked.
func (c *AFALGSkcipher) Crypt(out, in, iv []byte, encrypt bool) ([]byte, error) {
	if len(out) != len(in) {
		return nil, fmt.Errorf("af_alg: output buffer is %d bytes but input is %d", len(out), len(in))
	}
	if len(iv) == 0 {
		return nil, errors.New("af_alg: empty IV")
	}
	if len(iv) > 0xffff {
		return nil, fmt.Errorf("af_alg: IV of %d bytes is too long", len(iv))
	}

	op := uint32(algOpDecrypt)
	if encrypt {
		op = algOpEncrypt
	}

	// ALG_SET_OP carries a bare native-endian uint32.
	var opPayload [4]byte
	binary.NativeEndian.PutUint32(opPayload[:], op)

	// ALG_SET_IV carries a native-endian length prefix followed by the IV. The
	// length is the IV length in bytes, not including the prefix.
	ivPayload := make([]byte, 4+len(iv))
	binary.NativeEndian.PutUint32(ivPayload[:4], uint32(len(iv)))
	copy(ivPayload[4:], iv)

	oob := make([]byte, cmsgLen(len(opPayload))+cmsgLen(len(ivPayload)))
	off := putCmsg(oob, 0, solALG, algSetOP, opPayload[:])
	putCmsg(oob, off, solALG, algSetIV, ivPayload)

	if err := sendmsgAFALG(c.op, in, oob); err != nil {
		return nil, err
	}

	// The kernel produces exactly len(in) bytes for a skcipher operation, but a
	// read on a socket is allowed to return less, so loop rather than trusting a
	// single call.
	total := 0
	for total < len(out) {
		n, err := syscall.Read(c.op, out[total:])
		if err != nil {
			return nil, fmt.Errorf("af_alg: read: %w", err)
		}
		if n == 0 {
			return nil, fmt.Errorf("af_alg: read returned %d of %d bytes", total, len(out))
		}
		total += n
	}
	return out, nil
}

// sendmsgAFALG submits data with the prepared control buffer.
//
// syscall.SendmsgN takes the out-of-band bytes as a []byte and builds the
// msghdr itself, which is exactly what the kernel wants and avoids hand-rolling
// an msghdr struct whose field layout differs between ABIs.
func sendmsgAFALG(fd int, data, oob []byte) error {
	if _, err := syscall.SendmsgN(fd, data, oob, nil, 0); err != nil {
		return fmt.Errorf("af_alg: sendmsg: %w", err)
	}
	return nil
}

// Close releases both sockets.
func (c *AFALGSkcipher) Close() error {
	var first error
	if c.op >= 0 {
		if err := syscall.Close(c.op); err != nil {
			first = err
		}
		c.op = -1
	}
	if c.tfm >= 0 {
		if err := syscall.Close(c.tfm); err != nil && first == nil {
			first = err
		}
		c.tfm = -1
	}
	return first
}
