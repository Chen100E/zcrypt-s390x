package cipher

// AF_ALG: the kernel crypto API's userspace socket interface.
//
// Linux exposes every algorithm registered in /proc/crypto to userspace over
// the AF_ALG address family (see Documentation/crypto/userspace-if.rst). A
// caller binds a socket to (type, name), accepts a connection from it, writes
// the message to the accepted socket, and reads the result back.
//
// On s390x this is the only way to measure CPACF SHA-3 from Go without either
// adding golang.org/x/crypto or writing assembly for the KIMD function codes.
// The kernel's sha3-256-s390 driver sits behind the socket, so the bytes
// genuinely go through KIMD.
//
// The interface is built on raw syscalls rather than golang.org/x/sys/unix so
// that go.mod stays at zero requires. Two details make that work:
//
//   - syscall.Socket accepts AF_ALG as a plain int. The constant is not exported
//     by package syscall on all architectures, but the numeric value 38 is
//     fixed by the kernel ABI.
//   - The sockaddr_alg struct is a fixed 88-byte layout: 2 bytes of family,
//     14 bytes of type name, 4 bytes of feature flags, 4 bytes of mask, then
//     64 bytes of algorithm name. It is laid out identically on every
//     architecture because all the fields are byte arrays, so no endianness
//     conversion is needed beyond the family word.
//
// Everything here degrades to a clean error rather than a panic when AF_ALG is
// compiled out of the kernel, blocked by a seccomp policy, or absent because
// the machine is not Linux. The callers treat that as "hardware path not
// available" and fall back to the pure-Go implementation.

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

const (
	// afALG is AF_ALG. Not every GOARCH exports it from package syscall, so the
	// numeric ABI value is used directly.
	afALG = 38

	// algSockaddrSize is sizeof(struct sockaddr_alg):
	//   __u16 salg_family (2) + __u8 salg_type[14] + __u32 salg_feat (4)
	//   + __u32 salg_mask (4) + __u8 salg_name[64] = 88
	algSockaddrSize = 88

	// Layout offsets within sockaddr_alg.
	algOffType = 2  // salg_type[14]
	algOffName = 24 // salg_name[64]
)

// AFALGHash is a hash.Hash-alike backed by an AF_ALG socket.
//
// It deliberately does not implement hash.Hash: the AF_ALG interface has no
// "sum without resetting" operation, so a Sum() that left the state intact
// would have to buffer the whole message. The benchmark and the verifier both
// want one-shot semantics, so the smaller interface is the honest one.
type AFALGHash struct {
	tfm  int // the bound transformation socket
	op   int // the accepted operation socket
	name string
	size int
}

// newAFALGHash binds an AF_ALG socket to the named kernel hash algorithm and
// accepts one operation socket.
func newAFALGHash(name string) (*AFALGHash, error) {
	if name == "" {
		return nil, errors.New("af_alg: empty algorithm name")
	}
	if len(name) > 63 {
		return nil, fmt.Errorf("af_alg: algorithm name %q exceeds 63 bytes", name)
	}

	fd, err := syscall.Socket(afALG, syscall.SOCK_SEQPACKET, 0)
	if err != nil {
		return nil, fmt.Errorf("af_alg: socket: %w", err)
	}

	if err := bindAFALG(fd, "hash", name); err != nil {
		syscall.Close(fd)
		return nil, err
	}

	op, _, errno := syscall.Syscall6(syscall.SYS_ACCEPT4,
		uintptr(fd), 0, 0, 0, 0, 0)
	if errno != 0 {
		syscall.Close(fd)
		return nil, fmt.Errorf("af_alg: accept4(%s): %w", name, errno)
	}

	h := &AFALGHash{tfm: fd, op: int(op), name: name}
	// The digest length is fixed per algorithm; discover it once by hashing the
	// empty message, which is cheap and also proves the socket works.
	//
	// The probe leaves the socket in the "message consumed" state, so it must be
	// reset afterwards. Skipping that reset is subtle: the caller's first Write
	// would be appended to nothing and its first Sum would return the empty
	// message's digest, which looks like a correct-length digest of the wrong
	// data.
	d, err := h.Sum()
	if err != nil {
		h.Close()
		return nil, err
	}
	h.size = len(d)
	if err := h.Reset(); err != nil {
		h.Close()
		return nil, err
	}
	return h, nil
}

// bindAFALG writes a sockaddr_alg and binds the socket to it.
func bindAFALG(fd int, typ, name string) error {
	var sa [algSockaddrSize]byte

	// salg_family is a native-endian __u16. The rest of the struct is byte
	// arrays, so this is the only field that needs an endianness decision, and
	// on s390x (big-endian) writing the low byte first would be wrong.
	sa[0] = byte(afALG >> 8)
	sa[1] = byte(afALG)
	copy(sa[algOffType:algOffType+14], typ)
	copy(sa[algOffName:algOffName+64], name)

	_, _, errno := syscall.Syscall(syscall.SYS_BIND, uintptr(fd),
		uintptr(unsafe.Pointer(&sa[0])), algSockaddrSize)
	if errno != 0 {
		return fmt.Errorf("af_alg: bind(%s/%s): %w", typ, name, errno)
	}
	return nil
}

// Write submits the message. The kernel hashes whatever is written before the
// next Read.
func (h *AFALGHash) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	n, err := syscall.Write(h.op, p)
	if err != nil {
		return n, fmt.Errorf("af_alg: write: %w", err)
	}
	return n, nil
}

// Sum reads the digest for everything written since the last Reset.
func (h *AFALGHash) Sum() ([]byte, error) {
	if h.size == 0 {
		h.size = 64 // upper bound while discovering the real length
	}
	buf := make([]byte, h.size)
	n, err := syscall.Read(h.op, buf)
	if err != nil {
		return nil, fmt.Errorf("af_alg: read: %w", err)
	}
	if n == 0 {
		return nil, errors.New("af_alg: read returned no digest")
	}
	h.size = n
	return buf[:n], nil
}

// Size reports the digest length in bytes.
func (h *AFALGHash) Size() int { return h.size }

// Name reports the kernel algorithm name.
func (h *AFALGHash) Name() string { return h.name }

// Reset starts a new message on the same socket pair.
//
// AF_ALG has no explicit reset operation. Closing and re-accepting the
// operation socket from the still-bound transformation socket is the
// documented way to start over, and it costs one syscall pair.
func (h *AFALGHash) Reset() error {
	if h.op >= 0 {
		syscall.Close(h.op)
		h.op = -1
	}
	op, _, errno := syscall.Syscall6(syscall.SYS_ACCEPT4,
		uintptr(h.tfm), 0, 0, 0, 0, 0)
	if errno != 0 {
		return fmt.Errorf("af_alg: accept4 on reset: %w", errno)
	}
	h.op = int(op)
	return nil
}

// Close releases both sockets.
func (h *AFALGHash) Close() error {
	var first error
	if h.op >= 0 {
		if err := syscall.Close(h.op); err != nil {
			first = err
		}
		h.op = -1
	}
	if h.tfm >= 0 {
		if err := syscall.Close(h.tfm); err != nil && first == nil {
			first = err
		}
		h.tfm = -1
	}
	return first
}

// probeAFALGHash checks that AF_ALG can open the named hash and produce a
// digest. It is the capability test behind SHA3HardwareInfo.AFALGAvailable.
func probeAFALGHash(name string) error {
	h, err := newAFALGHash(name)
	if err != nil {
		return err
	}
	defer h.Close()
	if _, err := h.Write([]byte("zcrypt")); err != nil {
		return err
	}
	d, err := h.Sum()
	if err != nil {
		return err
	}
	if len(d) == 0 {
		return errors.New("af_alg: empty digest")
	}
	return nil
}
