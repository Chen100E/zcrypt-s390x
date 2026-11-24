package cipher

// AF_ALG for keyed hashes: GHASH.
//
// afalg.go covers the SHA family, which takes no key. GHASH is a keyed hash —
// the "key" is the hash subkey H = E_K(0^128) — so reaching the kernel's
// ghash-s390 driver needs one extra socket option before the operation socket is
// accepted:
//
//	bind(tfm, "hash", "ghash")
//	setsockopt(tfm, SOL_ALG, ALG_SET_KEY, H, 16)
//	accept4(tfm) -> op
//	write(op, message)
//	read(op, 16)
//
// ghash-s390 registers at priority 300 and lowers to KIMD function code 65
// (MSA-4), so on a LinuxONE host the bytes go through CPACF. On a host without
// that driver the kernel either has no "ghash" at all or has only
// ghash-generic; both cases surface here as a bind or write error and the
// callers treat that as "hardware path unavailable" rather than failing.
//
// One AF_ALG detail matters for correctness and is relied on deliberately: the
// kernel pads a trailing partial block with zeros before hashing, and an empty
// message hashes to 0^128. That matches GHASHSum's Sum() semantics exactly, so
// the two implementations can be compared on messages of any length rather than
// only on block-aligned ones.

import (
	"errors"
	"fmt"
	"syscall"
	"time"
	"unsafe"
)

// AFALGGHash is a GHASH instance backed by an AF_ALG socket pair.
//
// It has the same one-shot semantics as AFALGHash: the kernel finalises on
// read, so there is no "sum without resetting". Reset re-accepts the operation
// socket, which is the documented way to start a new message.
type AFALGGHash struct {
	tfm int // the bound, keyed transformation socket
	op  int // the accepted operation socket
}

// newAFALGGHash binds an AF_ALG socket to ("hash", "ghash"), installs H as the
// key, and accepts one operation socket.
func newAFALGGHash(h []byte) (*AFALGGHash, error) {
	if len(h) != ghashBlockSize {
		return nil, fmt.Errorf("af_alg: ghash key must be %d bytes, got %d", ghashBlockSize, len(h))
	}

	fd, err := syscall.Socket(afALG, syscall.SOCK_SEQPACKET, 0)
	if err != nil {
		return nil, fmt.Errorf("af_alg: socket: %w", err)
	}

	if err := bindAFALG(fd, "hash", "ghash"); err != nil {
		syscall.Close(fd)
		return nil, err
	}

	// The key must be installed on the transformation socket before accept4:
	// once an operation socket exists the key is already bound into it.
	_, _, errno := syscall.Syscall6(syscall.SYS_SETSOCKOPT,
		uintptr(fd), solALG, algSetKey,
		uintptr(unsafe.Pointer(&h[0])), uintptr(len(h)), 0)
	if errno != 0 {
		syscall.Close(fd)
		return nil, fmt.Errorf("af_alg: setsockopt(ALG_SET_KEY, ghash): %w", errno)
	}

	op, _, errno := syscall.Syscall6(syscall.SYS_ACCEPT4,
		uintptr(fd), 0, 0, 0, 0, 0)
	if errno != 0 {
		syscall.Close(fd)
		return nil, fmt.Errorf("af_alg: accept4(ghash): %w", errno)
	}

	return &AFALGGHash{tfm: fd, op: int(op)}, nil
}

// Write submits the message. The kernel hashes whatever was written before the
// next Read.
func (g *AFALGGHash) Write(p []byte) (int, error) {
	if len(p) == 0 {
		// A zero-length write is meaningful for GHASH: it is how the empty
		// message is submitted, and the kernel answers with 0^128.
		if _, err := syscall.Write(g.op, nil); err != nil {
			return 0, fmt.Errorf("af_alg: write: %w", err)
		}
		return 0, nil
	}
	n, err := syscall.Write(g.op, p)
	if err != nil {
		return n, fmt.Errorf("af_alg: write: %w", err)
	}
	return n, nil
}

// Sum reads the 16-byte GHASH for everything written since the last Reset.
func (g *AFALGGHash) Sum() ([]byte, error) {
	buf := make([]byte, ghashBlockSize)
	n, err := syscall.Read(g.op, buf)
	if err != nil {
		return nil, fmt.Errorf("af_alg: read: %w", err)
	}
	if n != ghashBlockSize {
		return nil, fmt.Errorf("af_alg: ghash read returned %d bytes, want %d", n, ghashBlockSize)
	}
	return buf[:n], nil
}

// Reset starts a new message on the same socket pair.
func (g *AFALGGHash) Reset() error {
	if g.op >= 0 {
		syscall.Close(g.op)
		g.op = -1
	}
	op, _, errno := syscall.Syscall6(syscall.SYS_ACCEPT4,
		uintptr(g.tfm), 0, 0, 0, 0, 0)
	if errno != 0 {
		return fmt.Errorf("af_alg: accept4 on reset: %w", errno)
	}
	g.op = int(op)
	return nil
}

// Close releases both sockets.
func (g *AFALGGHash) Close() error {
	var first error
	if g.op >= 0 {
		if err := syscall.Close(g.op); err != nil {
			first = err
		}
		g.op = -1
	}
	if g.tfm >= 0 {
		if err := syscall.Close(g.tfm); err != nil && first == nil {
			first = err
		}
		g.tfm = -1
	}
	return first
}

// ErrGHASHUnavailable is returned when the AF_ALG GHASH path cannot be used.
var ErrGHASHUnavailable = errors.New("ghash: AF_ALG hardware path unavailable")

// probeAFALGGHash checks that AF_ALG can open a keyed ghash socket and produce
// an answer. It is the capability test behind GHASHHardwareInfo.AFALGAvailable.
func probeAFALGGHash(h []byte) error {
	g, err := newAFALGGHash(h)
	if err != nil {
		return err
	}
	defer g.Close()
	if _, err := g.Write([]byte("zcrypt")); err != nil {
		return err
	}
	d, err := g.Sum()
	if err != nil {
		return err
	}
	if len(d) != ghashBlockSize {
		return errors.New("af_alg: ghash probe returned the wrong length")
	}
	return nil
}

// GHASHHardwareInfo reports whether the kernel exposes a CPACF-backed GHASH
// driver and whether the AF_ALG interface can reach it.
type GHASHHardwareInfo struct {
	// KernelDriver is the /proc/crypto driver name, e.g. "ghash-s390".
	KernelDriver string `json:"kernel_driver"`
	// KernelPriority is that driver's priority. CPACF drivers register at 300.
	KernelPriority int `json:"kernel_priority"`
	// Hardware is true when the driver is a CPACF implementation, which the
	// cpacf package decides from the driver name.
	Hardware bool `json:"hardware"`
	// AFALGAvailable is true when a keyed ghash socket was opened and used.
	AFALGAvailable bool   `json:"af_alg_available"`
	Error          string `json:"error,omitempty"`
}

// GHASHKernelInfo reads /proc/crypto for "ghash" and, when the selected driver
// is a CPACF one, checks that AF_ALG can actually reach it.
//
// The two checks answer different questions, exactly as in SHA3KernelInfo: the
// /proc/crypto entry says which driver the kernel itself will use, and the
// AF_ALG probe says whether userspace can measure that driver.
func GHASHKernelInfo() GHASHHardwareInfo {
	info := GHASHHardwareInfo{}
	report := detectKernelCryptoFor("ghash")
	alg, ok := report["ghash"]
	if !ok {
		info.Error = "no driver registered for ghash"
		return info
	}
	info.KernelDriver = alg.Driver
	info.KernelPriority = alg.Priority
	info.Hardware = alg.Hardware

	// The probe needs a key. Any 16-byte value works: the point is to prove
	// the socket opens and the key is accepted, not to check a digest here.
	probeKey := make([]byte, ghashBlockSize)
	if err := probeAFALGGHash(probeKey); err != nil {
		info.Error = "AF_ALG probe: " + err.Error()
	} else {
		info.AFALGAvailable = true
	}
	return info
}

// GHASHHardwareSum computes GHASH_H(msg) through AF_ALG, which on s390x reaches
// KIMD function code 65 in ghash-s390.
func GHASHHardwareSum(h, msg []byte) ([]byte, error) {
	g, err := newAFALGGHash(h)
	if err != nil {
		return nil, err
	}
	defer g.Close()
	if _, err := g.Write(msg); err != nil {
		return nil, err
	}
	return g.Sum()
}

// GHASHHardwareVerify hashes the same GHASH input through both paths and reports
// whether they agree bit for bit. This is the correctness gate for the hardware
// path, mirroring SHA3HardwareVerify: a fast wrong answer is worse than a slow
// right one.
//
// The message argument is the GHASH input, i.e. what GHASHMessage produces for a
// given (aad, ct) pair. Use GHASHHardwareVerifyGCM to compare the two paths on
// an (aad, ct) pair directly.
func GHASHHardwareVerify(h, msg []byte) (bool, error) {
	soft := GHASHSum(h, msg)
	if soft == nil {
		return false, fmt.Errorf("ghash: hash subkey H must be %d bytes", ghashBlockSize)
	}
	hard, err := GHASHHardwareSum(h, msg)
	if err != nil {
		return false, err
	}
	return bytesEqualConstTime(soft, hard), nil
}

// GHASHHardwareVerifyGCM is GHASHHardwareVerify over the GCM message
// construction: it builds pad16(aad)||pad16(ct)||len-block and compares both
// implementations on it. This is the form the report and the tests use, because
// it exercises the length block as well as the field arithmetic.
func GHASHHardwareVerifyGCM(aad, ct, h []byte) (bool, error) {
	return GHASHHardwareVerify(h, GHASHMessage(aad, ct))
}

// GHASHHardwareBenchmark measures GHASH through AF_ALG, which on s390x reaches
// the CPACF KIMD-GHASH function code in ghash-s390.
//
// The message is the padded block size, matching GHASHSoftwareBenchmark, so the
// two throughput figures are directly comparable.
func GHASHHardwareBenchmark(h []byte, blockSize, iterations int) (GHASHResult, error) {
	res := GHASHResult{Backend: "af_alg", BlockSize: blockSize, Iterations: iterations}
	if blockSize <= 0 || iterations <= 0 {
		return res, errors.New("ghash: block size and iterations must be positive")
	}

	g, err := newAFALGGHash(h)
	if err != nil {
		return res, err
	}
	defer g.Close()

	data := ghashBenchData(blockSize)

	t0 := time.Now()
	var sum []byte
	for i := 0; i < iterations; i++ {
		if err := g.Reset(); err != nil {
			return res, fmt.Errorf("ghash af_alg: reset: %w", err)
		}
		if _, err := g.Write(data); err != nil {
			return res, fmt.Errorf("ghash af_alg: write: %w", err)
		}
		sum, err = g.Sum()
		if err != nil {
			return res, fmt.Errorf("ghash af_alg: read: %w", err)
		}
	}
	dur := time.Since(t0).Seconds()

	totalMB := float64(len(data)) * float64(iterations) / (1024 * 1024)
	res.MBps = totalMB / dur
	res.Sum = hexEncode(sum)
	return res, nil
}
