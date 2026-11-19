package main

// Small platform helpers used by the watch loop and the report.
//
// These live in their own file so the watch logic reads as logic rather than as
// a pile of os/exec calls, and so the two values that come from outside Go (the
// toolchain version and the kernel release) have one place to be wrong.

import (
	"crypto/sha256"
	"hash"
	"os"
	"runtime"
	"strings"

	"github.com/Chen100E/zcrypt-s390x/pkg/cpacf"
)

// runtimeVersion reports the toolchain version the binary was built with.
func runtimeVersion() string { return runtime.Version() }

// kernelRelease reads the running kernel release from /proc/sys/kernel/osrelease.
//
// It is read from procfs rather than shelled out to uname so the binary has no
// external process dependency, which matters for the exporter running in a
// container.
func kernelRelease() string {
	b, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(b))
}

// newSHA256 is the constructor passed to cipher.BenchmarkHash for the SHA-256
// rows. Declared as a function so the call sites read as "benchmark this hash"
// rather than "benchmark sha256.New".
func newSHA256() hash.Hash { return sha256.New() }

// cipherCaps is the hardware-capability snapshot used by the tests and by any
// caller that needs a fingerprint without re-detecting. It is a thin wrapper so
// tests do not import cpacf directly for one call.
func cipherCaps() cpacf.HardwareCapabilities { return cpacf.Detect() }
