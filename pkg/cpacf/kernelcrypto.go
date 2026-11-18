package cpacf

import (
	"bufio"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
)

// KernelAlgorithm describes the crypto API backend that the Linux kernel has
// actually bound for one algorithm name.
//
// The kernel keeps several implementations of the same algorithm registered
// side by side and dispatches to the one with the highest priority. On s390x
// the CPACF-backed implementations register at priority 300 and are named with
// an "-s390" suffix, while the portable C implementations register at priority
// 100 and end in "-generic". Reading /proc/crypto therefore yields direct,
// kernel-side proof that hardware acceleration is engaged: if the winning
// driver for "aes" is "aes-s390" rather than "aes-generic", every kernel
// consumer of AES (dm-crypt, IPsec, kTLS, AF_ALG) is issuing KM/KMC
// instructions instead of running table-driven software AES.
type KernelAlgorithm struct {
	Name     string `json:"name"`
	Driver   string `json:"driver"`
	Module   string `json:"module"`
	Priority int    `json:"priority"`
	Type     string `json:"type"`
	Async    bool   `json:"async"`
	Selftest string `json:"selftest"`
	Hardware bool   `json:"hardware"`
	// Alternatives lists every registered driver for this name, highest
	// priority first. It is what makes the "hardware won" claim auditable.
	Alternatives []string `json:"alternatives,omitempty"`
}

// KernelCryptoReport is the parsed form of /proc/crypto.
type KernelCryptoReport struct {
	Available  bool              `json:"available"`
	Error      string            `json:"error,omitempty"`
	Algorithms []KernelAlgorithm `json:"algorithms"`
	// HardwareCount is the number of algorithms whose winning driver is a
	// CPACF-backed s390 implementation.
	HardwareCount int `json:"hardware_count"`
	TotalCount    int `json:"total_count"`
}

// InterestingAlgorithms is the set of algorithm names the report and the
// Prometheus exporter surface. These are exactly the primitives ZCrypt
// benchmarks, so that a reader can line up "what we measured" with "what the
// kernel dispatched".
var InterestingAlgorithms = []string{
	"aes",
	"cbc(aes)",
	"ctr(aes)",
	"ecb(aes)",
	"gcm(aes)",
	"xts(aes)",
	"sha1",
	"sha256",
	"sha512",
	"sha3-256",
	"sha3-512",
	"ghash",
	"des3_ede",
	"crc32-vx",
}

// DetectKernelCrypto parses /proc/crypto.
func DetectKernelCrypto() KernelCryptoReport {
	f, err := os.Open("/proc/crypto")
	if err != nil {
		return KernelCryptoReport{Error: "open /proc/crypto: " + err.Error()}
	}
	defer f.Close()
	return ParseKernelCrypto(f)
}

// ParseKernelCrypto parses a /proc/crypto stream.
//
// Each entry is a blank-line separated block of "key : value" pairs. Only the
// fields ZCrypt needs are retained; unknown keys are ignored so that newer
// kernels do not break the parser.
func ParseKernelCrypto(r io.Reader) KernelCryptoReport {
	rep := KernelCryptoReport{Available: true}
	if r == nil {
		return KernelCryptoReport{Error: "no reader"}
	}

	var (
		current KernelAlgorithm
		started bool
		all     []KernelAlgorithm
	)

	flush := func() {
		if !started {
			return
		}
		if current.Name != "" {
			current.Hardware = isHardwareDriver(current.Driver)
			all = append(all, current)
		}
		current = KernelAlgorithm{}
		started = false
	}

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			flush()
			continue
		}
		key, value, ok := splitCPUInfoLine(line)
		if !ok {
			continue
		}
		started = true
		switch key {
		case "name":
			current.Name = value
		case "driver":
			current.Driver = value
		case "module":
			current.Module = value
		case "priority":
			if n, err := strconv.Atoi(value); err == nil {
				current.Priority = n
			}
		case "type":
			current.Type = value
		case "async":
			current.Async = value == "yes"
		case "selftest":
			current.Selftest = value
		}
	}
	flush()

	// Group by algorithm name and elect the highest-priority driver. Ties are
	// broken by driver name so the result is deterministic across kernels.
	type group struct {
		best KernelAlgorithm
		alts []KernelAlgorithm
	}
	groups := make(map[string]*group)
	for _, a := range all {
		g, ok := groups[a.Name]
		if !ok {
			g = &group{best: a}
			groups[a.Name] = g
		} else if a.Priority > g.best.Priority ||
			(a.Priority == g.best.Priority && a.Driver < g.best.Driver) {
			g.best = a
		}
		g.alts = append(g.alts, a)
	}

	names := make([]string, 0, len(groups))
	for n := range groups {
		names = append(names, n)
	}
	sort.Strings(names)

	for _, n := range names {
		g := groups[n]
		best := g.best
		alts := g.alts
		sort.Slice(alts, func(i, j int) bool {
			if alts[i].Priority != alts[j].Priority {
				return alts[i].Priority > alts[j].Priority
			}
			return alts[i].Driver < alts[j].Driver
		})
		for _, a := range alts {
			best.Alternatives = append(best.Alternatives, a.Driver)
		}
		rep.Algorithms = append(rep.Algorithms, best)
		rep.TotalCount++
		if best.Hardware {
			rep.HardwareCount++
		}
	}
	return rep
}

// Lookup returns the winning backend for an algorithm name.
func (r KernelCryptoReport) Lookup(name string) (KernelAlgorithm, bool) {
	for _, a := range r.Algorithms {
		if a.Name == name {
			return a, true
		}
	}
	return KernelAlgorithm{}, false
}

// isHardwareDriver reports whether a kernel crypto driver name denotes a
// CPACF-backed s390x implementation.
//
// The naming conventions in the kernel are:
//   - aes-s390, sha256-s390, ghash-s390 ...      CPACF (KM/KMC/KIMD/KLMD/KMA)
//   - cbc-aes-s390, ctr-aes-s390, gcm-aes-s390   CPACF with a mode wrapper
//   - crc32-vx, crc32be-vx, crc32c-vx            vector-facility CRC
//   - *-generic, *-scomp, kernel                portable software
func isHardwareDriver(driver string) bool {
	d := strings.ToLower(driver)
	if strings.HasSuffix(d, "-s390") {
		return true
	}
	if strings.Contains(d, "-s390") {
		return true
	}
	// Vector-facility CRC implementations are hardware too, but they are not
	// CPACF; they are reported as hardware since they are not generic C code.
	if strings.HasSuffix(d, "-vx") {
		return true
	}
	return false
}

// HardwareAlgorithms returns only the algorithms dispatched to CPACF hardware,
// restricted to InterestingAlgorithms when restrict is true.
func (r KernelCryptoReport) HardwareAlgorithms(restrict bool) []KernelAlgorithm {
	want := make(map[string]bool, len(InterestingAlgorithms))
	for _, n := range InterestingAlgorithms {
		want[n] = true
	}
	var out []KernelAlgorithm
	for _, a := range r.Algorithms {
		if !a.Hardware {
			continue
		}
		if restrict && !want[a.Name] {
			continue
		}
		out = append(out, a)
	}
	return out
}
