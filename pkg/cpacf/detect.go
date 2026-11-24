package cpacf

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

// STFLE (Store Facility List Extended) facility bit numbers, as printed by the
// Linux kernel on the "facilities" line of /proc/cpuinfo.
//
// The numbering is the one used by z/Architecture Principles of Operation
// (SA22-7832): bit 0 is the leftmost bit of the 192-bit facility list. These
// constants are cross-checked against three independent sources:
//
//   - IBM s390-tools rust/cpacfinfo/src/msa.rs (msa2stfle)
//   - OpenSSL doc/man3/OPENSSL_s390xcap.pod
//   - Go runtime internal/cpu/cpu_s390x.go
//
// Note that only a subset of the MSA extensions has its own STFLE bit. MSA-1,
// MSA-2, MSA-6, MSA-7, MSA-10, MSA-11 and MSA-13 are announced implicitly and
// must be confirmed by executing the CPACF Query function of the relevant
// instruction (see query.go).
const (
	FacilityZArch    = 1   // z/Architecture mode active
	FacilitySTFLE    = 7   // store-facility-list-extended
	FacilityMSA      = 17  // Message-Security-Assist base (KM/KMC/KIMD/KLMD)
	FacilityMSA3     = 76  // MSA extension 3 (PCKMO, wrapped keys)
	FacilityMSA4     = 77  // MSA extension 4 (KMF/KMCTR/KMO, KIMD-GHASH)
	FacilityMSA5     = 57  // MSA extension 5 (PRNO)
	FacilityMSA12    = 86  // MSA extension 12
	FacilityVector   = 129 // Vector facility
	FacilityVectorE1 = 135 // Vector enhancements 1
	FacilityMSA8     = 146 // MSA extension 8 (KMA, AES-GCM in one instruction)
	FacilityMSA9     = 155 // MSA extension 9 (KDSA, ECC)
)

// HardwareCapabilities describes the on-chip crypto and vector capabilities of
// the host. It is the top-level type serialised by `zcrypt -json`.
type HardwareCapabilities struct {
	Arch           string   `json:"arch"`
	MachineType    string   `json:"machine_type"`
	HasCPACF       bool     `json:"has_cpacf"`
	HasVector      bool     `json:"has_vector"`
	HasNNPA        bool     `json:"has_nnpa"`
	CryptoFeatures []string `json:"crypto_features"`
	Endianness     string   `json:"endianness"`

	// MaxMSALevel is the highest Message-Security-Assist extension level that
	// could be positively confirmed, either from its STFLE bit or from a CPACF
	// Query function-code bitmap.
	MaxMSALevel int `json:"max_msa_level"`

	// Derived capability flags. These describe which CPACF instruction families
	// are usable, not merely which facility bits are set.
	HasAES      bool `json:"has_aes"`         // MSA-1/2 + KM-AES-128/192/256
	HasAESGCM   bool `json:"has_aes_gcm"`     // MSA-8 KMA, or MSA-4 KMCTR + GHASH
	HasSHA3     bool `json:"has_sha3"`        // MSA-6 KIMD/KLMD-SHA3
	HasSHAKE    bool `json:"has_shake"`       // MSA-6 KIMD/KLMD-SHAKE128/256
	HasECC      bool `json:"has_ecc"`         // MSA-9 KDSA
	HasGHASH    bool `json:"has_ghash"`       // MSA-4 KIMD-GHASH
	HasPRNO     bool `json:"has_prno"`        // MSA-5 PRNO
	HasWrappedK bool `json:"has_wrapped_key"` // MSA-3 PCKMO

	// FacilityBits is the raw, sorted STFLE bit list as reported by the kernel.
	FacilityBits []int `json:"facility_bits"`
}

// MSAFacilityBits lists every MSA extension level that owns a dedicated STFLE
// bit, together with that bit number.
var MSAFacilityBits = []struct {
	Level int
	Bit   int
}{
	{3, FacilityMSA3},
	{4, FacilityMSA4},
	{5, FacilityMSA5},
	{8, FacilityMSA8},
	{9, FacilityMSA9},
	{12, FacilityMSA12},
}

// Detect inspects /proc/cpuinfo on LinuxONE for s390x hardware crypto
// extensions. On non-s390x hosts it returns a zero-valued capability set with
// the architecture recorded, which keeps the tool usable (and testable) on
// amd64/arm64 CI runners.
func Detect() HardwareCapabilities {
	f, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return DetectFrom(nil)
	}
	defer f.Close()
	return DetectFrom(f)
}

// DetectFrom parses a /proc/cpuinfo stream. A nil reader yields the
// architecture-only default.
func DetectFrom(r io.Reader) HardwareCapabilities {
	caps := HardwareCapabilities{
		Arch:       runtime.GOARCH,
		Endianness: endianness(),
	}
	if r == nil {
		caps.MachineType = fmt.Sprintf("IBM zSeries (%s)", runtime.GOARCH)
		return caps
	}

	var (
		bits    = make(map[int]bool)
		feature = make(map[string]bool)
	)

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		key, value, ok := splitCPUInfoLine(line)
		if !ok {
			continue
		}
		switch key {
		case "machine", "vendor_id":
			// "machine" carries the IBM machine type (e.g. 9175 for z15);
			// vendor_id is "IBM/S390" and is only a fallback.
			if key == "machine" && value != "" {
				caps.MachineType = value
			} else if caps.MachineType == "" && value != "" {
				caps.MachineType = value
			}
		case "features":
			for _, f := range strings.Fields(value) {
				feature[f] = true
			}
		case "facilities":
			for _, f := range strings.Fields(value) {
				n, err := strconv.Atoi(f)
				if err != nil {
					continue
				}
				bits[n] = true
			}
		}
	}

	if caps.MachineType == "" {
		caps.MachineType = fmt.Sprintf("IBM zSeries (%s)", runtime.GOARCH)
	}

	for n := range bits {
		caps.FacilityBits = append(caps.FacilityBits, n)
	}
	sort.Ints(caps.FacilityBits)

	caps.HasCPACF = feature["msa"] || bits[FacilityMSA]
	caps.HasVector = feature["vx"] || bits[FacilityVector]
	caps.HasNNPA = feature["nnpa"]
	caps.HasWrappedK = bits[FacilityMSA3]
	caps.HasPRNO = bits[FacilityMSA5]
	caps.HasGHASH = bits[FacilityMSA4]
	caps.HasECC = bits[FacilityMSA9]

	// The STFLE list is authoritative for the levels that own a bit. MSA-1 and
	// MSA-2 have no bit of their own: every machine that implements MSA at all
	// implements KM-AES-128 (MSA-1) and KM-AES-192/256 (MSA-2).
	if caps.HasCPACF {
		caps.MaxMSALevel = 2
		caps.CryptoFeatures = []string{"msa", "msa1", "msa2"}
		for _, e := range MSAFacilityBits {
			if bits[e.Bit] {
				caps.CryptoFeatures = append(caps.CryptoFeatures, "msa"+strconv.Itoa(e.Level))
				if e.Level > caps.MaxMSALevel {
					caps.MaxMSALevel = e.Level
				}
			}
		}
	}
	caps.HasAES = caps.HasCPACF
	// AES-GCM needs either KMA (MSA-8) or the KMCTR+GHASH pair (MSA-4).
	caps.HasAESGCM = bits[FacilityMSA8] || bits[FacilityMSA4]
	// SHA-3 and SHAKE share the MSA-6 rung and neither has a STFLE bit of its
	// own, so both start false here and are proven only by a Query bitmap.
	caps.HasSHA3 = false
	caps.HasSHAKE = false

	sort.Strings(caps.CryptoFeatures)
	return caps
}

// RefineWithQuery upgrades a Detect() result using live CPACF Query results.
// Query bitmaps are the only way to confirm the MSA levels that have no STFLE
// bit of their own (MSA-6 SHA-3, MSA-7 PRNO, MSA-10 full-XTS, MSA-13 QAI) and
// they are also the only way to prove that a specific AES key size is really
// implemented in silicon rather than merely announced by a facility bit.
func RefineWithQuery(caps HardwareCapabilities, q Query) HardwareCapabilities {
	if !q.Available {
		return caps
	}

	if q.KM.Has(FuncKMAES128) && q.KM.Has(FuncKMAES192) && q.KM.Has(FuncKMAES256) {
		caps.HasAES = true
	}
	if q.KMA.Has(FuncKMAAES256) {
		caps.HasAESGCM = true
	}
	if q.KMCTR.Has(FuncKMCTRAES256) && q.KIMD.Has(FuncKIMDGHASH) {
		caps.HasAESGCM = true
	}
	if q.KIMD.Has(FuncKIMDGHASH) {
		caps.HasGHASH = true
	}
	if q.KIMD.Has(FuncKIMDSHA3_224) && q.KIMD.Has(FuncKIMDSHA3_256) &&
		q.KIMD.Has(FuncKIMDSHA3_384) && q.KIMD.Has(FuncKIMDSHA3_512) {
		caps.HasSHA3 = true
	}
	// SHAKE is a separate function-code pair in the same KIMD bitmap: 36 and 37.
	// It is not implied by SHA-3 (a machine may implement one family and not the
	// other, and the Query bitmap is per-function-code), so it is proven
	// independently.
	if q.KIMD.Has(FuncKIMDSHAKE128) && q.KIMD.Has(FuncKIMDSHAKE256) {
		caps.HasSHAKE = true
	}
	if q.KDSA.Available() {
		caps.HasECC = true
	}
	// PCKMO (MSA-3 wrapped keys) and PRNO (MSA-5) have no Go assembler
	// mnemonic, so they cannot be re-confirmed here; the STFLE facility bits
	// read by Detect() are authoritative for them.

	// Walk the levels we can now prove, from the top down, and take the first
	// one that holds. MSA-10 (full-XTS) and MSA-13 (QAI) are only observable
	// through KMO/KMF and the Query-Auth-Info function, so they are left to the
	// STFLE bits.
	switch {
	case q.HasQAI():
		caps.MaxMSALevel = maxInt(caps.MaxMSALevel, 13)
	case q.KDSA.Available():
		caps.MaxMSALevel = maxInt(caps.MaxMSALevel, 9)
	case q.KMA.Available():
		caps.MaxMSALevel = maxInt(caps.MaxMSALevel, 8)
	case caps.HasSHA3, caps.HasSHAKE:
		// SHA-3 (function codes 32-35) and SHAKE (36-37) are both MSA-6, so
		// either one proves the same rung. Neither raises the level past 6.
		caps.MaxMSALevel = maxInt(caps.MaxMSALevel, 6)
	}

	// Rebuild the feature list from the refined level so that the reported
	// "crypto_features" never contradicts "max_msa_level".
	if caps.HasCPACF {
		caps.CryptoFeatures = msaFeatureList(caps.MaxMSALevel)
	}
	return caps
}

// msaFeatureList renders the MSA level ladder up to max as feature tokens.
func msaFeatureList(max int) []string {
	out := []string{"msa"}
	for lvl := 1; lvl <= max; lvl++ {
		out = append(out, "msa"+strconv.Itoa(lvl))
	}
	return out
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// splitCPUInfoLine splits a "key : value" line from /proc/cpuinfo. The s390x
// kernel uses a tab before the colon ("features\t: ...") while other
// architectures use spaces, so both are handled.
func splitCPUInfoLine(line string) (key, value string, ok bool) {
	i := strings.IndexByte(line, ':')
	if i < 0 {
		return "", "", false
	}
	key = strings.TrimSpace(line[:i])
	value = strings.TrimSpace(line[i+1:])
	if key == "" {
		return "", "", false
	}
	return key, value, true
}

func endianness() string {
	// runtime.GOARCH is a compile-time constant; s390x is the only big-endian
	// architecture Go currently supports for Linux.
	if runtime.GOARCH == "s390x" {
		return "Big-Endian (MSB)"
	}
	return "Little-Endian (LSB)"
}
