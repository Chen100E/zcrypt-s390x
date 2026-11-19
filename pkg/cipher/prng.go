package cipher

// PRNG and entropy measurement for s390x.
//
// MSA-5 added PRNO (Perform Random Number Operation), which fills a buffer with
// cryptographically strong random bytes on chip. It is the hardware TRNG that
// the kernel's s390 trng driver draws from, and it is what makes /dev/hwrng
// exist on this machine.
//
// What this file can and cannot measure, stated plainly because the distinction
// matters for anyone reading the numbers:
//
//   - crypto/rand.Read on s390x does NOT issue PRNO. Go's crypto/rand is a
//     userspace ChaCha20-based DRBG seeded once from getrandom(2). So the
//     MB/s figure below is the cost of Go's DRBG, not of the hardware TRNG.
//   - The hardware TRNG is reachable through /dev/hwrng (the kernel trng
//     driver) and through getrandom(2) when the kernel's CRNG is seeded from
//     it. ZCrypt measures /dev/hwrng separately so the two are not conflated.
//   - The PRNO facility bit (STFLE bit 57) is read from /proc/cpuinfo, which is
//     the authoritative statement that the instruction exists. ZCrypt cannot
//     issue PRNO from Go: the assembler has no mnemonic for it, and unlike
//     KDSA/KIMD there is no kernel crypto API algorithm that maps onto it in a
//     way userspace can drive.
//
// The statistical checks below are smoke tests, not a randomness test suite.
// They catch gross faults -- a stuck bit, a constant, a counter that only ever
// increments, an entropy pool that returns the same block twice -- and nothing
// more. Passing them is not evidence of cryptographic quality; failing them is
// solid evidence of a problem.

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Chen100E/zcrypt-s390x/pkg/cpacf"
)

// PRNGBenchmarkResult is the measured cost of generating random bytes.
type PRNGBenchmarkResult struct {
	Source     string  `json:"source"`
	BlockSize  int     `json:"block_size"`
	Iterations int     `json:"iterations"`
	MBps       float64 `json:"mbps"`
	BytesTotal int64   `json:"bytes_total"`
	NanosTotal int64   `json:"nanos_total"`
	Error      string  `json:"error,omitempty"`
}

// BenchmarkCryptoRand measures crypto/rand.Read throughput.
//
// The buffer is allocated once outside the loop and reused, so the figure is the
// cost of the DRBG rather than of the allocator. On s390x this measures Go's
// ChaCha20 DRBG, not PRNO -- see the file comment.
func BenchmarkCryptoRand(blockSize, iterations int) (PRNGBenchmarkResult, error) {
	res := PRNGBenchmarkResult{
		Source:     "crypto/rand",
		BlockSize:  blockSize,
		Iterations: iterations,
	}
	if blockSize <= 0 || iterations <= 0 {
		return res, errors.New("prng: block size and iterations must be positive")
	}

	buf := make([]byte, blockSize)
	t0 := time.Now()
	for i := 0; i < iterations; i++ {
		if _, err := rand.Read(buf); err != nil {
			return res, fmt.Errorf("prng: crypto/rand read: %w", err)
		}
	}
	dur := time.Since(t0)

	res.NanosTotal = dur.Nanoseconds()
	res.BytesTotal = int64(blockSize) * int64(iterations)
	res.MBps = float64(res.BytesTotal) / (1024 * 1024) / dur.Seconds()
	return res, nil
}

// BenchmarkHWRNG measures /dev/hwrng throughput.
//
// /dev/hwrng is the kernel's trng driver, which on s390x reads from the CPACF
// PRNO instruction. It is root-only (mode 0600), so this returns a permission
// error rather than a number when run unprivileged; the caller reports that
// honestly instead of substituting the crypto/rand figure.
//
// Reads are capped at 32 bytes per call deliberately: the trng driver's read
// path has a per-call fixed cost that dominates small reads, and measuring it at
// its natural granularity is more useful than pretending a 1 MiB read is one
// operation. The buffer size parameter sets the *total* per iteration instead,
// and the loop issues as many 32-byte reads as needed.
func BenchmarkHWRNG(blockSize, iterations int) (PRNGBenchmarkResult, error) {
	res := PRNGBenchmarkResult{
		Source:     "/dev/hwrng",
		BlockSize:  blockSize,
		Iterations: iterations,
	}
	if blockSize <= 0 || iterations <= 0 {
		return res, errors.New("prng: block size and iterations must be positive")
	}

	f, err := os.Open("/dev/hwrng")
	if err != nil {
		return res, fmt.Errorf("prng: open /dev/hwrng: %w", err)
	}
	defer f.Close()

	const chunk = 32
	if blockSize < chunk {
		return res, fmt.Errorf("prng: /dev/hwrng block size must be at least %d bytes", chunk)
	}
	buf := make([]byte, blockSize)

	t0 := time.Now()
	for i := 0; i < iterations; i++ {
		filled := 0
		for filled < blockSize {
			n, err := f.Read(buf[filled:])
			if err != nil {
				return res, fmt.Errorf("prng: read /dev/hwrng: %w", err)
			}
			if n == 0 {
				return res, errors.New("prng: /dev/hwrng returned zero bytes")
			}
			filled += n
		}
	}
	dur := time.Since(t0)

	res.NanosTotal = dur.Nanoseconds()
	res.BytesTotal = int64(blockSize) * int64(iterations)
	res.MBps = float64(res.BytesTotal) / (1024 * 1024) / dur.Seconds()
	return res, nil
}

// EntropyPoolStatus reports the kernel's entropy accounting.
//
// entropy_avail is the number of bits the kernel believes it has collected.
// poolsize is the CRNG's capacity (256 bits on every modern kernel). The
// distinction that matters operationally: entropy_avail saturating at poolsize
// means the pool is full and getrandom(2) will not block, which is the normal
// steady state on a machine with a hardware TRNG. A machine whose entropy_avail
// hovers near zero will block in getrandom(2) during early boot.
type EntropyPoolStatus struct {
	EntropyAvail int    `json:"entropy_avail"`
	PoolSize     int    `json:"pool_size"`
	ReadWakeup   int    `json:"read_wakeup_threshold"`
	WriteWakeup  int    `json:"write_wakeup_threshold"`
	URandomMin   int    `json:"urandom_min_reseed_secs"`
	Full         bool   `json:"pool_full"`
	Error        string `json:"error,omitempty"`
}

// ReadEntropyPoolStatus reads /proc/sys/kernel/random/*.
func ReadEntropyPoolStatus() EntropyPoolStatus {
	var st EntropyPoolStatus
	read := func(name string) (int, error) {
		b, err := os.ReadFile("/proc/sys/kernel/random/" + name)
		if err != nil {
			return 0, err
		}
		return strconv.Atoi(strings.TrimSpace(string(b)))
	}

	var err error
	if st.EntropyAvail, err = read("entropy_avail"); err != nil {
		st.Error = "entropy_avail: " + err.Error()
		return st
	}
	if st.PoolSize, err = read("poolsize"); err != nil {
		st.Error = "poolsize: " + err.Error()
		return st
	}
	// These two are optional: their paths have moved between kernel versions and
	// their absence is not an error.
	st.ReadWakeup, _ = read("read_wakeup_threshold")
	st.WriteWakeup, _ = read("write_wakeup_threshold")
	st.URandomMin, _ = read("urandom_min_reseed_secs")
	st.Full = st.PoolSize > 0 && st.EntropyAvail >= st.PoolSize
	return st
}

// HWRNGStatus reports whether the hardware TRNG is exposed to userspace.
type HWRNGStatus struct {
	// DeviceExists is true when /dev/hwrng is present.
	DeviceExists bool `json:"device_exists"`
	// Readable is true when this process can open it. It is root-only on
	// purpose; a false value here is a permission fact, not a hardware fact.
	Readable bool `json:"readable"`
	// PRNOFacility is STFLE bit 57, the authoritative statement that the PRNO
	// instruction exists on this machine.
	PRNOFacility bool `json:"prno_facility"`
	// MaxMSALevel is included so a reader can see that PRNO (MSA-5) is below
	// the machine's ceiling.
	MaxMSALevel int    `json:"max_msa_level"`
	Error       string `json:"error,omitempty"`
}

// ReadHWRNGStatus inspects /dev/hwrng and the STFLE bits.
func ReadHWRNGStatus(caps cpacf.HardwareCapabilities) HWRNGStatus {
	st := HWRNGStatus{
		PRNOFacility: caps.HasPRNO,
		MaxMSALevel:  caps.MaxMSALevel,
	}
	if info, err := os.Stat("/dev/hwrng"); err == nil && info.Mode()&os.ModeCharDevice != 0 {
		st.DeviceExists = true
	}
	if st.DeviceExists {
		f, err := os.Open("/dev/hwrng")
		if err != nil {
			st.Error = "open /dev/hwrng: " + err.Error()
		} else {
			st.Readable = true
			f.Close()
		}
	}
	return st
}

// RandomnessReport is the outcome of the statistical smoke tests.
//
// Every field is a measured quantity, not a pass/fail opinion, because the
// thresholds that make a "pass" meaningful depend on the sample size.
type RandomnessReport struct {
	SampleBytes int `json:"sample_bytes"`

	// ByteHistogram is the count of each byte value. A healthy uniform sample of
	// N bytes has each count near N/256.
	ByteHistogram [256]int `json:"-"`
	// ByteChiSquare is the chi-square statistic against a uniform distribution
	// with 255 degrees of freedom. The 0.999 critical value is about 344; a
	// value far above that indicates a grossly non-uniform source.
	ByteChiSquare float64 `json:"byte_chi_square"`
	// HistogramMin and HistogramMax bound the per-byte counts.
	HistogramMin int `json:"histogram_min"`
	HistogramMax int `json:"histogram_max"`

	// BitBalance is the fraction of one bits. A healthy source is near 0.5.
	BitBalance float64 `json:"bit_balance"`
	// Ones and Zeros are the absolute bit counts.
	Ones  int64 `json:"ones"`
	Zeros int64 `json:"zeros"`

	// DistinctBlocks is how many distinct 16-byte blocks appeared, and
	// DuplicateBlocks is how many repeats there were. For a sample of N blocks
	// from a 128-bit space the expected number of duplicates is essentially
	// zero, so any duplicate is a serious finding.
	DistinctBlocks  int `json:"distinct_blocks"`
	DuplicateBlocks int `json:"duplicate_blocks"`
	TotalBlocks     int `json:"total_blocks"`

	// LongestRun is the longest run of identical consecutive bytes. For a
	// uniform source of N bytes the expected longest run is small (a handful);
	// a run of hundreds means a stuck source.
	LongestRun int `json:"longest_run"`

	// SerialCorrelation is the Pearson correlation between adjacent bytes. A
	// healthy source is near zero; a counter-like source is near 1.
	SerialCorrelation float64 `json:"serial_correlation"`

	// EntropyPerByte is Shannon entropy of the byte histogram in bits, with a
	// ceiling of 8.0. It cannot distinguish good randomness from a well-mixed
	// counter, so it is reported as a diagnostic rather than a test.
	EntropyPerByte float64 `json:"entropy_per_byte"`
}

// AnalyzeRandomness computes the smoke-test statistics over a sample.
func AnalyzeRandomness(sample []byte) RandomnessReport {
	rep := RandomnessReport{SampleBytes: len(sample)}
	if len(sample) == 0 {
		return rep
	}

	// --- byte histogram ---
	for _, b := range sample {
		rep.ByteHistogram[b]++
	}
	expected := float64(len(sample)) / 256.0
	chi := 0.0
	first := true
	for _, c := range rep.ByteHistogram {
		if first {
			rep.HistogramMin, rep.HistogramMax = c, c
			first = false
		}
		if c < rep.HistogramMin {
			rep.HistogramMin = c
		}
		if c > rep.HistogramMax {
			rep.HistogramMax = c
		}
		d := float64(c) - expected
		chi += d * d / expected
	}
	rep.ByteChiSquare = chi

	// --- bit balance ---
	for _, b := range sample {
		for bit := 0; bit < 8; bit++ {
			if b&(1<<bit) != 0 {
				rep.Ones++
			} else {
				rep.Zeros++
			}
		}
	}
	total := rep.Ones + rep.Zeros
	if total > 0 {
		rep.BitBalance = float64(rep.Ones) / float64(total)
	}

	// --- duplicate 16-byte blocks ---
	const blockLen = 16
	if len(sample) >= blockLen {
		seen := make(map[string]struct{}, len(sample)/blockLen)
		for off := 0; off+blockLen <= len(sample); off += blockLen {
			key := string(sample[off : off+blockLen])
			rep.TotalBlocks++
			if _, dup := seen[key]; dup {
				rep.DuplicateBlocks++
			} else {
				seen[key] = struct{}{}
			}
		}
		rep.DistinctBlocks = len(seen)
	}

	// --- longest identical-byte run ---
	run := 1
	best := 1
	for i := 1; i < len(sample); i++ {
		if sample[i] == sample[i-1] {
			run++
			if run > best {
				best = run
			}
		} else {
			run = 1
		}
	}
	rep.LongestRun = best

	// --- serial correlation between adjacent bytes ---
	if len(sample) >= 2 {
		n := float64(len(sample) - 1)
		var sumX, sumY, sumXY, sumX2, sumY2 float64
		for i := 0; i+1 < len(sample); i++ {
			x := float64(sample[i])
			y := float64(sample[i+1])
			sumX += x
			sumY += y
			sumXY += x * y
			sumX2 += x * x
			sumY2 += y * y
		}
		num := n*sumXY - sumX*sumY
		den := math.Sqrt((n*sumX2 - sumX*sumX) * (n*sumY2 - sumY*sumY))
		if den != 0 {
			rep.SerialCorrelation = num / den
		}
	}

	// --- Shannon entropy of the byte histogram ---
	ent := 0.0
	n := float64(len(sample))
	for _, c := range rep.ByteHistogram {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		ent -= p * math.Log2(p)
	}
	rep.EntropyPerByte = ent

	return rep
}

// Anomalies returns a list of human-readable findings, one per statistic that
// is outside a generous bound. An empty list means the sample passed the smoke
// tests, which is a weak statement: see the file comment.
func (r RandomnessReport) Anomalies() []string {
	var out []string
	if r.SampleBytes == 0 {
		return []string{"empty sample"}
	}

	// Chi-square: 255 degrees of freedom. 344 is the 0.999 quantile, so anything
	// above it is a one-in-a-thousand event for a uniform source and worth
	// reporting. The bound is deliberately loose because this is a smoke test.
	if r.ByteChiSquare > 344 {
		out = append(out, fmt.Sprintf(
			"byte histogram chi-square %.1f exceeds 344 (255 dof, 0.999 quantile); distribution is not uniform",
			r.ByteChiSquare))
	}

	// Bit balance: a deviation of more than 1% from 0.5 over a large sample is
	// not plausible for a healthy source.
	if r.BitBalance < 0.49 || r.BitBalance > 0.51 {
		out = append(out, fmt.Sprintf(
			"bit balance %.4f is outside 0.49..0.51; the source is biased", r.BitBalance))
	}

	// Any duplicate 16-byte block in a sample of this size is a finding.
	if r.DuplicateBlocks > 0 {
		out = append(out, fmt.Sprintf(
			"%d duplicate 16-byte blocks out of %d; a 128-bit source should produce none",
			r.DuplicateBlocks, r.TotalBlocks))
	}

	// A run of 16 identical bytes has probability 256^-15, so a run this long
	// means the source is stuck rather than unlucky.
	if r.LongestRun > 16 {
		out = append(out, fmt.Sprintf(
			"longest identical-byte run is %d; the source appears to be stuck", r.LongestRun))
	}

	// Serial correlation: adjacent bytes should be independent.
	if r.SerialCorrelation > 0.1 || r.SerialCorrelation < -0.1 {
		out = append(out, fmt.Sprintf(
			"serial correlation %.4f is outside -0.1..0.1; adjacent bytes are dependent",
			r.SerialCorrelation))
	}

	// Shannon entropy: a full 8 bits requires all 256 values present. Anything
	// below 7.9 in a large sample means some byte values never occur.
	if r.SampleBytes >= 65536 && r.EntropyPerByte < 7.9 {
		out = append(out, fmt.Sprintf(
			"Shannon entropy %.4f bits/byte is below 7.9; some byte values are missing",
			r.EntropyPerByte))
	}

	return out
}

// PRNGSuite runs the full PRNG measurement: crypto/rand throughput, /dev/hwrng
// throughput when permitted, entropy pool state, hardware status, and the
// statistical smoke tests over a fresh crypto/rand sample.
type PRNGSuiteResult struct {
	CryptoRand   PRNGBenchmarkResult  `json:"crypto_rand"`
	HWRNG        *PRNGBenchmarkResult `json:"hwrng,omitempty"`
	HWRNGError   string               `json:"hwrng_error,omitempty"`
	Entropy      EntropyPoolStatus    `json:"entropy_pool"`
	Hardware     HWRNGStatus          `json:"hwrng_status"`
	Randomness   RandomnessReport     `json:"randomness"`
	Anomalies    []string             `json:"anomalies,omitempty"`
	SampleSource string               `json:"sample_source"`
}

// RunPRNGSuite executes every PRNG measurement.
func RunPRNGSuite(caps cpacf.HardwareCapabilities, blockSize, iterations int) (PRNGSuiteResult, error) {
	var out PRNGSuiteResult

	cr, err := BenchmarkCryptoRand(blockSize, iterations)
	if err != nil {
		return out, err
	}
	out.CryptoRand = cr

	out.Entropy = ReadEntropyPoolStatus()
	out.Hardware = ReadHWRNGStatus(caps)

	// /dev/hwrng is root-only; measure it when possible and record the reason
	// when not, rather than silently omitting the row.
	if hw, err := BenchmarkHWRNG(blockSize, iterations); err != nil {
		out.HWRNGError = err.Error()
	} else {
		out.HWRNG = &hw
	}

	// The statistical sample comes from crypto/rand, because that is the source
	// every caller in this program actually uses. Sampling /dev/hwrng would test
	// the TRNG's raw output, which is not what any application sees.
	sample := make([]byte, 256*1024)
	if _, err := rand.Read(sample); err != nil {
		return out, fmt.Errorf("prng: read statistical sample: %w", err)
	}
	out.SampleSource = "crypto/rand"
	out.Randomness = AnalyzeRandomness(sample)
	out.Anomalies = out.Randomness.Anomalies()

	return out, nil
}

// PRNGSources measures several independent sources so a reader can see they do
// not agree byte for byte, which is the property that actually distinguishes a
// random source from a deterministic one.
type SourceComparison struct {
	Sources     []string `json:"sources"`
	SampleBytes int      `json:"sample_bytes"`
	// IdenticalPairs lists the source pairs whose samples were byte-identical.
	// For independent random sources this must be empty; a non-empty list means
	// two "different" sources are in fact the same generator.
	IdenticalPairs []string `json:"identical_pairs,omitempty"`
	Error          string   `json:"error,omitempty"`
}

// CompareSources draws a sample from each available source and checks that no
// two are identical.
func CompareSources(sampleBytes int) SourceComparison {
	out := SourceComparison{SampleBytes: sampleBytes}
	if sampleBytes <= 0 {
		out.Error = "sample size must be positive"
		return out
	}

	samples := map[string][]byte{}
	add := func(name string, b []byte, err error) {
		if err != nil {
			return
		}
		samples[name] = b
		out.Sources = append(out.Sources, name)
	}

	a := make([]byte, sampleBytes)
	_, err := rand.Read(a)
	add("crypto/rand", a, err)

	b := make([]byte, sampleBytes)
	_, err = rand.Read(b)
	add("crypto/rand (second draw)", b, err)

	if f, err := os.Open("/dev/hwrng"); err == nil {
		h := make([]byte, sampleBytes)
		filled := 0
		for filled < sampleBytes {
			n, rerr := f.Read(h[filled:])
			if rerr != nil {
				break
			}
			filled += n
		}
		f.Close()
		if filled == sampleBytes {
			add("/dev/hwrng", h, nil)
		}
	}

	names := make([]string, 0, len(samples))
	for n := range samples {
		names = append(names, n)
	}
	for i := 0; i < len(names); i++ {
		for j := i + 1; j < len(names); j++ {
			if bytesEqualConstTime(samples[names[i]], samples[names[j]]) {
				out.IdenticalPairs = append(out.IdenticalPairs,
					names[i]+" == "+names[j])
			}
		}
	}
	return out
}

// bytesEqualConstTime compares two slices without early exit. It is used only
// for a diagnostic comparison of two random samples, so timing is not a threat
// model here, but writing it this way costs nothing and avoids the reflex of
// reaching for a fast path in crypto-adjacent code.
func bytesEqualConstTime(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// PRNGInfo bundles the static facts a report needs to explain the numbers.
type PRNGInfo struct {
	// PRNOFacility is STFLE bit 57 (MSA-5).
	PRNOFacility bool `json:"prno_facility"`
	// GoUsesPRNO is false, and that is the point: crypto/rand does not issue
	// PRNO on s390x. It is a ChaCha20 DRBG seeded from getrandom(2).
	GoUsesPRNO bool `json:"go_crypto_rand_uses_prno"`
	// KernelTRNGDriver names the driver behind /dev/hwrng when known.
	KernelTRNGDriver string `json:"kernel_trng_driver"`
	Notes            string `json:"notes"`
}

// ReadPRNGInfo gathers the static PRNG facts.
func ReadPRNGInfo(caps cpacf.HardwareCapabilities) PRNGInfo {
	info := PRNGInfo{
		PRNOFacility: caps.HasPRNO,
		GoUsesPRNO:   false,
	}
	// The kernel's s390 trng driver registers a "stdrng" or "jitterentropy_rng"
	// hwrng source. Both names appear in /proc/crypto; the hwrng core also
	// exposes the active one under /sys/class/misc/hw_random.
	if b, err := os.ReadFile("/sys/class/misc/hw_random/rng_current"); err == nil {
		info.KernelTRNGDriver = strings.TrimSpace(string(b))
	}
	if info.PRNOFacility {
		info.Notes = "PRNO exists on this machine (MSA-5); Go's crypto/rand does not issue it, " +
			"so the crypto/rand throughput is the DRBG cost and the TRNG is reached via /dev/hwrng"
	} else {
		info.Notes = "PRNO facility bit is clear; this machine has no CPACF random number instruction"
	}
	return info
}
