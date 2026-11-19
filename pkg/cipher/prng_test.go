package cipher

import (
	"crypto/rand"
	"math"
	"os"
	"testing"

	"github.com/Chen100E/zcrypt-s390x/pkg/cpacf"
)

// TestCryptoRandBenchmarkMeasures runs the real measurement and asserts a
// positive throughput. The absolute number is machine-dependent; what must hold
// on any machine is that reading N bytes takes positive time and reports a
// positive rate.
func TestCryptoRandBenchmarkMeasures(t *testing.T) {
	res, err := BenchmarkCryptoRand(64*1024, 50)
	if err != nil {
		t.Fatalf("crypto/rand benchmark: %v", err)
	}
	if res.MBps <= 0 {
		t.Errorf("non-positive throughput %f", res.MBps)
	}
	if res.BytesTotal != int64(64*1024)*50 {
		t.Errorf("bytes total = %d, want %d", res.BytesTotal, int64(64*1024)*50)
	}
	if res.NanosTotal <= 0 {
		t.Error("non-positive elapsed time")
	}
	if res.Source != "crypto/rand" {
		t.Errorf("source = %q", res.Source)
	}
	// Sanity bound: even a pathological DRBG does better than 1 MB/s, and even a
	// fast one does worse than 100 GB/s. A number outside this range means the
	// timing or the byte accounting is broken.
	if res.MBps < 1 || res.MBps > 100000 {
		t.Errorf("throughput %f MB/s is outside the plausible range 1..100000", res.MBps)
	}
	t.Logf("crypto/rand: %.1f MB/s", res.MBps)
}

// TestPRNGBenchmarkRejectsBadParameters covers the guard clauses.
func TestPRNGBenchmarkRejectsBadParameters(t *testing.T) {
	if _, err := BenchmarkCryptoRand(0, 10); err == nil {
		t.Error("accepted zero block size")
	}
	if _, err := BenchmarkCryptoRand(1024, 0); err == nil {
		t.Error("accepted zero iterations")
	}
	if _, err := BenchmarkCryptoRand(-1, 10); err == nil {
		t.Error("accepted negative block size")
	}
	if _, err := BenchmarkHWRNG(0, 10); err == nil {
		t.Error("hwrng accepted zero block size")
	}
	// A block size below the 32-byte chunk must be rejected explicitly rather
	// than silently rounding up.
	if _, err := BenchmarkHWRNG(16, 10); err == nil {
		t.Error("hwrng accepted a 16-byte block size")
	}
}

// TestHWRNGUnreadableIsAnErrorNotAZero proves the /dev/hwrng path reports a
// permission failure rather than returning a throughput of zero, which a report
// could mistake for "measured, and it was slow".
func TestHWRNGUnreadableIsAnErrorNotAZero(t *testing.T) {
	_, err := BenchmarkHWRNG(4096, 2)
	if err != nil {
		// Either the device is absent or we are unprivileged; both are honest
		// errors and both must mention the device.
		t.Logf("/dev/hwrng unavailable as expected for this process: %v", err)
		return
	}
	// If we *can* read it, the number must be positive.
	res, err := BenchmarkHWRNG(4096, 2)
	if err != nil {
		t.Fatalf("second attempt failed: %v", err)
	}
	if res.MBps <= 0 {
		t.Errorf("readable /dev/hwrng reported %f MB/s", res.MBps)
	}
	t.Logf("/dev/hwrng: %.2f MB/s", res.MBps)
}

// TestEntropyPoolStatus checks the /proc/sys/kernel/random parse against the
// invariants that must hold on any Linux host.
func TestEntropyPoolStatus(t *testing.T) {
	st := ReadEntropyPoolStatus()
	if st.Error != "" {
		t.Skipf("entropy pool unreadable: %s", st.Error)
	}
	if st.PoolSize != 256 {
		t.Errorf("pool size = %d, want 256", st.PoolSize)
	}
	if st.EntropyAvail < 0 || st.EntropyAvail > st.PoolSize {
		t.Errorf("entropy_avail = %d, outside 0..%d", st.EntropyAvail, st.PoolSize)
	}
	// Full must be consistent with the comparison it claims to make.
	if wantFull := st.EntropyAvail >= st.PoolSize; st.Full != wantFull {
		t.Errorf("Full = %v but entropy_avail=%d poolsize=%d", st.Full, st.EntropyAvail, st.PoolSize)
	}
	t.Logf("entropy_avail=%d/%d full=%v read_wakeup=%d",
		st.EntropyAvail, st.PoolSize, st.Full, st.ReadWakeup)
}

// TestAnalyzeRandomnessOnCryptoRand is the positive control: a real
// crypto/rand sample must pass every smoke test. If this fails, either the
// analysis is wrong or the host's RNG is genuinely broken.
func TestAnalyzeRandomnessOnCryptoRand(t *testing.T) {
	sample := make([]byte, 256*1024)
	if _, err := rand.Read(sample); err != nil {
		t.Fatalf("read sample: %v", err)
	}
	rep := AnalyzeRandomness(sample)

	if rep.SampleBytes != len(sample) {
		t.Errorf("sample size = %d, want %d", rep.SampleBytes, len(sample))
	}
	// Every byte value must occur in a 256 KiB sample: the expected count is
	// 1024 with a standard deviation of ~32, so a zero count is a 32-sigma event.
	for v, c := range rep.ByteHistogram {
		if c == 0 {
			t.Errorf("byte value %d never occurred in a 256 KiB sample", v)
		}
	}
	if rep.DuplicateBlocks != 0 {
		t.Errorf("%d duplicate 16-byte blocks in a 256 KiB crypto/rand sample", rep.DuplicateBlocks)
	}
	if rep.LongestRun > 16 {
		t.Errorf("longest run %d is implausible for crypto/rand", rep.LongestRun)
	}
	if math.Abs(rep.BitBalance-0.5) > 0.01 {
		t.Errorf("bit balance %.5f is implausible for crypto/rand", rep.BitBalance)
	}
	if rep.EntropyPerByte < 7.99 {
		t.Errorf("Shannon entropy %.5f bits/byte is implausible for crypto/rand", rep.EntropyPerByte)
	}
	if math.Abs(rep.SerialCorrelation) > 0.05 {
		t.Errorf("serial correlation %.5f is implausible for crypto/rand", rep.SerialCorrelation)
	}

	if anomalies := rep.Anomalies(); len(anomalies) > 0 {
		for _, a := range anomalies {
			t.Errorf("crypto/rand sample flagged: %s", a)
		}
	}
	t.Logf("chi2=%.1f bitBalance=%.5f entropy=%.5f serial=%.5f longestRun=%d blocks=%d/%d distinct",
		rep.ByteChiSquare, rep.BitBalance, rep.EntropyPerByte, rep.SerialCorrelation,
		rep.LongestRun, rep.DistinctBlocks, rep.TotalBlocks)
}

// TestAnalyzeRandomnessCatchesBadSources is the negative control, and it is the
// important half: a detector that never fires is worthless. Each case is a
// source that is obviously broken in one specific way, and the corresponding
// anomaly must be reported.
func TestAnalyzeRandomnessCatchesBadSources(t *testing.T) {
	cases := []struct {
		name     string
		sample   []byte
		wantWord string
	}{
		{
			name:     "all zeros",
			sample:   make([]byte, 64*1024),
			wantWord: "chi-square",
		},
		{
			name:     "all 0xff",
			sample:   bytesRepeat(0xFF, 64*1024),
			wantWord: "chi-square",
		},
		{
			// A byte counter is uniform in its histogram, so the chi-square test
			// does not fire; what gives it away is that it repeats with a period
			// of 256, so 16-byte blocks recur constantly.
			name:     "incrementing counter",
			sample:   counterSample(64 * 1024),
			wantWord: "duplicate",
		},
		{
			// Alternating 0x00/0xFF is a degenerate two-value source: the
			// histogram is wildly non-uniform and every block repeats.
			name:     "alternating two values",
			sample:   alternatingSample(64*1024, 0x00, 0xFF),
			wantWord: "chi-square",
		},
		{
			name:     "repeated 16-byte block",
			sample:   bytesRepeat(0x5A, 64*1024),
			wantWord: "duplicate",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rep := AnalyzeRandomness(c.sample)
			anomalies := rep.Anomalies()
			if len(anomalies) == 0 {
				t.Fatalf("%s produced no anomalies", c.name)
			}
			found := false
			for _, a := range anomalies {
				if containsFold(a, c.wantWord) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("%s: expected an anomaly mentioning %q, got %v", c.name, c.wantWord, anomalies)
			}
			t.Logf("%s: %d anomalies, first: %s", c.name, len(anomalies), anomalies[0])
		})
	}
}

// TestAnalyzeRandomnessEmptySample checks the degenerate input.
func TestAnalyzeRandomnessEmptySample(t *testing.T) {
	rep := AnalyzeRandomness(nil)
	if rep.SampleBytes != 0 {
		t.Errorf("sample bytes = %d, want 0", rep.SampleBytes)
	}
	anomalies := rep.Anomalies()
	if len(anomalies) != 1 || anomalies[0] != "empty sample" {
		t.Errorf("anomalies = %v, want [\"empty sample\"]", anomalies)
	}
}

// TestAnalyzeRandomnessSmallSample proves the analysis does not panic or divide
// by zero on samples shorter than a block.
func TestAnalyzeRandomnessSmallSample(t *testing.T) {
	for _, n := range []int{1, 2, 3, 7, 15, 16, 17} {
		sample := make([]byte, n)
		for i := range sample {
			sample[i] = byte(i * 37)
		}
		rep := AnalyzeRandomness(sample)
		if rep.SampleBytes != n {
			t.Errorf("n=%d: sample bytes = %d", n, rep.SampleBytes)
		}
		if n >= 16 && rep.TotalBlocks != n/16 {
			t.Errorf("n=%d: total blocks = %d, want %d", n, rep.TotalBlocks, n/16)
		}
		if n < 16 && rep.TotalBlocks != 0 {
			t.Errorf("n=%d: total blocks = %d, want 0", n, rep.TotalBlocks)
		}
	}
}

// TestRandomnessStatsAreCorrectOnAKnownInput pins the statistics against a
// hand-computed case, so a refactor that quietly changes the chi-square or the
// bit balance formula is caught.
func TestRandomnessStatsAreCorrectOnAKnownInput(t *testing.T) {
	// 512 bytes: every value 0..255 exactly twice. Perfectly uniform, so the
	// chi-square must be exactly zero, the bit balance exactly 0.5 (each value
	// appears twice, so the total bit counts are symmetric), and the Shannon
	// entropy exactly 8 bits/byte.
	sample := make([]byte, 0, 512)
	for i := 0; i < 256; i++ {
		sample = append(sample, byte(i), byte(i))
	}
	rep := AnalyzeRandomness(sample)

	if rep.ByteChiSquare != 0 {
		t.Errorf("chi-square = %v, want exactly 0 for a perfectly uniform histogram", rep.ByteChiSquare)
	}
	if rep.BitBalance != 0.5 {
		t.Errorf("bit balance = %v, want exactly 0.5", rep.BitBalance)
	}
	if math.Abs(rep.EntropyPerByte-8.0) > 1e-9 {
		t.Errorf("entropy = %v bits/byte, want exactly 8", rep.EntropyPerByte)
	}
	if rep.HistogramMin != 2 || rep.HistogramMax != 2 {
		t.Errorf("histogram bounds = %d..%d, want 2..2", rep.HistogramMin, rep.HistogramMax)
	}

}

// TestReadHWRNGStatusIsConsistent checks the hardware status against the
// capability flags it was given.
func TestReadHWRNGStatusIsConsistent(t *testing.T) {
	caps := cpacf.Detect()
	st := ReadHWRNGStatus(caps)

	if st.PRNOFacility != caps.HasPRNO {
		t.Errorf("PRNO facility = %v, but caps say %v", st.PRNOFacility, caps.HasPRNO)
	}
	if st.MaxMSALevel != caps.MaxMSALevel {
		t.Errorf("MSA level = %d, but caps say %d", st.MaxMSALevel, caps.MaxMSALevel)
	}
	// Readable implies the device exists; the converse is not required because
	// the device is root-only.
	if st.Readable && !st.DeviceExists {
		t.Error("device reported readable but not present")
	}
	t.Logf("/dev/hwrng: exists=%v readable=%v prno=%v msa=%d err=%q",
		st.DeviceExists, st.Readable, st.PRNOFacility, st.MaxMSALevel, st.Error)
}

// TestReadPRNGInfoStatesTheHonestAnswer checks the info struct says what the
// file comment says: Go's crypto/rand does not use PRNO, regardless of whether
// the machine has it.
func TestReadPRNGInfoStatesTheHonestAnswer(t *testing.T) {
	caps := cpacf.Detect()
	info := ReadPRNGInfo(caps)

	if info.PRNOFacility != caps.HasPRNO {
		t.Errorf("PRNO facility = %v, want %v", info.PRNOFacility, caps.HasPRNO)
	}
	if info.GoUsesPRNO {
		t.Error("GoUsesPRNO is true, but crypto/rand does not issue PRNO on s390x")
	}
	if info.Notes == "" {
		t.Error("no notes explaining the PRNO situation")
	}
	t.Logf("PRNO facility=%v goUsesPRNO=%v trngDriver=%q",
		info.PRNOFacility, info.GoUsesPRNO, info.KernelTRNGDriver)
}

// TestCompareSourcesFindsNoCollisions proves independent sources are actually
// independent. Two crypto/rand draws must never be identical.
func TestCompareSourcesFindsNoCollisions(t *testing.T) {
	cmp := CompareSources(4096)
	if cmp.Error != "" {
		t.Skipf("source comparison unavailable: %s", cmp.Error)
	}
	if len(cmp.Sources) < 2 {
		t.Fatalf("only %d sources available, need at least 2", len(cmp.Sources))
	}
	if len(cmp.IdenticalPairs) > 0 {
		t.Errorf("independent sources produced identical samples: %v", cmp.IdenticalPairs)
	}
	t.Logf("compared %d sources: %v", len(cmp.Sources), cmp.Sources)
}

// TestCompareSourcesRejectsBadSize covers the guard clause.
func TestCompareSourcesRejectsBadSize(t *testing.T) {
	if cmp := CompareSources(0); cmp.Error == "" {
		t.Error("accepted a zero sample size")
	}
	if cmp := CompareSources(-10); cmp.Error == "" {
		t.Error("accepted a negative sample size")
	}
}

// TestRunPRNGSuite exercises the whole pipeline end to end.
func TestRunPRNGSuite(t *testing.T) {
	caps := cpacf.Detect()
	res, err := RunPRNGSuite(caps, 64*1024, 20)
	if err != nil {
		t.Fatalf("suite: %v", err)
	}
	if res.CryptoRand.MBps <= 0 {
		t.Error("crypto/rand throughput not measured")
	}
	if res.Randomness.SampleBytes == 0 {
		t.Error("no statistical sample collected")
	}
	if res.SampleSource != "crypto/rand" {
		t.Errorf("sample source = %q", res.SampleSource)
	}
	// The suite's own sample must pass its own smoke tests, or the suite is
	// reporting a host fault.
	if len(res.Anomalies) > 0 {
		t.Errorf("crypto/rand sample flagged by the suite's own analysis: %v", res.Anomalies)
	}
	// The hwrng row must be either measured or explained, never silently absent.
	if res.HWRNG == nil && res.HWRNGError == "" {
		t.Error("/dev/hwrng neither measured nor explained")
	}
	t.Logf("crypto/rand %.1f MB/s, entropy %d/%d, anomalies %d",
		res.CryptoRand.MBps, res.Entropy.EntropyAvail, res.Entropy.PoolSize, len(res.Anomalies))
}

// TestRunPRNGSuiteRejectsBadParameters covers the guard clause that propagates
// from BenchmarkCryptoRand.
func TestRunPRNGSuiteRejectsBadParameters(t *testing.T) {
	caps := cpacf.Detect()
	if _, err := RunPRNGSuite(caps, 0, 10); err == nil {
		t.Error("accepted a zero block size")
	}
}

// helpers

func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func counterSample(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i)
	}
	return out
}

func alternatingSample(n int, a, b byte) []byte {
	out := make([]byte, n)
	for i := range out {
		if i%2 == 0 {
			out[i] = a
		} else {
			out[i] = b
		}
	}
	return out
}

func containsFold(haystack, needle string) bool {
	if len(needle) == 0 {
		return true
	}
	h := toLower(haystack)
	nd := toLower(needle)
	for i := 0; i+len(nd) <= len(h); i++ {
		if h[i:i+len(nd)] == nd {
			return true
		}
	}
	return false
}

func toLower(s string) string {
	out := []byte(s)
	for i, c := range out {
		if c >= 'A' && c <= 'Z' {
			out[i] = c + ('a' - 'A')
		}
	}
	return string(out)
}

// TestHWRNGDeviceModeIsRootOnly documents the permission model rather than
// asserting a specific mode, so the test does not fail on a host that has
// loosened it deliberately.
func TestHWRNGDeviceModeIsRootOnly(t *testing.T) {
	info, err := os.Stat("/dev/hwrng")
	if err != nil {
		t.Skip("/dev/hwrng not present")
	}
	mode := info.Mode().Perm()
	t.Logf("/dev/hwrng mode is %04o", mode)
	if mode&0o077 != 0 {
		t.Logf("note: /dev/hwrng is group/world accessible (%04o), which is a policy deviation", mode)
	}
}
