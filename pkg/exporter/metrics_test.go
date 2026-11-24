package exporter

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Chen100E/zcrypt-s390x/pkg/cipher"
	"github.com/Chen100E/zcrypt-s390x/pkg/cpacf"
)

// sampleSnapshot builds a fully-populated Snapshot so that Render can be
// exercised without touching /proc or running a benchmark.
func sampleSnapshot() Snapshot {
	var km cpacf.FunctionBitmap
	// KM-AES-128 (18), KM-AES-192 (19), KM-AES-256 (20), KM-XTS-AES-256 (52).
	for _, fc := range []uint{18, 19, 20, 52} {
		km[fc/8] |= 0x80 >> (fc % 8)
	}
	return Snapshot{
		Timestamp: time.Unix(1794969657, 0),
		Caps: cpacf.HardwareCapabilities{
			Arch:           "s390x",
			MachineType:    "9175",
			HasCPACF:       true,
			HasVector:      true,
			HasNNPA:        true,
			HasAES:         true,
			HasAESGCM:      true,
			HasGHASH:       true,
			HasSHA3:        true,
			HasSHAKE:       true,
			HasECC:         true,
			HasPRNO:        true,
			HasWrappedK:    true,
			CryptoFeatures: []string{"msa", "msa1", "msa2"},
			Endianness:     "Big-Endian (MSB)",
			MaxMSALevel:    13,
		},
		Query: cpacf.Query{Available: true, KM: km},
		Kernel: cpacf.KernelCryptoReport{
			Available: true,
			Algorithms: []cpacf.KernelAlgorithm{
				{Name: "aes", Driver: "aes-s390", Priority: 300, Type: "cipher", Hardware: true},
				{Name: "gcm(aes)", Driver: "gcm-aes-s390", Priority: 900, Type: "aead", Hardware: true},
				{Name: "sha256", Driver: "sha256-generic", Priority: 100, Type: "shash", Hardware: false},
			},
			HardwareCount: 2,
			TotalCount:    3,
		},
		AES: []cipher.AESGCMResult{
			{BlockSize: 1024, EncryptMBps: 7000, DecryptMBps: 6900},
			{BlockSize: 1048576, EncryptMBps: 13839.97, DecryptMBps: 14150.94},
		},
		SHA256MBps: 4339.68,
		SHA512MBps: 6793.86,
		// Two GHASH paths on the same buffer size. The hardware figure is what
		// ghash-s390 reports; the reference implementation is three orders of
		// magnitude slower, which is the whole argument for the CPACF path.
		GHASHSoftwareMBps: 6.62,
		GHASHHardwareMBps: 477.94,
		VectorsOK:         true,
		AESImpl: cipher.AESImplementation{
			Arch:         "s390x",
			AssemblyPath: true,
			Endianness:   "Big-Endian (MSB)",
			Description:  "CPACF assembly path",
		},
	}
}

func TestRenderProducesValidExposition(t *testing.T) {
	out := Render(sampleSnapshot())
	if out == "" {
		t.Fatal("Render produced an empty body")
	}
	if !strings.HasSuffix(out, "\n") {
		t.Error("exposition body must end with a newline")
	}

	// Every metric name must have exactly one HELP and one TYPE line, and every
	// sample line must belong to a family that was declared.
	declared := make(map[string]bool)
	samples := make(map[string]bool)
	for _, line := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		if strings.HasPrefix(line, "# HELP ") {
			name := strings.Fields(line)[2]
			if declared[name] {
				t.Errorf("duplicate HELP for %q", name)
			}
			declared[name] = true
			continue
		}
		if strings.HasPrefix(line, "# TYPE ") {
			fields := strings.Fields(line)
			if len(fields) != 4 {
				t.Errorf("malformed TYPE line: %q", line)
			}
			continue
		}
		if strings.HasPrefix(line, "#") {
			continue
		}
		name := line
		if i := strings.IndexAny(name, "{ "); i >= 0 {
			name = name[:i]
		}
		samples[name] = true
	}
	if len(declared) == 0 {
		t.Fatal("no HELP lines emitted")
	}
	for name := range samples {
		if !declared[name] {
			t.Errorf("sample %q has no HELP/TYPE declaration", name)
		}
	}
	for name := range declared {
		if !samples[name] {
			t.Errorf("%q declared but never sampled", name)
		}
	}
}

func TestRenderContainsExpectedMetrics(t *testing.T) {
	out := Render(sampleSnapshot())
	// These are the metric names a dashboard would depend on; a rename is a
	// breaking change and must be a deliberate test edit.
	for _, want := range []string{
		"zcrypt_cpacf_available",
		"zcrypt_info",
		"zcrypt_crypto_features",
		"zcrypt_capability",
		"zcrypt_max_msa_level",
		"zcrypt_cpacf_query_function",
		"zcrypt_kernel_crypto_hw",
		"zcrypt_kernel_crypto_algorithms",
		"zcrypt_sha256_throughput_mbps",
		"zcrypt_sha512_throughput_mbps",
		"zcrypt_ghash_throughput_mbps",
		"zcrypt_aes256gcm_encrypt_mbps",
		"zcrypt_aes256gcm_decrypt_mbps",
		"zcrypt_aes256gcm_throughput_mbps",
		"zcrypt_nist_vectors_passed",
		"zcrypt_scrape_timestamp_seconds",
		"zcrypt_up",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("exposition is missing metric %q", want)
		}
	}
}

func TestRenderValues(t *testing.T) {
	out := Render(sampleSnapshot())
	checks := []string{
		`zcrypt_cpacf_available{arch="s390x",machine_type="9175"} 1`,
		`zcrypt_max_msa_level 13`,
		`zcrypt_capability{feature="aes"} 1`,
		`zcrypt_capability{feature="nnpa"} 1`,
		`zcrypt_kernel_crypto_algorithms{kind="total"} 3`,
		`zcrypt_kernel_crypto_algorithms{kind="hardware"} 2`,
		`zcrypt_nist_vectors_passed 1`,
		`zcrypt_scrape_timestamp_seconds 1794969657`,
		`zcrypt_up 1`,
		`zcrypt_aes256gcm_encrypt_mbps{block_size="1048576"} 13839.97`,
		`zcrypt_aes256gcm_decrypt_mbps{block_size="1048576"} 14150.94`,
		`zcrypt_sha256_throughput_mbps 4339.68`,
		`zcrypt_sha512_throughput_mbps 6793.86`,
		`zcrypt_ghash_throughput_mbps{backend="pure-go"} 6.62`,
		`zcrypt_ghash_throughput_mbps{backend="af_alg"} 477.94`,
	}
	for _, want := range checks {
		if !strings.Contains(out, want) {
			t.Errorf("missing expected sample line:\n  want %s", want)
		}
	}
	// The largest buffer must drive the summary gauges.
	if !strings.Contains(out, `zcrypt_aes256gcm_throughput_mbps{direction="encrypt"} 13839.97`) {
		t.Error("summary encrypt gauge does not use the largest buffer")
	}
	if !strings.Contains(out, `zcrypt_aes256gcm_throughput_mbps{direction="decrypt"} 14150.94`) {
		t.Error("summary decrypt gauge does not use the largest buffer")
	}
}

// TestRenderKernelSoftwareZero checks the regression signal: an algorithm that
// fell back to software must be exported with value 0, not omitted.
func TestRenderKernelSoftwareZero(t *testing.T) {
	out := Render(sampleSnapshot())
	want := `zcrypt_kernel_crypto_hw{algorithm="sha256",driver="sha256-generic",priority="100"} 0`
	if !strings.Contains(out, want) {
		t.Errorf("software fallback not exported as 0:\n  want %s", want)
	}
}

func TestRenderFailureStates(t *testing.T) {
	snap := sampleSnapshot()
	snap.Caps.HasCPACF = false
	snap.VectorsOK = false
	snap.VectorErr = "boom"
	snap.CollectErr = "collect failed"

	out := Render(snap)
	if !strings.Contains(out, `zcrypt_cpacf_available{arch="s390x",machine_type="9175"} 0`) {
		t.Error("cpacf_available should be 0 when CPACF is absent")
	}
	if !strings.Contains(out, "zcrypt_nist_vectors_passed 0") {
		t.Error("nist_vectors_passed should be 0 when verification failed")
	}
	if !strings.Contains(out, "zcrypt_up 0") {
		t.Error("up should be 0 when collection failed")
	}
}

func TestRenderNoQueryAndNoKernel(t *testing.T) {
	snap := Snapshot{
		Timestamp: time.Unix(0, 0),
		Caps:      cpacf.HardwareCapabilities{Arch: "amd64", Endianness: "Little-Endian (LSB)"},
		Query:     cpacf.Query{Available: false, Error: "not s390x"},
		Kernel:    cpacf.KernelCryptoReport{Available: false, Error: "no /proc/crypto"},
	}
	out := Render(snap)
	if out == "" {
		t.Fatal("Render must still produce a body when everything is unavailable")
	}
	if strings.Contains(out, "zcrypt_cpacf_query_function") {
		t.Error("query rows must be omitted when the Query is unavailable")
	}
	if !strings.Contains(out, "zcrypt_up 1") {
		t.Error("up should be 1: missing hardware is not a collection error")
	}
	if !strings.Contains(out, "zcrypt_max_msa_level 0") {
		t.Error("max_msa_level should be 0 without CPACF")
	}
}

// TestRenderCapabilityFlags covers the per-feature capability gauge, including
// the SHAKE flag. A feature that is present but not exported is invisible to a
// dashboard, which is how the SHAKE detection gap went unnoticed: the hardware
// had it, the exporter never mentioned it.
func TestRenderCapabilityFlags(t *testing.T) {
	snap := sampleSnapshot()
	snap.Caps.HasSHAKE = true
	out := Render(snap)

	for _, want := range []string{
		`zcrypt_capability{feature="sha3"} 1`,
		`zcrypt_capability{feature="shake"} 1`,
		`zcrypt_capability{feature="aes"} 1`,
		`zcrypt_capability{feature="nnpa"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing capability sample %q", want)
		}
	}

	// With the flag clear the gauge must read 0, not disappear: a dashboard
	// needs the series to exist in order to alert on its absence.
	snap.Caps.HasSHAKE = false
	out = Render(snap)
	if !strings.Contains(out, `zcrypt_capability{feature="shake"} 0`) {
		t.Error("shake capability must be exported as 0 when the flag is clear")
	}
}

// TestRenderShakeQueryRows checks the KIMD SHAKE function codes appear as
// labelled query rows, so the hardware evidence for the capability gauge is
// visible in the exposition rather than only in the boolean.
func TestRenderShakeQueryRows(t *testing.T) {
	snap := sampleSnapshot()
	var kimd cpacf.FunctionBitmap
	for _, fc := range []uint{
		cpacf.FuncKIMDSHA3_256, cpacf.FuncKIMDSHAKE128, cpacf.FuncKIMDSHAKE256,
	} {
		kimd[fc/8] |= 0x80 >> (fc % 8)
	}
	snap.Query = cpacf.Query{Available: true, KIMD: kimd}

	out := Render(snap)
	for _, want := range []string{
		`zcrypt_cpacf_query_function{instruction="KIMD",function="KIMD-SHAKE128",code="36"} 1`,
		`zcrypt_cpacf_query_function{instruction="KIMD",function="KIMD-SHAKE256",code="37"} 1`,
		`zcrypt_cpacf_query_function{instruction="KIMD",function="KIMD-SHA3-256",code="33"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing query row %q", want)
		}
	}
	// A code that is absent must still be exported, as 0.
	if !strings.Contains(out, `function="KIMD-GHASH",code="65"} 0`) {
		t.Error("absent function codes must be exported as 0, not omitted")
	}
}

func TestMaxThroughput(t *testing.T) {
	results := []cipher.AESGCMResult{
		{BlockSize: 1024, EncryptMBps: 5000},
		{BlockSize: 1048576, EncryptMBps: 13000},
		{BlockSize: 65536, EncryptMBps: 14000},
	}
	got := maxThroughput(results, func(r cipher.AESGCMResult) float64 { return r.EncryptMBps })
	if got != 13000 {
		t.Errorf("maxThroughput = %.0f, want 13000 (the 1 MiB result, not the largest value)", got)
	}
	if got := maxThroughput(nil, func(r cipher.AESGCMResult) float64 { return r.EncryptMBps }); got != 0 {
		t.Errorf("maxThroughput(nil) = %f, want 0", got)
	}
}

func TestAesPathLabel(t *testing.T) {
	cases := []struct {
		impl cipher.AESImplementation
		want string
	}{
		{cipher.AESImplementation{PureGoBuild: true}, "purego"},
		{cipher.AESImplementation{AssemblyPath: true}, "assembly"},
		{cipher.AESImplementation{}, "unknown"},
	}
	for _, c := range cases {
		if got := aesPathLabel(c.impl); got != c.want {
			t.Errorf("aesPathLabel(%+v) = %q, want %q", c.impl, got, c.want)
		}
	}
}

func TestNewCollectorDefaults(t *testing.T) {
	c := NewCollector()
	if c.BenchmarkInterval != 5*time.Minute {
		t.Errorf("BenchmarkInterval = %v, want 5m", c.BenchmarkInterval)
	}
	if c.IterationScale != 1 {
		t.Errorf("IterationScale = %d, want 1", c.IterationScale)
	}
}

func TestHandlerRoutes(t *testing.T) {
	srv := NewServer(":0")
	h := srv.Handler()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK || rec.Body.String() != "ok\n" {
		t.Errorf("/healthz = %d %q, want 200 \"ok\\n\"", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/nope", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("/nope = %d, want 404", rec.Code)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("/ = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "/metrics") {
		t.Error("index page should mention /metrics")
	}
}
