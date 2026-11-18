package exporter

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Chen100E/zcrypt-s390x/pkg/cipher"
	"github.com/Chen100E/zcrypt-s390x/pkg/cpacf"
)

// This package implements a Prometheus text-format exporter with no third-party
// dependencies: the exposition format is simple enough that a hand-written
// renderer is both smaller and easier to audit than a client library, and it
// keeps go.mod at zero requires.
//
// Exposition format reference:
// https://prometheus.io/docs/instrumenting/exposition_formats/#text-format-details

// Snapshot is one point-in-time measurement of everything ZCrypt can observe.
// It is computed once per scrape so that all gauges in a single response are
// mutually consistent.
type Snapshot struct {
	Timestamp  time.Time
	Caps       cpacf.HardwareCapabilities
	Query      cpacf.Query
	Kernel     cpacf.KernelCryptoReport
	AES        []cipher.AESGCMResult
	SHA256MBps float64
	SHA512MBps float64
	VectorsOK  bool
	VectorErr  string
	AESImpl    cipher.AESImplementation
	CollectErr string
}

// Collector produces Snapshots. It is a struct rather than a bare function so
// that the expensive benchmark suite can be cached between scrapes: a 15-second
// Prometheus scrape interval must not trigger three full throughput sweeps.
type Collector struct {
	// BenchmarkInterval is how long a benchmark result stays valid.
	BenchmarkInterval time.Duration
	// IterationScale multiplies the per-size iteration counts.
	IterationScale int

	mu        sync.Mutex
	cached    *Snapshot
	lastBench time.Time
}

// NewCollector returns a Collector with sane defaults.
func NewCollector() *Collector {
	return &Collector{
		BenchmarkInterval: 5 * time.Minute,
		IterationScale:    1,
	}
}

// Collect gathers a snapshot, reusing cached benchmark figures when they are
// still fresh.
func (c *Collector) Collect() Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	snap := Snapshot{
		Timestamp: now,
		Caps:      cpacf.Detect(),
		Kernel:    cpacf.DetectKernelCrypto(),
		AESImpl:   cipher.DetectAESImplementation(),
	}
	snap.Query = cpacf.ProbeQuery(snap.Caps)
	snap.Caps = cpacf.RefineWithQuery(snap.Caps, snap.Query)

	// NIST vectors are cheap (a few microseconds) so they run on every scrape.
	// If they ever fail the exporter must say so loudly rather than silently
	// continuing to report throughput for a broken primitive.
	if _, err := cipher.VerifyAESGCMVectors(); err != nil {
		snap.VectorsOK = false
		snap.VectorErr = err.Error()
	} else if err := cipher.VerifyNISTVectors(); err != nil {
		snap.VectorsOK = false
		snap.VectorErr = err.Error()
	} else {
		snap.VectorsOK = true
	}

	if c.cached != nil && now.Sub(c.lastBench) < c.BenchmarkInterval {
		snap.AES = c.cached.AES
		snap.SHA256MBps = c.cached.SHA256MBps
		snap.SHA512MBps = c.cached.SHA512MBps
		return snap
	}

	key, err := cipher.RandomKey()
	if err != nil {
		snap.CollectErr = err.Error()
		return snap
	}
	scale := c.IterationScale
	if scale <= 0 {
		scale = 1
	}
	aes, err := cipher.AESGCMBenchmarkSuite(key, scale)
	if err != nil {
		snap.CollectErr = err.Error()
	} else {
		snap.AES = aes
	}
	sha256MBps, sha512MBps := cipher.BenchmarkDigest(1024*1024, 20*scale)
	snap.SHA256MBps = sha256MBps
	snap.SHA512MBps = sha512MBps

	c.cached = &snap
	c.lastBench = now
	return snap
}

// maxThroughput returns the largest-buffer figure, which is the one that
// reflects sustained bulk throughput rather than per-call overhead.
func maxThroughput(results []cipher.AESGCMResult, pick func(cipher.AESGCMResult) float64) float64 {
	if len(results) == 0 {
		return 0
	}
	best := results[0]
	for _, r := range results[1:] {
		if r.BlockSize > best.BlockSize {
			best = r
		}
	}
	return pick(best)
}

// Render produces the Prometheus text exposition body for a snapshot.
func Render(s Snapshot) string {
	var b strings.Builder

	writeHelp := func(name, help, typ string) {
		fmt.Fprintf(&b, "# HELP %s %s\n", name, help)
		fmt.Fprintf(&b, "# TYPE %s %s\n", name, typ)
	}

	// --- availability ---
	writeHelp("zcrypt_cpacf_available",
		"1 if CPACF hardware crypto instructions are available on this host.",
		"gauge")
	fmt.Fprintf(&b, "zcrypt_cpacf_available{arch=%q,machine_type=%q} %d\n",
		s.Caps.Arch, s.Caps.MachineType, b2i(s.Caps.HasCPACF))

	writeHelp("zcrypt_info",
		"Static build and platform information, always 1.",
		"gauge")
	fmt.Fprintf(&b, "zcrypt_info{arch=%q,endianness=%q,aes_path=%q,version=%q} 1\n",
		s.Caps.Arch, s.Caps.Endianness, aesPathLabel(s.AESImpl), Version)

	// --- feature flags ---
	writeHelp("zcrypt_crypto_features",
		"1 for each confirmed Message-Security-Assist extension level.",
		"gauge")
	for _, f := range s.Caps.CryptoFeatures {
		fmt.Fprintf(&b, "zcrypt_crypto_features{features=%q} 1\n", f)
	}

	writeHelp("zcrypt_capability",
		"1 when a specific CPACF-backed primitive is usable, 0 otherwise.",
		"gauge")
	featureFlags := []struct {
		name string
		val  bool
	}{
		{"aes", s.Caps.HasAES},
		{"aes_gcm", s.Caps.HasAESGCM},
		{"ghash", s.Caps.HasGHASH},
		{"sha3", s.Caps.HasSHA3},
		{"ecc", s.Caps.HasECC},
		{"prno", s.Caps.HasPRNO},
		{"wrapped_key", s.Caps.HasWrappedK},
		{"vector", s.Caps.HasVector},
		{"nnpa", s.Caps.HasNNPA},
	}
	for _, f := range featureFlags {
		fmt.Fprintf(&b, "zcrypt_capability{feature=%q} %d\n", f.name, b2i(f.val))
	}

	writeHelp("zcrypt_max_msa_level",
		"Highest Message-Security-Assist extension level confirmed by STFLE or CPACF Query.",
		"gauge")
	fmt.Fprintf(&b, "zcrypt_max_msa_level %d\n", s.Caps.MaxMSALevel)

	// --- CPACF query proof ---
	// Only declare the family when there is at least one row: an exposition
	// that advertises a metric with no samples is legal but misleading.
	if rows := queryRows(s.Query); len(rows) > 0 {
		writeHelp("zcrypt_cpacf_query_function",
			"1 for each CPACF function code reported present by the hardware Query instruction.",
			"gauge")
		for _, q := range rows {
			fmt.Fprintf(&b, "zcrypt_cpacf_query_function{instruction=%q,function=%q,code=%q} %d\n",
				q.instruction, q.function, q.code, b2i(q.present))
		}
	}

	// --- kernel dispatch proof ---
	writeHelp("zcrypt_kernel_crypto_hw",
		"1 if the Linux kernel crypto API dispatches this algorithm to a CPACF/vector driver.",
		"gauge")
	for _, a := range s.Kernel.HardwareAlgorithms(false) {
		fmt.Fprintf(&b, "zcrypt_kernel_crypto_hw{algorithm=%q,driver=%q,priority=%q} 1\n",
			a.Name, a.Driver, strconv.Itoa(a.Priority))
	}
	// Also emit an explicit 0 for the algorithms we care about that fell back to
	// software, so a dashboard can alert on the regression.
	hw := make(map[string]bool)
	for _, a := range s.Kernel.Algorithms {
		if a.Hardware {
			hw[a.Name] = true
		}
	}
	for _, name := range cpacf.InterestingAlgorithms {
		if hw[name] {
			continue
		}
		if a, ok := s.Kernel.Lookup(name); ok {
			fmt.Fprintf(&b, "zcrypt_kernel_crypto_hw{algorithm=%q,driver=%q,priority=%q} 0\n",
				a.Name, a.Driver, strconv.Itoa(a.Priority))
		}
	}

	writeHelp("zcrypt_kernel_crypto_algorithms",
		"Number of algorithms registered with the kernel crypto API, and how many are hardware-backed.",
		"gauge")
	fmt.Fprintf(&b, "zcrypt_kernel_crypto_algorithms{kind=\"total\"} %d\n", s.Kernel.TotalCount)
	fmt.Fprintf(&b, "zcrypt_kernel_crypto_algorithms{kind=\"hardware\"} %d\n", s.Kernel.HardwareCount)

	// --- throughput ---
	writeHelp("zcrypt_sha256_throughput_mbps", "SHA-256 throughput in MB/s on 1 MiB buffers.", "gauge")
	fmt.Fprintf(&b, "zcrypt_sha256_throughput_mbps %.2f\n", s.SHA256MBps)

	writeHelp("zcrypt_sha512_throughput_mbps", "SHA-512 throughput in MB/s on 1 MiB buffers.", "gauge")
	fmt.Fprintf(&b, "zcrypt_sha512_throughput_mbps %.2f\n", s.SHA512MBps)

	writeHelp("zcrypt_aes256gcm_encrypt_mbps",
		"AES-256-GCM seal throughput in MB/s, labelled by buffer size.", "gauge")
	for _, r := range s.AES {
		fmt.Fprintf(&b, "zcrypt_aes256gcm_encrypt_mbps{block_size=%q} %.2f\n",
			strconv.Itoa(r.BlockSize), r.EncryptMBps)
	}

	writeHelp("zcrypt_aes256gcm_decrypt_mbps",
		"AES-256-GCM open throughput in MB/s, labelled by buffer size.", "gauge")
	for _, r := range s.AES {
		fmt.Fprintf(&b, "zcrypt_aes256gcm_decrypt_mbps{block_size=%q} %.2f\n",
			strconv.Itoa(r.BlockSize), r.DecryptMBps)
	}

	writeHelp("zcrypt_aes256gcm_throughput_mbps",
		"AES-256-GCM throughput in MB/s at the largest measured buffer, by direction.", "gauge")
	fmt.Fprintf(&b, "zcrypt_aes256gcm_throughput_mbps{direction=\"encrypt\"} %.2f\n",
		maxThroughput(s.AES, func(r cipher.AESGCMResult) float64 { return r.EncryptMBps }))
	fmt.Fprintf(&b, "zcrypt_aes256gcm_throughput_mbps{direction=\"decrypt\"} %.2f\n",
		maxThroughput(s.AES, func(r cipher.AESGCMResult) float64 { return r.DecryptMBps }))

	// --- correctness ---
	writeHelp("zcrypt_nist_vectors_passed",
		"1 if every NIST known-answer vector (AES-256-GCM and SHA-2) matched bit-for-bit.", "gauge")
	fmt.Fprintf(&b, "zcrypt_nist_vectors_passed %d\n", b2i(s.VectorsOK))

	writeHelp("zcrypt_scrape_timestamp_seconds",
		"Unix time of the measurement that produced this exposition.", "gauge")
	fmt.Fprintf(&b, "zcrypt_scrape_timestamp_seconds %d\n", s.Timestamp.Unix())

	writeHelp("zcrypt_up", "1 if the last collection completed without an internal error.", "gauge")
	fmt.Fprintf(&b, "zcrypt_up %d\n", b2i(s.CollectErr == ""))

	return b.String()
}

type queryRow struct {
	instruction string
	function    string
	code        string
	present     bool
}

// queryRows flattens the CPACF Query bitmaps into labelled rows. Only the
// function codes ZCrypt reports on are listed; the full 128-entry bitmap per
// instruction would make the exposition noisy without adding signal.
func queryRows(q cpacf.Query) []queryRow {
	if !q.Available {
		return nil
	}
	type probe struct {
		instr string
		bm    cpacf.FunctionBitmap
		codes []struct {
			name string
			fc   uint
		}
	}
	probes := []probe{
		{"KM", q.KM, []struct {
			name string
			fc   uint
		}{
			{"KM-AES-128", cpacf.FuncKMAES128},
			{"KM-AES-192", cpacf.FuncKMAES192},
			{"KM-AES-256", cpacf.FuncKMAES256},
			{"KM-XTS-AES-256", cpacf.FuncKMXTS256},
		}},
		{"KMC", q.KMC, []struct {
			name string
			fc   uint
		}{
			{"KMC-AES-256", cpacf.FuncKMAES256},
		}},
		{"KMCTR", q.KMCTR, []struct {
			name string
			fc   uint
		}{
			{"KMCTR-AES-256", cpacf.FuncKMCTRAES256},
		}},
		{"KMA", q.KMA, []struct {
			name string
			fc   uint
		}{
			{"KMA-GCM-AES-256", cpacf.FuncKMAAES256},
			{"KMA-Query-Auth-Info", cpacf.FuncQAI},
		}},
		{"KIMD", q.KIMD, []struct {
			name string
			fc   uint
		}{
			{"KIMD-SHA-256", cpacf.FuncKIMDSHA256},
			{"KIMD-SHA-512", cpacf.FuncKIMDSHA512},
			{"KIMD-SHA3-256", cpacf.FuncKIMDSHA3_256},
			{"KIMD-GHASH", cpacf.FuncKIMDGHASH},
		}},
		{"KDSA", q.KDSA, []struct {
			name string
			fc   uint
		}{
			{"KDSA-ECDSA-Sign-P256", cpacf.FuncKDSASignP256},
			{"KDSA-ECDSA-Verify-P256", cpacf.FuncKDSAVerifyP256},
		}},
	}

	var rows []queryRow
	for _, p := range probes {
		for _, c := range p.codes {
			rows = append(rows, queryRow{
				instruction: p.instr,
				function:    c.name,
				code:        strconv.Itoa(int(c.fc)),
				present:     p.bm.Has(c.fc),
			})
		}
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].instruction != rows[j].instruction {
			return rows[i].instruction < rows[j].instruction
		}
		return rows[i].function < rows[j].function
	})
	return rows
}

func aesPathLabel(impl cipher.AESImplementation) string {
	switch {
	case impl.PureGoBuild:
		return "purego"
	case impl.AssemblyPath:
		return "assembly"
	default:
		return "unknown"
	}
}

func b2i(v bool) int {
	if v {
		return 1
	}
	return 0
}

// Version is stamped at build time via -ldflags when releasing; it defaults to
// "dev" so an unreleased build is never mistaken for a tagged one.
var Version = "dev"

// Server wraps the HTTP surface of the exporter.
type Server struct {
	Collector *Collector
	// Addr is the listen address, e.g. ":9110".
	Addr string
	// Logger receives lifecycle messages; nil disables logging.
	Logger *log.Logger
}

// NewServer returns a Server bound to addr.
func NewServer(addr string) *Server {
	return &Server{Collector: NewCollector(), Addr: addr}
}

// Handler returns the http.Handler exposing /metrics, /healthz and /.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		snap := s.Collector.Collect()
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(Render(snap)))
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("zcrypt exporter\n\n/metrics  Prometheus text exposition\n/healthz  liveness probe\n"))
	})
	return mux
}

// Run starts the HTTP server and blocks until ctx is cancelled, then shuts the
// server down gracefully.
func (s *Server) Run(ctx context.Context) error {
	if s.Addr == "" {
		s.Addr = ":9110"
	}
	srv := &http.Server{
		Addr:              s.Addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return fmt.Errorf("exporter: listen %s: %w", s.Addr, err)
	}
	if s.Logger != nil {
		s.Logger.Printf("zcrypt exporter listening on %s (metrics at /metrics)", ln.Addr())
	}

	errCh := make(chan error, 1)
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}
