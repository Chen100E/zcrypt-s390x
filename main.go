package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/Chen100E/zcrypt-s390x/pkg/cipher"
	"github.com/Chen100E/zcrypt-s390x/pkg/cpacf"
	"github.com/Chen100E/zcrypt-s390x/pkg/exporter"
)

// version is injected at build time via -ldflags "-X main.version=..."
var version = "dev"

func main() {
	// Subcommand dispatch: `zcrypt export` runs the Prometheus exporter, bare
	// `zcrypt` runs the one-shot report. Using a leading positional argument
	// keeps the existing flag-only invocation working unchanged, which matters
	// because the daily benchmark timer calls `./zcrypt -json`.
	if len(os.Args) > 1 && os.Args[1] == "export" {
		runExporter(os.Args[2:])
		return
	}
	// `--serve` is accepted at the top level as an alias for `export`, so the
	// documented one-liner `./zcrypt --serve :9110` works without the
	// subcommand. The leading flag has to be intercepted before flag.Parse,
	// which would otherwise reject an unknown flag.
	if len(os.Args) > 1 && (os.Args[1] == "--serve" || os.Args[1] == "-serve") {
		runExporter(os.Args[1:])
		return
	}

	jsonOutput := flag.Bool("json", false, "Output results in JSON format")
	verifyOnly := flag.Bool("verify", false, "Run NIST test vector verification only")
	iterations := flag.Int("n", 200, "Benchmark iterations per block size")
	noAES := flag.Bool("no-aes", false, "Skip the AES-256-GCM throughput sweep")
	sweep := flag.Bool("sweep", false, "Run the buffer-size sweep and print the curves")
	sweepScale := flag.Int("sweep-scale", 1, "Iteration scale for the buffer-size sweep")
	writeBaseline := flag.String("write-baseline", "", "Measure and write a performance baseline to this path")
	baselineCheck := flag.String("baseline-check", "", "Compare current throughput against the baseline at this path")
	tolerance := flag.Float64("tolerance", 20, "Regression tolerance percentage for --baseline-check and --watch")
	watchInterval := flag.String("watch", "", "Re-benchmark every interval and refresh metrics (e.g. 60s); use with --serve")
	watchBaseline := flag.String("baseline", "", "Baseline path for --watch to compare each tick against")
	showVersion := flag.Bool("version", false, "Print version information and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("zcrypt %s (%s/%s, %s)\n", version, runtime.GOOS, runtime.GOARCH, runtime.Version())
		return
	}

	// 1. Detect hardware, then refine with live CPACF Query results.
	caps := cpacf.Detect()
	query := cpacf.ProbeQuery(caps)
	caps = cpacf.RefineWithQuery(caps, query)

	// 2. Read the kernel crypto API dispatch table.
	kernel := cpacf.DetectKernelCrypto()

	// 3. Baseline writing and checking are standalone modes: they measure and
	// exit, so they run before the report path builds up any state.
	if *writeBaseline != "" {
		runWriteBaseline(*writeBaseline, caps)
		return
	}
	if *baselineCheck != "" {
		runBaselineCheck(*baselineCheck, caps, *tolerance)
		return
	}

	// 4. The sweep is also standalone: it prints its own tables.
	if *sweep {
		runSweep(*sweepScale)
		return
	}

	// 5. Watch mode without --serve: a console monitor emitting one JSON line
	// per tick. With --serve the same loop runs inside the exporter, so it is
	// handled in runExporter instead.
	if *watchInterval != "" {
		runWatchConsole(*watchInterval, *iterations/200, *watchBaseline, *tolerance)
		return
	}

	// 5. Verify NIST compliance.
	if err := cipher.VerifyNISTVectors(); err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: %v\n", err)
		os.Exit(1)
	}
	vectorsPassed, aesErr := cipher.VerifyAESGCMVectors()
	if aesErr != nil {
		fmt.Fprintf(os.Stderr, "FATAL: AES-256-GCM NIST vector mismatch: %v\n", aesErr)
		os.Exit(1)
	}
	modeVectorsPassed, modeErr := cipher.VerifyAESModeVectors()
	if modeErr != nil {
		fmt.Fprintf(os.Stderr, "FATAL: SP 800-38A vector mismatch: %v\n", modeErr)
		os.Exit(1)
	}
	sha3Passed, sha3Err := cipher.VerifySHA3Vectors()
	if sha3Err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: SHA-3 NIST vector mismatch: %v\n", sha3Err)
		os.Exit(1)
	}

	if *verifyOnly {
		fmt.Printf("NIST SHA-256 and SHA-512 verification passed on %s.\n", caps.Endianness)
		fmt.Printf("NIST AES-256-GCM verification passed: %d/%d vectors bit-exact.\n",
			vectorsPassed, len(cipher.NISTGCMVectors))
		fmt.Printf("NIST SP 800-38A verification passed: %d/%d vectors bit-exact (ECB/CBC/CTR).\n",
			modeVectorsPassed, len(cipher.NISTSP80038AVectors))
		fmt.Printf("NIST SHA-3 verification passed: %d/%d vectors bit-exact (224/256/384/512).\n",
			sha3Passed, len(cipher.NISTSHA3Vectors))
		return
	}

	// 4. Digest throughput.
	sha256_64K, sha512_64K := cipher.BenchmarkDigest(64*1024, *iterations)
	sha256_1M, sha512_1M := cipher.BenchmarkDigest(1024*1024, *iterations/4+1)

	// 5. AES-256-GCM throughput.
	//
	// The iteration scale is derived once here and reused by every later
	// measurement, so all of them run for a comparable wall-clock time regardless
	// of which sections are enabled.
	scale := *iterations / 200
	if scale < 1 {
		scale = 1
	}

	var aesResults []cipher.AESGCMResult
	if !*noAES {
		key, err := cipher.RandomKey()
		if err != nil {
			fmt.Fprintf(os.Stderr, "FATAL: %v\n", err)
			os.Exit(1)
		}
		results, err := cipher.AESGCMBenchmarkSuite(key, scale)
		if err != nil {
			fmt.Fprintf(os.Stderr, "FATAL: AES-256-GCM benchmark: %v\n", err)
			os.Exit(1)
		}
		aesResults = results
	}

	// 6. AES mode comparison, SHA-3, ECC and PRNG.
	modeRows := cipher.AESModeComparisonSuite(256, scale)
	sha3Rows := cipher.SHA3Suite(1024*1024, *iterations/10+1)
	sha3Kernel := cipher.SHA3KernelDrivers()
	signRows := cipher.SignSuite(*iterations / 4)
	eccKernel := cipher.ECCKernelReport()
	prng, prngErr := cipher.RunPRNGSuite(caps, 64*1024, *iterations/2)
	prngInfo := cipher.ReadPRNGInfo(caps)

	if *jsonOutput {
		out := map[string]interface{}{
			"capabilities":             caps,
			"cpacf_query":              query,
			"kernel_crypto":            kernel,
			"aes_impl":                 cipher.DetectAESImplementation(),
			"nist_verified":            true,
			"nist_gcm_vectors_passed":  vectorsPassed,
			"nist_mode_vectors_passed": modeVectorsPassed,
			"nist_sha3_vectors_passed": sha3Passed,
			"throughput_mbps": map[string]interface{}{
				"sha256_64k": sha256_64K,
				"sha512_64k": sha512_64K,
				"sha256_1m":  sha256_1M,
				"sha512_1m":  sha512_1M,
			},
			"aes256gcm":      aesResults,
			"aes_modes":      modeRows,
			"aes_mode_table": cipher.AESModeTable,
			"sha3":           sha3Rows,
			"sha3_kernel":    sha3Kernel,
			"signatures":     signRows,
			"ecc_kernel":     eccKernel,
			"curve_table":    cipher.CurveTable,
			"prng":           prng,
			"prng_info":      prngInfo,
		}
		if prngErr != nil {
			out["prng_error"] = prngErr.Error()
		}
		data, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "FATAL: marshal JSON: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(data))
		return
	}

	printReport(caps, query, kernel, aesResults, sha256_64K, sha512_64K, sha256_1M, sha512_1M, vectorsPassed)
	printModeSection(modeRows)
	printSHA3Section(sha3Rows, sha3Kernel)
	printECCSection(signRows, eccKernel)
	printPRNGSection(prng, prngInfo, prngErr)
}

func printReport(
	caps cpacf.HardwareCapabilities,
	query cpacf.Query,
	kernel cpacf.KernelCryptoReport,
	aesResults []cipher.AESGCMResult,
	sha256_64K, sha512_64K, sha256_1M, sha512_1M float64,
	vectorsPassed int,
) {
	const line = "=================================================================="

	fmt.Println(line)
	fmt.Println("  ZCrypt-s390x: Mainframe Hardware Crypto & Digest Benchmark Suite ")
	fmt.Println(line)
	fmt.Printf("Architecture    : %s (%s)\n", caps.Arch, caps.Endianness)
	fmt.Printf("Machine Model   : %s\n", caps.MachineType)
	fmt.Printf("Hardware CPACF  : %v | Max MSA Level: MSA-%d\n", caps.HasCPACF, caps.MaxMSALevel)
	fmt.Printf("Crypto Features : %s\n", strings.Join(caps.CryptoFeatures, " "))
	fmt.Printf("Primitives      : AES=%v GCM=%v GHASH=%v SHA3=%v ECC=%v PRNO=%v\n",
		caps.HasAES, caps.HasAESGCM, caps.HasGHASH, caps.HasSHA3, caps.HasECC, caps.HasPRNO)
	fmt.Printf("Vector Unit(VX) : %v | On-Chip NNPA: %v\n", caps.HasVector, caps.HasNNPA)

	impl := cipher.DetectAESImplementation()
	fmt.Println(line)
	fmt.Println("AES Implementation")
	fmt.Println(line)
	fmt.Printf("Build path      : %s\n", impl.Description)
	if impl.PureGoBuild {
		fmt.Println("NOTE: this binary was compiled with -tags purego, so crypto/aes is")
		fmt.Println("      NOT using CPACF. Rebuild without the tag for hardware numbers.")
	}

	if query.Available {
		fmt.Println(line)
		fmt.Println("CPACF Query Function Codes (hardware-confirmed)")
		fmt.Println(line)
		fmt.Printf("KM    (Cipher Message)          : %s\n", hexBitmap(query.KM))
		fmt.Printf("KMC   (Cipher Message w/ Chain) : %s\n", hexBitmap(query.KMC))
		fmt.Printf("KMCTR (Cipher Message w/ Ctr)   : %s\n", hexBitmap(query.KMCTR))
		fmt.Printf("KMA   (Cipher Msg w/ Auth)      : %s\n", hexBitmap(query.KMA))
		fmt.Printf("KIMD  (Compute Interm Digest)   : %s\n", hexBitmap(query.KIMD))
		fmt.Printf("KLMD  (Compute Last Digest)     : %s\n", hexBitmap(query.KLMD))
		fmt.Printf("KDSA  (Digital Signature Auth)  : %s\n", hexBitmap(query.KDSA))
		// PCKMO (MSA-3) and PRNO (MSA-5) have no Go assembler mnemonic, so they
		// are not queried here. Their presence is taken from the STFLE facility
		// bits, which is authoritative for those two levels.
		fmt.Printf("PCKMO (MSA-3) / PRNO (MSA-5)    : %v / %v (from STFLE bits 76 / 57)\n",
			caps.HasWrappedK, caps.HasPRNO)
	}

	printKernelSection(kernel)

	fmt.Println(line)
	fmt.Printf("NIST SHA-256/SHA-512 : [PASS] Big-Endian bit-exact match confirmed\n")
	fmt.Printf("NIST AES-256-GCM     : [PASS] %d/%d vectors bit-exact (seal + open + tag tamper)\n",
		vectorsPassed, len(cipher.NISTGCMVectors))
	fmt.Println(line)
	fmt.Printf("SHA-256 Throughput (64KB buffer) : %8.2f MB/sec\n", sha256_64K)
	fmt.Printf("SHA-512 Throughput (64KB buffer) : %8.2f MB/sec\n", sha512_64K)
	fmt.Printf("SHA-256 Throughput ( 1MB buffer) : %8.2f MB/sec\n", sha256_1M)
	fmt.Printf("SHA-512 Throughput ( 1MB buffer) : %8.2f MB/sec\n", sha512_1M)

	if len(aesResults) > 0 {
		fmt.Println("------------------------------------------------------------------")
		fmt.Println("AES-256-GCM Throughput")
		fmt.Printf("%-12s %18s %18s\n", "Buffer", "Encrypt (MB/s)", "Decrypt (MB/s)")
		for _, r := range aesResults {
			fmt.Printf("%-12s %18.2f %18.2f\n",
				humanSize(r.BlockSize), r.EncryptMBps, r.DecryptMBps)
		}
	}
	fmt.Println(line)
}

func printKernelSection(kernel cpacf.KernelCryptoReport) {
	const line = "=================================================================="
	fmt.Println(line)
	fmt.Println("Kernel Crypto Backend (/proc/crypto)")
	fmt.Println(line)
	if !kernel.Available {
		fmt.Printf("Unavailable: %s\n", kernel.Error)
		return
	}
	fmt.Printf("%-14s %-18s %8s %10s  %s\n", "ALGORITHM", "DRIVER", "PRIORITY", "TYPE", "BACKEND")
	for _, a := range kernel.HardwareAlgorithms(true) {
		backend := "software"
		if a.Hardware {
			backend = "HARDWARE (CPACF)"
		}
		fmt.Printf("%-14s %-18s %8d %10s  %s\n", a.Name, a.Driver, a.Priority, a.Type, backend)
	}
	for _, name := range cpacf.InterestingAlgorithms {
		a, ok := kernel.Lookup(name)
		if !ok || a.Hardware {
			continue
		}
		fmt.Printf("%-14s %-18s %8d %10s  %s\n", a.Name, a.Driver, a.Priority, a.Type, "software")
	}
	fmt.Printf("\n%d/%d registered algorithms dispatched to hardware.\n",
		kernel.HardwareCount, kernel.TotalCount)
}

func hexBitmap(b cpacf.FunctionBitmap) string {
	var parts []string
	for _, v := range b {
		parts = append(parts, fmt.Sprintf("%02x", v))
	}
	return strings.Join(parts, " ")
}

func humanSize(n int) string {
	switch {
	case n >= 1024*1024:
		return strconv.Itoa(n/(1024*1024)) + " MB"
	case n >= 1024:
		return strconv.Itoa(n/1024) + " KB"
	default:
		return strconv.Itoa(n) + " B"
	}
}

// runExporter implements `zcrypt export`, the Prometheus exporter subcommand.
func runExporter(args []string) {
	fs := flag.NewFlagSet("export", flag.ExitOnError)
	addr := fs.String("serve", ":9110", "HTTP listen address for the metrics endpoint")
	scale := fs.Int("scale", 1, "Benchmark iteration scale for the exporter")
	interval := fs.Duration("benchmark-interval", 0, "How long benchmark results stay cached (0 = default 5m)")
	watch := fs.String("watch", "", "Re-benchmark every interval (e.g. 60s) and refresh the metrics")
	baselinePath := fs.String("baseline", "", "Baseline to compare each watch tick against")
	tolerance := fs.Float64("tolerance", 20, "Regression tolerance percentage for --baseline")
	_ = fs.Parse(args)

	srv := exporter.NewServer(*addr)
	srv.Collector.IterationScale = *scale
	if *interval > 0 {
		srv.Collector.BenchmarkInterval = *interval
	}
	srv.Logger = log.New(os.Stderr, "", log.LstdFlags)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// With --watch, a background loop refreshes the collector's cache on a
	// timer. The HTTP handler keeps serving whatever the collector last
	// produced, so a slow benchmark never blocks a scrape and a scrape never
	// triggers an unscheduled benchmark.
	if *watch != "" {
		d, err := parseWatchInterval(*watch)
		if err != nil {
			fmt.Fprintf(os.Stderr, "FATAL: %v\n", err)
			os.Exit(2)
		}
		w := &watcher{
			interval:  d,
			scale:     *scale,
			collector: srv.Collector,
			tolerance: *tolerance,
			out:       os.Stderr,
		}
		if *baselinePath != "" {
			b, err := cipher.ReadBaseline(*baselinePath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "FATAL: %v\n", err)
				os.Exit(2)
			}
			w.baseline = &b
		}
		go func() {
			if err := w.run(ctx); err != nil {
				fmt.Fprintf(os.Stderr, "watch loop stopped: %v\n", err)
			}
		}()
		if srv.Logger != nil {
			srv.Logger.Printf("watch mode: re-benchmarking every %s", d)
		}
	}

	if err := srv.Run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: %v\n", err)
		os.Exit(1)
	}
}

// runWatchConsole implements `zcrypt --watch <interval>` without --serve: one
// JSON line per tick on stdout, which is what a shell monitor or a log shipper
// wants.
func runWatchConsole(interval string, scale int, baselinePath string, tolerance float64) {
	d, err := parseWatchInterval(interval)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: %v\n", err)
		os.Exit(2)
	}
	w := &watcher{interval: d, scale: scale, tolerance: tolerance, out: os.Stdout}
	if baselinePath != "" {
		b, err := cipher.ReadBaseline(baselinePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "FATAL: %v\n", err)
			os.Exit(2)
		}
		w.baseline = &b
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Fprintf(os.Stderr, "watching: measuring every %s, Ctrl-C to stop\n", d)
	if err := w.run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: %v\n", err)
		os.Exit(1)
	}
}
