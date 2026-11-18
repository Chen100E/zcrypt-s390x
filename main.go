package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/Chen100E/zcrypt-s390x/pkg/cipher"
	"github.com/Chen100E/zcrypt-s390x/pkg/cpacf"
	"github.com/Chen100E/zcrypt-s390x/pkg/exporter"
)

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
	flag.Parse()

	// 1. Detect hardware, then refine with live CPACF Query results.
	caps := cpacf.Detect()
	query := cpacf.ProbeQuery(caps)
	caps = cpacf.RefineWithQuery(caps, query)

	// 2. Read the kernel crypto API dispatch table.
	kernel := cpacf.DetectKernelCrypto()

	// 3. Verify NIST compliance.
	if err := cipher.VerifyNISTVectors(); err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: %v\n", err)
		os.Exit(1)
	}
	vectorsPassed, aesErr := cipher.VerifyAESGCMVectors()
	if aesErr != nil {
		fmt.Fprintf(os.Stderr, "FATAL: AES-256-GCM NIST vector mismatch: %v\n", aesErr)
		os.Exit(1)
	}

	if *verifyOnly {
		fmt.Printf("NIST SHA-256 and SHA-512 verification passed on %s.\n", caps.Endianness)
		fmt.Printf("NIST AES-256-GCM verification passed: %d/%d vectors bit-exact.\n",
			vectorsPassed, len(cipher.NISTGCMVectors))
		return
	}

	// 4. Digest throughput.
	sha256_64K, sha512_64K := cipher.BenchmarkDigest(64*1024, *iterations)
	sha256_1M, sha512_1M := cipher.BenchmarkDigest(1024*1024, *iterations/4+1)

	// 5. AES-256-GCM throughput.
	var aesResults []cipher.AESGCMResult
	if !*noAES {
		key, err := cipher.RandomKey()
		if err != nil {
			fmt.Fprintf(os.Stderr, "FATAL: %v\n", err)
			os.Exit(1)
		}
		scale := *iterations / 200
		if scale < 1 {
			scale = 1
		}
		results, err := cipher.AESGCMBenchmarkSuite(key, scale)
		if err != nil {
			fmt.Fprintf(os.Stderr, "FATAL: AES-256-GCM benchmark: %v\n", err)
			os.Exit(1)
		}
		aesResults = results
	}

	if *jsonOutput {
		out := map[string]interface{}{
			"capabilities":            caps,
			"cpacf_query":             query,
			"kernel_crypto":           kernel,
			"aes_impl":                cipher.DetectAESImplementation(),
			"nist_verified":           true,
			"nist_gcm_vectors_passed": vectorsPassed,
			"throughput_mbps": map[string]interface{}{
				"sha256_64k": sha256_64K,
				"sha512_64k": sha512_64K,
				"sha256_1m":  sha256_1M,
				"sha512_1m":  sha512_1M,
			},
			"aes256gcm": aesResults,
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
	_ = fs.Parse(args)

	srv := exporter.NewServer(*addr)
	srv.Collector.IterationScale = *scale
	if *interval > 0 {
		srv.Collector.BenchmarkInterval = *interval
	}
	srv.Logger = log.New(os.Stderr, "", log.LstdFlags)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := srv.Run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: %v\n", err)
		os.Exit(1)
	}
}
