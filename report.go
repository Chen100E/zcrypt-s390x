package main

// Report sections for the primitives added in the second phase, plus the
// standalone CLI modes (--sweep, --write-baseline, --baseline-check).
//
// Each section prints a table whose columns are the numbers a reader needs to
// make a decision, and a short block of prose only where the number is
// surprising. The prose is not decoration: on this machine the interesting
// findings are that CTR is slower than CBC (because Go does not issue KMCTR on
// that path) and that the kernel registers no ECDSA driver (because KDSA is a
// userspace instruction, not a kernel akcipher). Neither is guessable from the
// table alone.

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/Chen100E/zcrypt-s390x/pkg/cipher"
	"github.com/Chen100E/zcrypt-s390x/pkg/cpacf"
)

const sectionRule = "=================================================================="

// printModeSection renders the AES mode comparison.
func printModeSection(rows []cipher.AESModeResult) {
	if len(rows) == 0 {
		return
	}
	fmt.Println(sectionRule)
	fmt.Println("AES Mode Comparison (CPACF instruction per mode)")
	fmt.Println(sectionRule)

	fmt.Printf("%-6s %-8s %-8s %14s %14s  %s\n",
		"MODE", "BUFFER", "INSN", "ENCRYPT MB/s", "DECRYPT MB/s", "VERIFIED")
	for _, r := range rows {
		if r.Error != "" {
			fmt.Printf("%-6s %-8s %-8s %14s %14s  %s\n",
				r.Mode, humanSize(r.BlockSize), r.Instruction, "-", "-", "ERROR: "+r.Error)
			continue
		}
		verified := "no"
		if r.Verified {
			verified = "yes"
		}
		fmt.Printf("%-6s %-8s %-8s %14.1f %14.1f  %s\n",
			r.Mode, humanSize(r.BlockSize), r.Instruction,
			r.EncryptMBps, r.DecryptMBps, verified)
	}

	fmt.Println()
	fmt.Println("Instruction mapping and why the numbers look the way they do:")
	for _, info := range cipher.AESModeTable {
		fmt.Printf("  %-4s -> %-5s (MSA-%d)  %s\n",
			info.Mode, info.Instruction, info.MSALevel, info.Notes)
	}
	fmt.Println()
	fmt.Println("Note: crypto/aes on s390x does NOT issue KMCTR for cipher.NewCTR. It")
	fmt.Println("refills a 512-byte ECB keystream buffer with KM and XORs in Go, which is")
	fmt.Println("why CTR measures below CBC here despite being the more parallel mode.")
}

// printSHA3Section renders SHA-3 throughput and the hardware comparison.
func printSHA3Section(rows []cipher.SHA3DigestResult, kernel []cipher.SHA3HardwareInfo) {
	if len(rows) == 0 {
		return
	}
	fmt.Println(sectionRule)
	fmt.Println("SHA-3 (pure-Go Keccak vs CPACF KIMD)")
	fmt.Println(sectionRule)

	// Build a lookup from variant label to the kernel driver info.
	byVariant := map[string]cipher.SHA3HardwareInfo{}
	for _, k := range kernel {
		byVariant[k.KernelDriver] = k
	}

	fmt.Printf("%-9s %12s %14s %14s %8s  %s\n",
		"VARIANT", "BUFFER", "PURE GO MB/s", "CPACF MB/s", "SPEEDUP", "DRIVER")
	for _, r := range rows {
		if r.Error != "" {
			fmt.Printf("%-9s %12s %14s %14s %8s  %s\n",
				r.Variant, humanSize(r.BlockSize), "-", "-", "-", "ERROR: "+r.Error)
			continue
		}
		// Find the kernel info for this variant by matching the driver prefix.
		var drv string
		var hwMBps float64
		for _, k := range kernel {
			if strings.HasPrefix(k.KernelDriver, strings.ToLower(r.Variant)) {
				if k.Hardware {
					drv = k.KernelDriver
				}
				break
			}
		}
		// Measure the hardware path at this size when the driver is present.
		if drv != "" {
			var v cipher.SHA3Variant
			switch r.Variant {
			case "SHA3-224":
				v = cipher.SHA3_224
			case "SHA3-256":
				v = cipher.SHA3_256
			case "SHA3-384":
				v = cipher.SHA3_384
			case "SHA3-512":
				v = cipher.SHA3_512
			}
			if hw, err := cipher.SHA3HardwareBenchmark(v, r.BlockSize, r.Iterations); err == nil {
				hwMBps = hw.MBps
			}
		}
		if drv == "" {
			drv = "software only"
		}
		if hwMBps > 0 {
			fmt.Printf("%-9s %12s %14.1f %14.1f %7.0fx  %s\n",
				r.Variant, humanSize(r.BlockSize), r.MBps, hwMBps, hwMBps/r.MBps, drv)
		} else {
			fmt.Printf("%-9s %12s %14.1f %14s %8s  %s\n",
				r.Variant, humanSize(r.BlockSize), r.MBps, "-", "-", drv)
		}
	}

	fmt.Println()
	fmt.Println("Kernel dispatch for SHA-3:")
	for _, k := range kernel {
		switch {
		case k.KernelDriver == "":
			fmt.Printf("  no driver registered (%s)\n", k.Error)
		case k.Hardware:
			fmt.Printf("  %-20s driver %-16s priority %3d  AF_ALG %v\n",
				k.KernelDriver, k.KernelDriver, k.KernelPriority, k.AFALGAvailable)
		default:
			fmt.Printf("  %-20s driver %-16s priority %3d  software\n",
				k.KernelDriver, k.KernelDriver, k.KernelPriority)
		}
	}
	fmt.Println()
	fmt.Println("The pure-Go sponge is the reference implementation and the fallback; the")
	fmt.Println("CPACF column is what a caller gets through AF_ALG, where sha3-256-s390")
	fmt.Println("lowers to KIMD function code 33. Both produce identical digests, which the")
	fmt.Println("test suite checks before either number is reported.")
}

// printECCSection renders the signature benchmarks.
func printECCSection(rows []cipher.SignatureResult, kernel []cipher.ECCKernelInfo) {
	if len(rows) == 0 {
		return
	}
	fmt.Println(sectionRule)
	fmt.Println("ECC & Digital Signatures (KDSA)")
	fmt.Println(sectionRule)

	fmt.Printf("%-9s %-7s %14s %14s %9s %9s  %s\n",
		"CURVE", "ALG", "SIGN ops/s", "VERIFY ops/s", "SIGN us", "VERIFY us", "KDSA")
	for _, r := range rows {
		if r.Error != "" {
			fmt.Printf("%-9s %-7s %14s %14s %9s %9s  %s\n",
				r.Curve, r.Algorithm, "-", "-", "-", "-", "ERROR: "+r.Error)
			continue
		}
		fmt.Printf("%-9s %-7s %14.0f %14.0f %9.1f %9.1f  %d/%d\n",
			r.Curve, r.Algorithm, r.SignPerSec, r.VerifyPerSec,
			r.SignNanosOp/1000, r.VerifyNanos/1000,
			r.SignCode, r.VerifyCode)
	}

	fmt.Println()
	fmt.Println("KDSA function codes and kernel dispatch:")
	for _, k := range kernel {
		driver := k.KernelDriver
		if driver == "" {
			driver = "(none registered)"
		}
		fmt.Printf("  %-9s codes %2d/%2d  KDSA %-5v  kernel driver: %s\n",
			k.Curve, k.SignCode, k.VerifyCode, k.KDSAUsable, driver)
	}
	fmt.Println()
	fmt.Println("KDSA issues directly from crypto/ecdsa and crypto/ed25519 on s390x; it does")
	fmt.Println("not need a kernel driver. The absence of an ecdsa akcipher entry in")
	fmt.Println("/proc/crypto is expected and does not mean the numbers above are software.")
}

// printXTSSection renders the AES-XTS known-answer result and the
// software-versus-KMF throughput comparison.
//
// This section exists because XTS is the one mode in the table that Go's
// standard library does not implement, so the "pure Go" column here is not
// crypto/cipher driving CPACF blocks — it is this package's own tweak loop
// wrapped around them. The gap between the two columns is therefore the cost of
// doing the GF(2^128) multiply and the XORs in Go instead of in KMF, which is a
// different and more interesting number than a pure AES-round comparison.
func printXTSSection(rows []cipher.XTSResult, vectorsPassed, vectorTotal int, info cipher.XTSHardwareInfo) {
	fmt.Println(sectionRule)
	fmt.Println("AES-XTS (IEEE 1619-2007 / NIST SP 800-38E)")
	fmt.Println(sectionRule)

	fmt.Printf("Known-answer vectors : %d/%d bit-exact (NIST CAVP + CTS cases)\n", vectorsPassed, vectorTotal)
	driver := info.KernelDriver
	if driver == "" {
		driver = "(none registered)"
	}
	fmt.Printf("Kernel driver        : %s (priority %d)\n", driver, info.KernelPriority)
	fmt.Printf("AF_ALG reachable     : %v\n", info.AFALGAvailable)
	if len(info.Alternatives) > 0 {
		fmt.Printf("Registered drivers   : %s\n", strings.Join(info.Alternatives, ", "))
	}
	if info.Error != "" {
		fmt.Printf("Note                 : %s\n", firstLine(info.Error))
	}
	fmt.Println()

	if len(rows) == 0 {
		return
	}

	fmt.Printf("%-8s %-8s %14s %14s %14s %9s  %s\n",
		"MODE", "BUFFER", "GO ENC MB/s", "GO DEC MB/s", "KMF ENC MB/s", "SPEEDUP", "VERIFIED")
	for _, r := range rows {
		label := fmt.Sprintf("XTS-%d", r.KeyBits)
		if r.Error != "" {
			fmt.Printf("%-8s %-8s %14s %14s %14s %9s  %s\n",
				label, humanSize(r.BlockSize), "-", "-", "-", "-", "ERROR: "+firstLine(r.Error))
			continue
		}
		hw := "-"
		sp := "-"
		if r.HardwareMBps > 0 {
			hw = fmt.Sprintf("%.1f", r.HardwareMBps)
			sp = fmt.Sprintf("%.2fx", r.Speedup)
		} else if r.HardwareError != "" {
			hw = "n/a"
			sp = "n/a"
		}
		verified := "no"
		if r.Verified {
			verified = "yes"
		}
		fmt.Printf("%-8s %-8s %14.1f %14.1f %14s %9s  %s\n",
			label, humanSize(r.BlockSize), r.EncryptMBps, r.DecryptMBps, hw, sp, verified)
	}
	if rows[0].HardwareError != "" {
		fmt.Println()
		fmt.Printf("KMF column unavailable: %s\n", firstLine(rows[0].HardwareError))
	}

	fmt.Println()
	fmt.Println("Go has no cipher.NewXTS, so the portable path above is this project's own")
	fmt.Println("implementation: crypto/aes lowers each block to the CPU's AES, but the")
	fmt.Println("tweak doubling and the XORs run in Go.")
	if info.Hardware {
		fmt.Println("The kernel path binds AF_ALG to xts(aes), which dispatches to")
		fmt.Println("xts-aes-s390 (priority 402) and issues KMF (function codes 50/52,")
		fmt.Println("MSA-4), where the tweak multiply, the XOR and the cipher happen in one")
		fmt.Println("instruction. That is the column the portable path is being compared to.")
	} else {
		fmt.Printf("The kernel path binds AF_ALG to xts(aes), which on this host is %q.\n", driver)
		fmt.Println("It is not a CPACF driver, so the comparison measures a different")
		fmt.Println("kernel implementation rather than KMF; on s390x the same code reaches")
		fmt.Println("xts-aes-s390 and KMF.")
	}
	fmt.Println("Both paths reproduce the same CAVP ciphertext, which the test suite")
	fmt.Println("checks before either number is reported.")
}

// printPRNGSection renders the PRNG measurements.
func printPRNGSection(res cipher.PRNGSuiteResult, info cipher.PRNGInfo, err error) {
	fmt.Println(sectionRule)
	fmt.Println("PRNG & Entropy Sources")
	fmt.Println(sectionRule)
	if err != nil {
		fmt.Printf("PRNG suite failed: %v\n", err)
		return
	}

	fmt.Printf("crypto/rand throughput    : %10.1f MB/s\n", res.CryptoRand.MBps)
	if res.HWRNG != nil {
		fmt.Printf("/dev/hwrng throughput     : %10.2f MB/s\n", res.HWRNG.MBps)
	} else if res.HWRNGError != "" {
		fmt.Printf("/dev/hwrng throughput     : unavailable (%s)\n", firstLine(res.HWRNGError))
	}

	fmt.Printf("entropy_avail             : %d/%d bits (full: %v)\n",
		res.Entropy.EntropyAvail, res.Entropy.PoolSize, res.Entropy.Full)
	fmt.Printf("PRNO facility (STFLE 57)  : %v\n", info.PRNOFacility)
	fmt.Printf("Go crypto/rand uses PRNO  : %v\n", info.GoUsesPRNO)
	if info.KernelTRNGDriver != "" {
		fmt.Printf("kernel TRNG driver        : %s\n", info.KernelTRNGDriver)
	}

	r := res.Randomness
	fmt.Println()
	fmt.Printf("Randomness smoke tests over %d bytes from %s:\n",
		r.SampleBytes, res.SampleSource)
	fmt.Printf("  byte chi-square   : %10.1f  (255 dof, 0.999 quantile ~344)\n", r.ByteChiSquare)
	fmt.Printf("  bit balance       : %10.5f  (ideal 0.5)\n", r.BitBalance)
	fmt.Printf("  Shannon entropy   : %10.4f  bits/byte (ceiling 8)\n", r.EntropyPerByte)
	fmt.Printf("  serial correlation: %10.5f  (ideal 0)\n", r.SerialCorrelation)
	fmt.Printf("  longest byte run  : %10d\n", r.LongestRun)
	fmt.Printf("  distinct 16B blocks: %d/%d (%d duplicates)\n",
		r.DistinctBlocks, r.TotalBlocks, r.DuplicateBlocks)

	if len(res.Anomalies) > 0 {
		fmt.Println()
		fmt.Println("ANOMALIES:")
		for _, a := range res.Anomalies {
			fmt.Printf("  - %s\n", a)
		}
	} else {
		fmt.Println()
		fmt.Println("No anomalies: every statistic is within its bound.")
	}

	fmt.Println()
	fmt.Println(info.Notes)
}

// runSweep executes --sweep and prints the curves.
func runSweep(scale int) {
	res := cipher.RunSweep(scale)
	if err := cipher.ValidateSweep(res); err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: sweep produced an invalid result: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(sectionRule)
	fmt.Printf("  Buffer Size Performance Sweep (scale %d, elapsed %s)\n", res.Scale, res.Elapsed)
	fmt.Println(sectionRule)

	for _, c := range res.Curves {
		fmt.Println()
		fmt.Printf("%s\n", c.Algorithm)
		fmt.Printf("%-10s %14s %12s\n", "BUFFER", "MB/s", "ITERATIONS")
		for _, p := range c.Points {
			if p.Error != "" {
				fmt.Printf("%-10s %14s %12s\n", humanSize(p.BlockSize), "ERROR", p.Error)
				continue
			}
			fmt.Printf("%-10s %14.1f %12d\n", humanSize(p.BlockSize), p.MBps, p.Iterations)
		}
		fmt.Printf("  peak %.1f MB/s at %s | knee %s (%.0f%% of peak) | plateau %s..%s | decline %.1f%%\n",
			c.PeakMBps, humanSize(c.PeakSize), humanSize(c.KneeSize), c.KneeFraction*100,
			humanSize(c.PlateauMin), humanSize(c.PlateauMax), c.DeclinePercent)
	}

	// Crossovers between every pair, since that is the question a caller
	// choosing between primitives actually asks.
	fmt.Println()
	fmt.Println("Crossovers within the ladder:")
	found := false
	for i := 0; i < len(res.Curves); i++ {
		for j := i + 1; j < len(res.Curves); j++ {
			if size := cipher.CrossoverPoint(res.Curves[i], res.Curves[j]); size > 0 {
				fmt.Printf("  %s crosses %s at %s\n",
					res.Curves[i].Algorithm, res.Curves[j].Algorithm, humanSize(size))
				found = true
			}
		}
	}
	if !found {
		fmt.Println("  none: the ordering is fixed by which CPACF instruction backs each")
		fmt.Println("  primitive, not by buffer size.")
	}
}

// runWriteBaseline implements --write-baseline.
func runWriteBaseline(path string, caps cpacf.HardwareCapabilities) {
	fmt.Fprintf(os.Stderr, "measuring baseline metrics...\n")
	metrics, err := cipher.BuildBaselineMetrics(1)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: %v\n", err)
		os.Exit(1)
	}
	b := cipher.NewBaseline(machineFingerprint(caps), metrics,
		fmt.Sprintf("captured by zcrypt --write-baseline on %s", caps.MachineType))
	if err := cipher.WriteBaseline(path, b); err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "wrote %d metrics to %s\n", len(metrics), path)

	// Print the metrics so a caller piping this sees them without reading the
	// file back.
	for _, m := range metrics {
		fmt.Printf("%-26s %14.1f %s\n", m.Name, m.MBps, m.Unit)
	}
}

// runBaselineCheck implements --baseline-check.
//
// Exit status is the contract the shell script depends on: 0 within tolerance,
// 1 a regression, 2 the comparison could not be performed.
func runBaselineCheck(path string, caps cpacf.HardwareCapabilities, tolerance float64) {
	base, err := cipher.ReadBaseline(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: %v\n", err)
		os.Exit(2)
	}

	metrics, err := cipher.BuildBaselineMetrics(1)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: measure: %v\n", err)
		os.Exit(2)
	}

	rep := cipher.CompareMetrics(base, metrics, machineFingerprint(caps), tolerance)

	// JSON to stdout so the shell script can parse the verdict; the human
	// summary goes to stderr so the two do not interfere.
	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: marshal comparison: %v\n", err)
		os.Exit(2)
	}
	fmt.Println(string(data))

	fmt.Fprintf(os.Stderr, "baseline: %s\n", rep.Summary())
	if !rep.Comparable {
		fmt.Fprintf(os.Stderr, "  reason: %s\n", rep.ComparableReason)
	}
	for _, c := range rep.Results {
		switch c.Verdict {
		case cipher.VerdictRegressed:
			fmt.Fprintf(os.Stderr, "  REGRESSED %-26s %10.1f -> %10.1f %s (%+.1f%%)\n",
				c.Name, c.Baseline, c.Current, c.Unit, c.DeltaPct)
		case cipher.VerdictImproved:
			fmt.Fprintf(os.Stderr, "  improved  %-26s %10.1f -> %10.1f %s (%+.1f%%)\n",
				c.Name, c.Baseline, c.Current, c.Unit, c.DeltaPct)
		case cipher.VerdictMissing:
			fmt.Fprintf(os.Stderr, "  missing   %-26s %s\n", c.Name, c.Note)
		}
	}

	switch {
	case !rep.Comparable:
		os.Exit(2)
	case rep.Regressions > 0:
		os.Exit(1)
	}
}

// firstLine returns the first line of s, for compact inline error reporting.
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
