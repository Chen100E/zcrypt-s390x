package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/Chen100E/zcrypt-s390x/pkg/cipher"
	"github.com/Chen100E/zcrypt-s390x/pkg/cpacf"
)

func main() {
	jsonOutput := flag.Bool("json", false, "Output results in JSON format")
	verifyOnly := flag.Bool("verify", false, "Run NIST test vector verification only")
	iterations := flag.Int("n", 200, "Benchmark iterations per block size")
	flag.Parse()

	// 1. Detect hardware
	caps := cpacf.Detect()

	// 2. Verify NIST compliance
	err := cipher.VerifyNISTVectors()
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: %v\n", err)
		os.Exit(1)
	}

	if *verifyOnly {
		fmt.Println("NIST SHA-256 and SHA-512 verification passed on s390x Big-Endian.")
		return
	}

	// 3. Run Throughput Benchmarks across block sizes (64KB, 1MB)
	sha256_64K, sha512_64K := cipher.BenchmarkDigest(64*1024, *iterations)
	sha256_1M, sha512_1M := cipher.BenchmarkDigest(1024*1024, *iterations/4+1)

	if *jsonOutput {
		out := map[string]interface{}{
			"capabilities": caps,
			"nist_verified": true,
			"throughput_mbps": map[string]interface{}{
				"sha256_64k": sha256_64K,
				"sha512_64k": sha512_64K,
				"sha256_1m":  sha256_1M,
				"sha512_1m":  sha512_1M,
			},
		}
		data, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(data))
		return
	}

	fmt.Println("==================================================================")
	fmt.Println("  ZCrypt-s390x: Mainframe Hardware Crypto & Digest Benchmark Suite ")
	fmt.Println("==================================================================")
	fmt.Printf("Architecture    : %s (%s)\n", caps.Arch, caps.Endianness)
	fmt.Printf("Machine Model   : %s\n", caps.MachineType)
	fmt.Printf("Hardware CPACF  : %v (Features: %v)\n", caps.HasCPACF, caps.CryptoFeatures)
	fmt.Printf("Vector Unit(VX) : %v | On-Chip NNPA: %v\n", caps.HasVector, caps.HasNNPA)
	fmt.Println("------------------------------------------------------------------")
	fmt.Println("NIST Test Vectors : [PASS] Big-Endian bit-exact match confirmed")
	fmt.Println("------------------------------------------------------------------")
	fmt.Printf("SHA-256 Throughput (64KB buffer) : %8.2f MB/sec\n", sha256_64K)
	fmt.Printf("SHA-512 Throughput (64KB buffer) : %8.2f MB/sec\n", sha512_64K)
	fmt.Printf("SHA-256 Throughput ( 1MB buffer) : %8.2f MB/sec\n", sha256_1M)
	fmt.Printf("SHA-512 Throughput ( 1MB buffer) : %8.2f MB/sec\n", sha512_1M)
	fmt.Println("==================================================================")
}
