//go:build s390x

package cpacf

// This file drives the CPACF Query functions directly in hardware.
//
// Every CPACF instruction family (KM, KMC, KMCTR, KMA, KIMD, KLMD, KDSA)
// reserves function code 0 as a "Query" operation. Executing it with a 16-byte
// parameter block returns a bitmap of the function codes that the machine
// actually implements.
//
// This is strictly stronger evidence than the STFLE facility bits in
// /proc/cpuinfo:
//
//   - Several MSA extensions (1, 2, 6, 7, 10, 11, 13) have no STFLE bit at all,
//     so their presence can only be established this way.
//   - A facility bit states that an instruction exists; the Query bitmap states
//     which key sizes and modes that instruction supports.
//
// Only instructions whose mnemonics the Go assembler recognises are used here.
// PCKMO (MSA-3), KMO/KMF (MSA-4) and PRNO (MSA-5) have no Go mnemonic; their
// presence is established from STFLE facility bits, which is authoritative for
// exactly those levels because each owns a dedicated facility bit.
//
// The instruction encodings and register conventions mirror the Go runtime's
// own internal/cpu implementation for s390x.

// ProbeQuery executes the Query function of every encodable CPACF instruction.
//
// It must only be called after Detect() reported HasCPACF: on a machine without
// CPACF these instructions raise SIGILL, which the Go runtime cannot recover
// from. The guard below makes that contract explicit and returns an error
// instead of crashing.
func ProbeQuery(caps HardwareCapabilities) Query {
	if !caps.HasCPACF {
		return Query{Error: "CPACF not available on this host"}
	}
	return Query{
		Available: true,
		KM:        kmQuery(),
		KMC:       kmcQuery(),
		KMCTR:     kmctrQuery(),
		KMA:       kmaQuery(),
		KIMD:      kimdQuery(),
		KLMD:      klmdQuery(),
		KDSA:      kdsaQuery(),
	}
}

// Declared in query_s390x.s. Each writes 16 bytes of function-code bitmap into
// the return slot using the Query function code (R0 = 0).
func kmQuery() FunctionBitmap
func kmcQuery() FunctionBitmap
func kmctrQuery() FunctionBitmap
func kmaQuery() FunctionBitmap
func kimdQuery() FunctionBitmap
func klmdQuery() FunctionBitmap
func kdsaQuery() FunctionBitmap
