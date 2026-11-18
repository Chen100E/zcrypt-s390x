//go:build s390x

#include "textflag.h"

// Each function executes the Query operation (function code 0) of a CPACF
// instruction and stores the resulting 16-byte function-code bitmap in the
// return slot.
//
// Register convention for the Query operation:
//   R0     = function code (0 for Query)
//   R1     = address of the 16-byte parameter block
//   R2, R4 = unused by Query, but required to encode the instruction
//
// Only instructions whose mnemonics the Go assembler recognises are used here:
// KM, KMC, KMCTR, KMA, KIMD, KLMD and KDSA. That covers every primitive ZCrypt
// reports on — AES (all key sizes and modes), AES-GCM, SHA-1/2/3, SHAKE, GHASH
// and ECC signatures.
//
// PCKMO (MSA-3), KMO/KMF (MSA-4) and PRNO (MSA-5) have no assembler mnemonic in
// Go. Their presence is instead established from the STFLE facility bits, which
// is authoritative for exactly those levels because each of them owns a
// dedicated facility bit (see FacilityMSA3/4/5 in detect.go).

TEXT ·kmQuery(SB), NOSPLIT|NOFRAME, $0-16
	MOVD $0, R0
	MOVD $ret+0(FP), R1
	KM   R2, R4
	RET

TEXT ·kmcQuery(SB), NOSPLIT|NOFRAME, $0-16
	MOVD $0, R0
	MOVD $ret+0(FP), R1
	KMC  R2, R4
	RET

TEXT ·kmctrQuery(SB), NOSPLIT|NOFRAME, $0-16
	MOVD $0, R0
	MOVD $ret+0(FP), R1
	KMCTR R2, R4, R4
	RET

TEXT ·kmaQuery(SB), NOSPLIT|NOFRAME, $0-16
	MOVD $0, R0
	MOVD $ret+0(FP), R1
	KMA  R2, R6, R4
	RET

TEXT ·kimdQuery(SB), NOSPLIT|NOFRAME, $0-16
	MOVD $0, R0
	MOVD $ret+0(FP), R1
	KIMD R2, R4
	RET

TEXT ·klmdQuery(SB), NOSPLIT|NOFRAME, $0-16
	MOVD $0, R0
	MOVD $ret+0(FP), R1
	KLMD R2, R4
	RET

TEXT ·kdsaQuery(SB), NOSPLIT|NOFRAME, $0-16
	MOVD $0, R0
	MOVD $ret+0(FP), R1
	KDSA R2, R4
	RET
