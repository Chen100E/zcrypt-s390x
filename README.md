# ZCrypt-s390x 🔐

[![Multi-Arch Crypto CI](https://img.shields.io/badge/CI-Multi--Arch%20(s390x%20%2F%20amd64%20%2F%20arm64)-brightgreen.svg)]()
[![Go Report Card](https://img.shields.io/badge/Go-1.22+-blue.svg)](https://golang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Architecture](https://img.shields.io/badge/Architecture-IBM%20s390x%20(Big--Endian)-purple.svg)]()
[![Hardware CPACF](https://img.shields.io/badge/Hardware-IBM%20CPACF%20%2F%20MSA-red.svg)]()

**ZCrypt-s390x** is an open-source hardware-accelerated cryptographic benchmark and zero-copy packet serialization verification suite designed specifically for **IBM Z and LinuxONE (`s390x`)** mainframes.

---

## 🌟 Background & Motivation

IBM z/Architecture (`s390x`) provides dedicated on-chip cryptographic hardware acceleration known as **CPACF (CP Assist for Cryptographic Function)** alongside Message-Security-Assist (MSA) instructions (KIMD, KLMD, KMAC, KMCTR) and vector extensions.

Many open-source cryptographic libraries and distributed data systems written for Little-Endian architectures (x86_64, arm64) suffer from two common pitfalls when compiled on s390x:
1. **Silent Fallback to Slow Emulation**: Failing to engage CPACF hardware instructions, resulting in significant cryptographic throughput penalties.
2. **Endianness Bit Inversion**: Inverting binary digest states or network serialization packets during buffer packing and unpacking.

**ZCrypt-s390x** provides automated validation, hardware instruction discovery, and high-precision throughput profiling.

---

## 📋 Architecture Overview

```
+------------------------------------------------------------------------+
|                          ZCrypt-s390x Engine                           |
+-----------------------------------+------------------------------------+
                                    |
            +-----------------------+-----------------------+
            |                                               |
     [CPACF Detector]                                [Crypto Engine]
  - Discovers IBM z15/z16 model                   - Hardware SHA-256 / SHA-512
  - Inspects MSA1-MSA9 flags                      - NIST Vector Bit-Exactness
            |                                               |
            +-----------------------+-----------------------+
                                    |
                    +---------------+---------------+
                    |                               |
          [Zero-Copy Codec]               [Benchmarking Suite]
       Big-Endian Packet Stream          Measures MB/sec Throughput
```

---

## 🛠️ Quick Start

### 1. Build and Run
```bash
go build -o zcrypt main.go
./zcrypt
```

### 2. Verify NIST Vector Conformance
```bash
./zcrypt -verify
```

### 3. Structured JSON Export
```bash
./zcrypt -json
```

---

## 🚀 AES-256-GCM Hardware Acceleration

AES on s390x is not a table lookup — it is a single instruction. CPACF exposes
four cipher instructions, and Go's `crypto/aes` picks the right one at runtime
based on the facility bits reported by the kernel:

| Instruction | Meaning | Used for |
| --- | --- | --- |
| `KM` | Cipher Message | Single-block ECB/CBC |
| `KMC` | Cipher Message with Chaining | CBC with chaining value |
| `KMCTR` | Cipher Message with Counter | CTR |
| `KMA` | Cipher Message with Authentication | GCM (encrypt + GHASH in one call) |

For AES-256-GCM the hot path is `KMA`, which performs the block encryption and
the GHASH authentication over the same pass. The alternative is `KM`/`KMC` for
the blocks plus a separate `KIMD` GHASH sweep — two memory passes instead of
one. On this build the assembly path is what runs; `zcrypt` reports which one
it selected:

```
AES Implementation
==================================================================
Build path      : CPACF KM/KMC/KMCTR/KMA assembly path selected by crypto/aes
```

The build tag `purego` forces the portable bitsliced implementation instead, so
the two paths can be compared on the same machine:

```bash
go build -o zcrypt-hw .                # CPACF assembly
go build -tags purego -o zcrypt-sw .   # portable Go
```

### Measured throughput

Machine: IBM LinuxONE, type `9175`, 2 cores, kernel `5.15.0-56-generic`,
MSA-13. AES-256-GCM, 1 MB buffers:

| Buffer | Encrypt (MB/s) | Decrypt (MB/s) |
| ---: | ---: | ---: |
| 1 KB | 6830.61 | 6230.08 |
| 64 KB | 14630.76 | 14863.90 |
| 1 MB | 13669.55 | 14112.63 |

The dip at 1 MB relative to 64 KB is cache, not the instruction: 64 KB stays
inside L1/L2, while 1 MB streams from L2/L3 and the per-iteration allocation
becomes visible. Small buffers are dominated by call overhead — 1 KB is roughly
half the peak — which is why the sweep reports three sizes rather than one.

Correctness is checked before any timing runs. Four NIST AES-256-GCM vectors
cover seal, open, and a tampered tag that must be rejected:

```
NIST AES-256-GCM     : [PASS] 4/4 vectors bit-exact (seal + open + tag tamper)
```

Big-endian is the point of the exercise. On a little-endian host a missing byte
swap is often cancelled out by a compensating swap somewhere else in the stack.
On s390x there is nothing to cancel it, so a portability bug shows up
immediately as a wrong digest or a failing tag.

---

## 🔍 Kernel Crypto Backend Verification

Throughput inside a Go process only proves the Go path is fast. It does not
prove the *kernel* is using the hardware — and for anything going through
`AF_ALG`, dm-crypt, IPsec, or kTLS, the kernel's choice is what matters.

`zcrypt` parses `/proc/crypto` and reports which registered algorithms are
dispatched to a CPACF/vector driver. The `-s390` driver suffix is the evidence:
those modules are the ones that emit CPACF instructions.

```
ALGORITHM      DRIVER             PRIORITY       TYPE  BACKEND
aes            aes-s390                300     cipher  HARDWARE (CPACF)
cbc(aes)       cbc-aes-s390            402   skcipher  HARDWARE (CPACF)
ctr(aes)       ctr-aes-s390            402   skcipher  HARDWARE (CPACF)
ecb(aes)       ecb-aes-s390            401   skcipher  HARDWARE (CPACF)
gcm(aes)       gcm-aes-s390            900       aead  HARDWARE (CPACF)
xts(aes)       xts-aes-s390            402   skcipher  HARDWARE (CPACF)
ghash          ghash-s390              300      shash  HARDWARE (CPACF)
sha1           sha1-s390               300      shash  HARDWARE (CPACF)
sha256         sha256-s390             300      shash  HARDWARE (CPACF)
sha512         sha512-s390             300      shash  HARDWARE (CPACF)
sha3-256       sha3-256-s390           300      shash  HARDWARE (CPACF)
sha3-512       sha3-512-s390           300      shash  HARDWARE (CPACF)
```

`gcm(aes)` is the one to look at. Its priority of **900** is far above the
generic implementations, so every `AEAD` request through the kernel crypto API
lands on `gcm-aes-s390` without any explicit configuration.

The raw `/proc/crypto` entry confirms the module and that its self-test passed:

```
name         : gcm(aes)
driver       : gcm-aes-s390
module       : aes_s390
priority     : 900
selftest     : passed
type         : aead
ivsize       : 12
maxauthsize  : 16
```

Summary line on this host:

```
28/45 registered algorithms dispatched to hardware.
```

The count matters more than the list. 45 distinct algorithms are registered; 28
have a hardware driver selected. The remaining 17 split into two groups worth
telling apart. Some are genuinely software-only because no CPACF instruction
exists for them: `blake2b-*`, `md5`, `rsa`, `dh`, `lzo`, and the `*_null`
placeholders. Others have a generic implementation registered alongside a vector
one and the vector driver wins on priority, so they are accelerated but through
the vector facility rather than CPACF — `crc32`, `crc32be` and `crc32c` all
resolve to `*-vx`, and `chacha20` resolves to `chacha20-s390`.

If the hardware count drops after a kernel upgrade, the `-s390` modules failed
to load or the facility bits are being masked.

Verify it yourself:

```bash
grep -B1 -A6 'gcm(aes)' /proc/crypto
grep -c 's390' /proc/crypto
```

---

## 📊 Prometheus Metrics Exporter

`zcrypt` doubles as a Prometheus exporter, so the same measurements that print
to a terminal can be scraped and graphed over time.

```bash
./zcrypt --serve :9110
```

`export --serve` is the equivalent long form. Endpoints:

| Path | Purpose |
| --- | --- |
| `/metrics` | Prometheus exposition |
| `/healthz` | Liveness, returns `200 ok` |

```bash
curl -s localhost:9110/metrics | head -40
curl -s -o /dev/null -w '%{http_code}\n' localhost:9110/healthz   # 200
```

### Metric reference

| Metric | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `zcrypt_up` | gauge | — | 1 if the last collection completed without error |
| `zcrypt_info` | gauge | `arch`, `endianness`, `aes_path`, `version` | Static build and platform info, always 1 |
| `zcrypt_cpacf_available` | gauge | `arch`, `machine_type` | 1 if CPACF instructions exist |
| `zcrypt_max_msa_level` | gauge | — | Highest MSA level confirmed by STFLE or CPACF Query |
| `zcrypt_crypto_features` | gauge | `features` | 1 per confirmed MSA extension level |
| `zcrypt_capability` | gauge | `feature` | 1 when a CPACF-backed primitive is usable |
| `zcrypt_cpacf_query_function` | gauge | `instruction`, `function`, `code` | 1 per function code the hardware Query reports present |
| `zcrypt_kernel_crypto_hw` | gauge | `algorithm`, `driver`, `priority` | 1 if the kernel dispatches this algorithm to hardware |
| `zcrypt_kernel_crypto_algorithms` | gauge | `kind` (`total`/`hardware`) | Registered algorithm counts |
| `zcrypt_aes256gcm_encrypt_mbps` | gauge | `block_size` | AES-256-GCM seal throughput |
| `zcrypt_aes256gcm_decrypt_mbps` | gauge | `block_size` | AES-256-GCM open throughput |
| `zcrypt_aes256gcm_throughput_mbps` | gauge | `direction` | Throughput at the largest buffer, by direction |
| `zcrypt_sha256_throughput_mbps` | gauge | — | SHA-256 on 1 MiB buffers |
| `zcrypt_sha512_throughput_mbps` | gauge | — | SHA-512 on 1 MiB buffers |
| `zcrypt_nist_vectors_passed` | gauge | — | 1 if every NIST vector matched bit-for-bit |
| `zcrypt_scrape_timestamp_seconds` | gauge | — | Unix time of the measurement behind this exposition |

Actual output, trimmed:

```
# HELP zcrypt_cpacf_available 1 if CPACF hardware crypto instructions are available on this host.
# TYPE zcrypt_cpacf_available gauge
zcrypt_cpacf_available{arch="s390x",machine_type="9175"} 1
# HELP zcrypt_max_msa_level Highest Message-Security-Assist extension level confirmed by STFLE or CPACF Query.
# TYPE zcrypt_max_msa_level gauge
zcrypt_max_msa_level 13
# HELP zcrypt_kernel_crypto_algorithms Number of algorithms registered with the kernel crypto API, and how many are hardware-backed.
# TYPE zcrypt_kernel_crypto_algorithms gauge
zcrypt_kernel_crypto_algorithms{kind="total"} 45
zcrypt_kernel_crypto_algorithms{kind="hardware"} 28
# HELP zcrypt_aes256gcm_encrypt_mbps AES-256-GCM seal throughput in MB/s, labelled by buffer size.
# TYPE zcrypt_aes256gcm_encrypt_mbps gauge
zcrypt_aes256gcm_encrypt_mbps{block_size="1024"} 6632.93
zcrypt_aes256gcm_encrypt_mbps{block_size="65536"} 14474.30
zcrypt_aes256gcm_encrypt_mbps{block_size="1048576"} 13314.64
# HELP zcrypt_nist_vectors_passed 1 if every NIST known-answer vector (AES-256-GCM and SHA-2) matched bit-for-bit.
# TYPE zcrypt_nist_vectors_passed gauge
zcrypt_nist_vectors_passed 1
# HELP zcrypt_up 1 if the last collection completed without an internal error.
# TYPE zcrypt_up gauge
zcrypt_up 1
```

A full scrape is 115 lines. Benchmarks are cached for five minutes by default —
they are expensive and do not change second to second — so scraping every 15 s
costs one benchmark per cache window, not one per scrape. Both are adjustable:

```bash
./zcrypt --serve :9110 --benchmark-interval 60s --scale 1
```

`--scale` multiplies the iteration count for a less noisy number at the cost of
a slower first scrape.

### Alerting on the two things that actually break

```yaml
- alert: ZCryptHardwareCryptoLost
  expr: zcrypt_cpacf_available == 0
  for: 10m
  annotations:
    summary: CPACF is no longer available on this host

- alert: ZCryptKernelBackendDegraded
  expr: zcrypt_kernel_crypto_algorithms{kind="hardware"} < 28
  for: 30m
  annotations:
    summary: Fewer algorithms dispatched to hardware than expected
```

The second one catches the realistic failure: a kernel update that drops the
`-s390` modules, so everything still *works* but silently runs in software.

---

## ⚡ Hardware vs Software Comparison

The interesting comparison is not this project against OpenSSL — on s390x both
end up in the same `KMA` and `KIMD` instructions. It is hardware against
software on the *same* machine, which is what the numbers below show.

Full report: [`docs/benchmarks/hw-vs-sw-comparison.md`](docs/benchmarks/hw-vs-sw-comparison.md)

| Algorithm | Implementation | Path | Throughput (MB/s) | Gain |
| --- | --- | --- | ---: | ---: |
| AES-256-GCM | OpenSSL | CPACF `KMA` | 13869.20 | — |
| AES-256-GCM | OpenSSL | portable C | 138.78 | 99.9× |
| AES-256-GCM | ZCrypt (seal) | CPACF `KMA` | 13717.78 | — |
| AES-256-GCM | ZCrypt (seal) | portable Go | 65.61 | 209.1× |
| AES-256-GCM | ZCrypt (open) | CPACF `KMA` | 14543.85 | — |
| AES-256-GCM | ZCrypt (open) | portable Go | 65.84 | 220.9× |
| SHA-256 | OpenSSL | CPACF `KIMD` | 4383.91 | — |
| SHA-256 | OpenSSL | portable C | 274.02 | 16.0× |
| SHA-256 | ZCrypt | CPACF `KIMD` | 4345.05 | — |
| SHA-256 | ZCrypt | portable Go | 147.86 | 29.4× |
| SHA-512 | OpenSSL | CPACF `KIMD` | 6697.94 | — |
| SHA-512 | OpenSSL | portable C | 437.64 | 15.3× |
| SHA-512 | ZCrypt | CPACF `KIMD` | 6877.15 | — |
| SHA-512 | ZCrypt | portable Go | 217.74 | 31.6× |

The two hardware columns agree to within a few percent, which is the sanity
check: both runtimes reached the same instructions, so the residual gap is
per-call overhead rather than throughput. OpenSSL reuses one long-lived context
across a 3-second `speed` run; ZCrypt allocates per iteration and measures from
the Go side, including AEAD construction and the `cipher.AEAD` interface
boundary.

The software columns are where the hardware shows its value — roughly two
orders of magnitude for AES-GCM, one for the digests. AES gains most because
`KMA` fuses encryption and authentication into one pass, so software has to do
both jobs serially.

Reproduce with the script; it measures all four combinations itself rather than
hardcoding anything:

```bash
scripts/compare-openssl.sh docs/benchmarks/hw-vs-sw-comparison.md
```

It masks CPACF for OpenSSL via `OPENSSL_s390xcap="stfle:0:0:0:0"` and builds
ZCrypt twice, with and without `-tags purego`.

---

## 🧭 MSA Level Detection

The Message-Security-Assist level determines which instructions exist. Getting
it right from a runtime check rather than a model-number lookup matters,
because an LPAR can run on a machine whose full facility set is masked, and
because new levels keep appearing.

The authoritative source is `STFLE` (Store Facility List Extended), which the
kernel exposes as facility bits. `zcrypt` reads the bits directly and maps them
to MSA levels:

| Facility bit | MSA level | What it adds |
| ---: | --- | --- |
| 17 | MSA (base) | `KM`/`KMC`, `KIMD`/`KLMD` — DES/3DES and SHA-1 |
| 57 | MSA-5 | `PRNO` pseudo-random number generator |
| 76 | MSA-3 | `PCKMO` — wrap/unwrap keys without exposing them to software |
| 77 | MSA-4 | `KMCTR`, `KMF`, `KMO`, `KIMD-GHASH` — CTR mode and raw GHASH |
| 86 | MSA-12 | Vector-packed cryptographic operations |
| 146 | MSA-8 | `KMA` — AES-GCM encryption and authentication in one instruction |
| 155 | MSA-9 | `KDSA` — ECC and digital signatures |

Only a subset of the extensions has its own facility bit. MSA-1, MSA-2, MSA-6,
MSA-7, MSA-10, MSA-11 and MSA-13 are announced implicitly: their presence has to
be confirmed by running the CPACF Query function of the relevant instruction.
The bit numbers above follow z/Architecture Principles of Operation (SA22-7832)
numbering, where bit 0 is the leftmost bit of the 192-bit facility list, and are
cross-checked against IBM s390-tools `cpacfinfo`, `OPENSSL_s390xcap(7)` and the
Go runtime's `internal/cpu/cpu_s390x.go`.

On this host `STFLE` reports the full chain through MSA-13:

```
Hardware CPACF  : true | Max MSA Level: MSA-13
Crypto Features : msa msa1 msa2 msa3 msa4 msa5 msa6 msa7 msa8 msa9 msa10 msa11 msa12 msa13
Primitives      : AES=true GCM=true GHASH=true SHA3=true ECC=true PRNO=true
```

`STFLE` gives the ceiling. What is actually usable is confirmed by running the
CPACF Query instruction, whose answer is a bitmap of function codes the
hardware will accept. `zcrypt` does both and reports the intersection — a
facility bit can be set while the specific function code is not, for example on
a machine with the base feature but no GCM:

```
KM    (Cipher Message)          : f0 70 38 38 00 00 28 28 00 00 28 28 00 00 00 01
KMC   (Cipher Message w/ Chain) : f0 70 38 38 00 00 00 00 10 00 00 00 00 00 00 01
KMCTR (Cipher Message w/ Ctr)   : f0 70 38 38 00 00 00 00 00 00 00 00 00 00 00 01
KMA   (Cipher Msg w/ Auth)      : 80 00 38 38 00 00 00 00 00 00 00 00 00 00 00 01
KIMD  (Compute Interm Digest)   : f0 00 00 00 fc 00 00 00 40 00 00 00 00 00 00 01
KLMD  (Compute Last Digest)     : f0 00 00 00 fc 00 00 00 00 00 00 00 00 00 00 01
KDSA  (Digital Signature Auth)  : f0 70 70 00 88 88 88 00 00 00 00 00 00 00 00 01
```

Decoding the `KM` line byte by byte. A function code `n` lives in byte `n/8` at
mask `0x80>>(n%8)`, so the 16 bytes read left to right as codes 0-127:

| Byte | Hex | Codes | Meaning |
| ---: | --- | --- | --- |
| 0 | `f0` | 0,1,2,3 | Query, DES, 3DES-192, 3DES-168 |
| 1 | `70` | 9,10,11 | SHA-1, SHA-256, SHA-512 (via `KIMD`/`KLMD`) |
| 2 | `38` | **18,19,20** | **AES-128, AES-192, AES-256** |
| 3 | `38` | 26,27,28 | 3DES-192, 3DES-168, 3DES-128 |
| 6 | `28` | 50,52 | XTS-AES-128, XTS-AES-256 |
| 7 | `28` | 58,60 | AES-CFB-128, AES-OFB-128 |
| 10-11 | `28 28` | 82,84,90,92 | CFB/OFB at the larger block sizes |
| 15 | `01` | 127 | Query Authentication Information (MSA-13) |

`0x38` is `0b00111000` — three adjacent bits, which is exactly AES-128/192/256
in function codes 18/19/20. That is why the AES benchmark can run at all, and
the same pattern in byte 3 is the three 3DES key sizes.

The `KMA` line is the GCM story in one word: byte 0 is `80`, a single bit at
code 0, and bytes 2-3 are the same `38 38` AES pattern. `KMA` is the only
instruction that performs encryption and authentication in a single call, which
is what the AES-256-GCM numbers in this README are measuring.

Reading the bitmap rather than trusting the facility bit matters because a zero
bit means the specific operation is unavailable even when the facility is
announced. In that case `zcrypt` reports the primitive as absent instead of
timing a software fallback and labelling it hardware.

Query is guarded by build tags — `query_s390x.s` holds the assembly for the
instruction itself, `query_other.go` is the stub that returns an empty bitmap on
other architectures — so the same source builds and runs on amd64 and arm64 for
CI, where it correctly reports no CPACF.

```bash
./zcrypt -json | jq '.capabilities.max_msa_level'
```

---

## 🔀 AES Mode Comparison: CBC / CTR / GCM

GCM is not the only mode that matters on a mainframe, and the mode you pick
determines which CPACF instruction you get — which determines the throughput.
`zcrypt` measures all four and records the mapping:

| Mode | CPACF instruction | MSA | Go call path | Parallel | Auth |
|------|-------------------|-----|--------------|:--------:|:----:|
| ECB | `KM` | 1 | `(*aesCipherAsm).Encrypt` | no | no |
| CBC | `KMC` | 1 | `NewCBCEncrypter` → `kmc()` | no | no |
| CTR | `KM` | 1 | `(*aesctr).refill` → `cryptBlocks` + Go XOR | yes | no |
| GCM | `KMA` | 8 | `NewGCM` → `gcmKMA` | yes | yes |

### Measured throughput, AES-256

| Buffer | ECB enc/dec | CBC enc/dec | CTR enc/dec | GCM enc/dec |
|-------:|------------:|------------:|------------:|------------:|
| 1 KiB | 424 / 413 | 2,731 / 6,475 | 2,186 / 1,493 | **6,128 / 6,584** |
| 64 KiB | 423 / 416 | 3,772 / 16,106 | 3,253 / 3,247 | **14,687 / 14,590** |
| 1 MiB | 420 / 419 | 3,559 / 15,563 | 3,112 / 2,952 | **13,241 / 14,163** |

MB/s. `./zcrypt` reproduces these; every row is verified by a round trip before
its timing is counted.

### CTR is slower than CBC, and that is not a typo

The textbook answer is that counter mode is the more parallel construction and
should beat CBC. On s390x with Go 1.23 it does not, and the reason is in the
source rather than in the measurement:

`crypto/aes/ctr_s390x.go` does **not** issue `KMCTR`. It keeps a 512-byte buffer
of ECB-encrypted counter blocks, refills it with `cryptBlocks()` — that is `KM` —
and XORs the keystream into the caller's buffer in Go. `KMCTR` is only reached
inside the AES-GCM implementation, and only on machines below MSA-8.

CBC, by contrast, calls `KMC` once for the whole buffer. The chaining happens
on-chip, the CPU never touches the data, and decrypt handles the entire buffer in
a single instruction — which is why CBC decrypt at 16,106 MB/s is the fastest
number in the table.

The practical consequence: if you are choosing a mode on this platform and you
control both ends, GCM wins outright (KMA fuses the AES rounds with GHASH), CBC
is the best non-authenticated option, and CTR is the slowest of the three despite
being the mode whose hardware instruction exists.

`./zcrypt --verify` checks 8 SP 800-38A Appendix F vectors (ECB F.1.x, CBC
F.2.x, CTR F.5.x across AES-128/192/256) bit-for-bit in both directions. Every
expected ciphertext was reproduced independently with `openssl enc -nopad` on the
target machine before being committed.

---

## 🧬 SHA-3 Hardware Acceleration

MSA-6 added SHA-3 to CPACF. This machine has it, and the kernel binds all four
variants to hardware drivers at priority 300:

```
name: sha3-256   driver: sha3-256-s390   module: sha3_256_s390   priority: 300
```

### Why there is a pure-Go implementation at all

Go 1.24 moved SHA-3 into the standard library as `crypto/sha3`. The target
toolchain here is **go1.23.2**, where that package does not exist. The
alternative, `golang.org/x/crypto/sha3`, would add the project's first
third-party require to a `go.mod` that has none.

So ZCrypt carries both: a dependency-free Keccak-f[1600] sponge as the reference
implementation and fallback, and an AF_ALG path that reaches the real KIMD
hardware through the kernel crypto API. The two are checked against each other
before either is timed.

### Measured throughput, 1 MiB buffer

| Variant | Pure Go | CPACF (AF_ALG) | Speedup |
|---------|--------:|---------------:|--------:|
| SHA3-224 | 68.9 | 9,113 | **132×** |
| SHA3-256 | 66.2 | 8,776 | **133×** |
| SHA3-384 | 50.2 | 8,480 | **169×** |
| SHA3-512 | 34.4 | 7,317 | **213×** |

MB/s. The speedup grows with digest size because a bigger digest means a smaller
sponge rate, so the software permutation runs more rounds per byte while the
hardware instruction's cost is nearly flat.

### Two details that are the whole difficulty of SHA-3 on a big-endian machine

1. **The sponge absorbs and squeezes little-endian lanes**, by definition of
   FIPS 202, even though s390x is big-endian. This is the single most common way
   a SHA-3 implementation produces plausible-looking garbage on a mainframe. The
   FIPS 202 vectors exist to catch anyone who "fixes" it to match the host.

2. **The padding suffix is `0x06`**, not `0x01`. `0x01` is raw Keccak; SHA-3 uses
   the two-bit domain suffix `01` followed by the first padding bit. A raw Keccak
   implementation silently produces wrong digests that are stable and
   self-consistent.

`./zcrypt --verify` checks 11 FIPS 202 vectors across all four variants,
including the three 1,000,000-byte cases.

---

## 🔏 ECC & Digital Signatures

MSA-9 added `KDSA` (Compute Digital Signature Authentication). This machine
reports MSA-13, so every curve below takes the hardware path.

| Curve | Algorithm | Sign | Verify | Sign µs | Verify µs | KDSA codes |
|-------|-----------|-----:|-------:|--------:|----------:|-----------:|
| P-256 | ECDSA | **46,425/s** | 20,774/s | 21.5 | 48.1 | 9 / 1 |
| P-384 | ECDSA | 26,870/s | 10,498/s | 37.2 | 95.3 | 10 / 2 |
| P-521 | ECDSA | 18,184/s | 6,393/s | 55.0 | 156.4 | 11 / 3 |
| Ed25519 | EdDSA | 17,985/s | 6,550/s | 55.6 | 152.7 | 32 / 33 |

The P-256 sign rate independently matches `openssl speed ecdsap256` on the same
host (62,305 sign/s), which is the cross-check that the Go path is issuing KDSA
rather than falling back to `big.Int`.

### The function codes are not symmetric

ECDSA verify codes run 1..3 and sign codes run 9..11. EdDSA puts sign and verify
adjacent at 32/33. That asymmetry is a property of the instruction, not a
transcription error, and it is why the CPACF Query bitmap has to be consulted
per operation rather than per curve — a machine can implement
`KDSA-Verify-P256` without `KDSA-Sign-P256`.

### The honest negative result

`/proc/crypto` on this kernel registers **no** ECDSA akcipher driver:

```
kernel P-256    name="ecdsa-nist-p256"  driver=""  present=false  kdsa=true
kernel Ed25519  name="ed25519"          driver=""  present=false  kdsa=false
```

That does not mean the numbers above are software. KDSA issues directly from
`crypto/ecdsa` and `crypto/ed25519` in userspace; it does not need a kernel
driver to exist. The report says both things rather than implying hardware
acceleration for every operation.

Ed25519 shows `kdsa=false` while still signing at 17,985/s, and the reason is
visible in the raw bitmap:

```
KDSA  : f0 70 70 00 88 88 88 00 00 00 00 00 00 00 00 01
         ^^ bits 1,2,3 set  (verify P-256/384/521)
            ^^ byte 1 = 0x70 -> bits 9,10,11 (sign P-256/384/521)
                     ^^ byte 4 = 0x88 -> bits 32 and 36
```

Function code **32** (Ed25519 sign) is set, but code **33** (Ed25519 verify) is
not. Go's `internal/cpu` sets `HasEDDSA` only when both are present, so the
Ed25519 path falls back to `edwards25519` in userspace. The number is real and
the label is honest about which path produced it — and it is a good illustration
of why the Query bitmap has to be consulted per operation rather than per curve.

---

## 🎲 PRNG & Entropy Sources

MSA-5 added `PRNO`, the CPACF random number instruction. This machine has the
facility bit (STFLE bit 57) and the kernel's `s390-trng` driver is active.

### The finding worth leading with

**`crypto/rand.Read` on s390x does not issue PRNO.** Go's `crypto/rand` is a
userspace ChaCha20-based DRBG seeded once from `getrandom(2)`. The hardware TRNG
is reachable through `/dev/hwrng` (the `s390-trng` driver) and through
`getrandom(2)` once the kernel's CRNG is seeded from it.

ZCrypt measures both separately so the DRBG figure is never presented as PRNO
throughput:

| Source | Throughput | Note |
|--------|-----------:|------|
| `crypto/rand` | 389 MB/s | Go ChaCha20 DRBG, not PRNO |
| `/dev/hwrng` | 2.31 MB/s | CPACF TRNG, root-only, 32-byte driver reads |
| `entropy_avail` | 256/256 bits | pool full; `getrandom(2)` will not block |

### Randomness smoke tests

A 256 KiB `crypto/rand` sample, every statistic reported as a number rather than
a pass/fail opinion:

| Statistic | Measured | Bound |
|-----------|---------:|-------|
| byte-histogram χ² | 249.6 | < 344 (255 dof, 0.999 quantile) |
| bit balance | 0.500482 | 0.49 .. 0.51 |
| Shannon entropy | 7.9993 bits/byte | ≥ 7.9 |
| serial correlation | −0.00099 | −0.1 .. 0.1 |
| longest identical-byte run | 3 | ≤ 16 |
| duplicate 16-byte blocks | 0 / 16,384 | 0 |

These are smoke tests that catch gross faults — a stuck bit, a constant, a
counter that only increments, a source that returns the same block twice — and
nothing more. Passing them is not evidence of cryptographic quality; failing them
is solid evidence of a problem. The test suite includes a negative control: five
obviously broken sources, each of which must be flagged with the specific
statistic that catches it.

ZCrypt cannot issue `PRNO` directly: the Go assembler has no mnemonic for it, and
unlike KDSA or KIMD there is no kernel crypto API algorithm that maps onto it in a
way userspace can drive. The STFLE bit is therefore the authoritative statement
that the instruction exists, and that is what the report cites.

---

## 📐 Buffer Size Performance Sweep

Three sample points cannot show where throughput turns over. `./zcrypt --sweep`
measures a nine-point ladder from 64 B to 4 MiB and reports the knee — the
smallest buffer that reaches 90% of peak.

| Algorithm | 64 B | 1 KiB | 4 KiB | 64 KiB | 4 MiB | Peak | Knee |
|-----------|-----:|------:|------:|-------:|------:|-----:|-----:|
| AES-256-GCM | 702 | 7,066 | 13,854 | **14,249** | 13,523 | 14,249 @ 64 KiB | **4 KiB** |
| SHA-256 | 341 | 2,602 | 3,701 | 4,197 | 4,196 | 4,239 @ 256 KiB | **16 KiB** |
| SHA3-256 (pure Go) | 30 | 65 | 67 | **70** | 70 | 70 @ 64 KiB | **256 B** |

MB/s. Full curves, per-point iteration counts and method notes in
[`docs/benchmarks/buffer-size-sweep.md`](./docs/benchmarks/buffer-size-sweep.md).

### Reading the knees

- **AES-GCM turns over at 4 KiB.** Below it, a single KMA instruction is issuing
  on a buffer shorter than the pipeline is tuned for, and the fixed per-call cost
  has not been amortised. Above it the curve is flat within noise to 4 MiB. An
  application sealing 16 KiB TLS records is already at 97% of peak; one sealing
  1 KiB messages is leaving 2× on the table purely to per-call overhead.
- **SHA-256 needs 16 KiB**, four times more than AES. A hash is inherently
  serial, so there is no parallelism to hide the setup behind.
- **Pure-Go SHA3-256 turns over at 256 B**, far earlier, because its cost is
  almost entirely arithmetic — there is no instruction dispatch to amortise. The
  whole curve sits between 30 and 70 MB/s, which is the correct shape for a
  software permutation and why the hardware path's 133× matters.

No crossovers appear within the ladder: the ordering of these three primitives is
fixed by which CPACF instruction backs each, not by buffer size.

---

## 📉 Performance Regression Detection

A benchmark that is only ever run by hand is a benchmark that silently rots.
`zcrypt` makes the comparison mechanical.

```bash
# Capture a baseline (15 metrics, machine fingerprint included)
./zcrypt --write-baseline docs/benchmarks/baseline.json

# Compare against it; exit 1 on any regression beyond the tolerance
./zcrypt --baseline-check docs/benchmarks/baseline.json --tolerance 20

# Or use the wrapper, which decides the exit status and formats a summary
./scripts/check-regression.sh --tolerance 20
```

The comparability rules are the interesting part. CI runners are amd64 shared VMs
and the baseline is s390x on bare metal, so comparing them directly would report
a 15× "regression" on every push. Architecture and MSA level are therefore hard
requirements for comparison; machine type and Go version are reported as context
but do not block. A non-comparable machine reports every row as `skipped` with
the reason, never as a regression:

```
baseline: 0 regressed, 0 improved, 0 skipped of 15 metrics (tolerance 20%, worst -5.2%)
```

Fifteen metrics: AES-GCM/CBC/CTR encrypt and AES-GCM decrypt at 1 MiB, SHA-256
and SHA-512, pure-Go SHA3-256, and sign/verify rates for all four curves.
Small-buffer figures are deliberately excluded because they are the noisiest rows
and would make the gate fire on scheduling jitter.

Baselines are written atomically (temp file + rename), so an interrupted run
cannot leave a half-written file that the next comparison reads as corrupt.

---

## ⏱️ Continuous Monitoring Mode

`--watch` re-benchmarks on a timer and republishes metrics, turning a one-shot
report into something that runs unattended.

```bash
# Exporter whose collector self-refreshes every 60 seconds
./zcrypt --serve :9110 --watch 60s

# Console monitor: one JSON line per tick
./zcrypt --watch 60s

# Watch with regression detection on every tick
./zcrypt --watch 60s --baseline docs/benchmarks/baseline.json
```

```
{"seq":0,"timestamp":"2026-11-19T06:58:53Z","elapsed_ms":18,
 "aes256gcm_encrypt_mbps":12618.65,"sha256_mbps":4361.14,
 "nist_vectors_ok":true,"max_msa_level":12}
```

The design point: the watch loop does not call the exporter's HTTP handler. It
drives the same `Collector` the exporter uses, and the exporter serves whatever
that collector last produced. So a slow benchmark cannot block a Prometheus
scrape, and a scrape cannot trigger an unscheduled benchmark.

Each tick checks NIST vectors *before* reporting throughput, because a monitor
that reports numbers for a broken primitive is worse than one that reports
nothing. A tick takes about 18 ms at scale 1.

---

---

## 🏛️ Why this needs a permanent s390x host

This project is developed and validated on an IBM LinuxONE Community Cloud
instance (machine type 9175, Ubuntu 22.04, **MSA-13**). That instance is a
**60-day trial**, which cannot support what this tool exists to do.

**What a trial window cannot support:**

1. **Hardware-drift baselines.** CPACF throughput is a property of the *host*
   (microcode level, MSA generation, core allocation). A baseline captured on a
   machine that disappears is worthless — regression detection needs the same
   physical host measured across weeks.
2. **Cross-generation comparison.** Establishing how MSA-13 compares to MSA-9 or
   MSA-12 requires a stable reference host that does not expire mid-series.
3. **Continuous CI for hardware paths.** The `/proc/crypto` backend assertions and
   CPACF Query dumps are only meaningful if they run on real mainframe hardware
   on every change. An expiring runner turns that into a one-off snapshot.
4. **Kernel-crypto API tracking.** Which driver the kernel selects
   (`aes-s390` vs `aes-generic`) changes with kernel and microcode updates. Only
   a long-lived host can show whether a new kernel silently regressed to the
   portable path.

**What the permanent VM would run:**

- A daily hardware-crypto baseline with a stored reference, so a microcode or
  kernel update that quietly disables CPACF is caught the day it lands.
- The Prometheus exporter as a long-lived service exposing
  `zcrypt_kernel_crypto_hw{algorithm="aes"}` continuously.
- Multi-toolchain builds verifying that NIST / SP 800-38A vectors stay bit-exact
  on big-endian across Go releases.
- Sustained PRNG entropy monitoring (`/proc/sys/kernel/random/entropy_avail`)
  under real load.

**Validated on:** IBM LinuxONE III, machine type `9175`, Ubuntu 22.04 LTS,
`s390x` big-endian, **MSA-13**, Go 1.23.2. CPACF hardware path confirmed via
`/proc/crypto` (`aes-s390` prio 300, `gcm(aes)-s390` prio 900).

**Measured:** AES-256-GCM ~13,670 MB/s encrypt / ~14,110 MB/s decrypt at 1 MB
buffers; ~100× faster than the portable C path under OpenSSL.

---

## 📄 License

Licensed under the [MIT License](./LICENSE). Contributions and PRs for IBM Z and LinuxONE optimizations are warmly welcomed!
