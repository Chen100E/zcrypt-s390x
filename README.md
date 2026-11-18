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

## 📄 License

Licensed under the [MIT License](./LICENSE). Contributions and PRs for IBM Z and LinuxONE optimizations are warmly welcomed!
