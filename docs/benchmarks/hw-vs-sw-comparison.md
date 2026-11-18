# Hardware vs Software Crypto on IBM LinuxONE

Measured on the host that runs this repository's benchmark timer.

| Property | Value |
| --- | --- |
| Architecture | `s390x` |
| Machine type | `9175` |
| Kernel | `5.15.0-56-generic` |
| OpenSSL | OpenSSL 3.0.2 |
| Go | go1.23.2 |
| Measured at | 2026-11-18T03:33:28Z |
| OpenSSL block size | 16384 bytes |
| ZCrypt AES buffer | 1 MB |
| ZCrypt digest buffer | 1 MB |

"Hardware" means the CPACF instructions are live. "Software" means they are
masked off, so the portable code paths run on the same CPU and the same kernel.

## AES-256-GCM

| Implementation | Path | Throughput (MB/s) |
| --- | --- | ---: |
| OpenSSL | CPACF `KMA` | 13869.20 |
| OpenSSL | portable C | 138.78 |
| ZCrypt | CPACF `KMA` (seal) | 13717.78 |
| ZCrypt | CPACF `KMA` (open) | 14543.85 |
| ZCrypt | portable Go (seal) | 65.61 |
| ZCrypt | portable Go (open) | 65.84 |

Hardware gain, OpenSSL: **99.9x**
Hardware gain, ZCrypt seal: **209.1x**
Hardware gain, ZCrypt open: **220.9x**

## SHA-256

| Implementation | Path | Throughput (MB/s) |
| --- | --- | ---: |
| OpenSSL | CPACF `KIMD` | 4383.91 |
| OpenSSL | portable C | 274.02 |
| ZCrypt | CPACF `KIMD` | 4345.05 |
| ZCrypt | portable Go | 147.86 |

Hardware gain, OpenSSL: **16.0x**
Hardware gain, ZCrypt: **29.4x**

## SHA-512

| Implementation | Path | Throughput (MB/s) |
| --- | --- | ---: |
| OpenSSL | CPACF `KIMD` | 6697.94 |
| OpenSSL | portable C | 437.64 |
| ZCrypt | CPACF `KIMD` | 6877.15 |
| ZCrypt | portable Go | 217.74 |

Hardware gain, OpenSSL: **15.3x**
Hardware gain, ZCrypt: **31.6x**

## Reading the numbers

The two hardware columns agree because both runtimes end up in the same place.
On s390x `crypto/aes` calls `KM`/`KMC`/`KMCTR`/`KMA` and `crypto/sha256`
calls `KIMD`; OpenSSL's `aes-s390x.pl` and `sha512-s390x.pl` do the same.
The residual difference is per-call overhead, not instruction throughput:
OpenSSL reuses one long-lived context across a 3-second `speed` run, while
ZCrypt allocates per iteration and measures from the Go side, which includes
AEAD construction and the `cipher.AEAD` interface boundary.

The software columns are what the same machine does without the instructions,
and they are where the value of the hardware shows up. The ratio is the point:
on this host a single CPACF call does the work of dozens to hundreds of
portable iterations, and it does so without burning a general-purpose core.

Caveats worth stating plainly:

- These are single-threaded throughput numbers on a 2-core LPAR. CPACF
  throughput scales with cores, and the LPAR's crypto engines are shared with
  the rest of the machine.
- `OPENSSL_s390xcap="stfle:0:0:0:0"` masks the facility bits OpenSSL reads at
  start-up. It does not change the hardware; it only stops OpenSSL from
  selecting the accelerated paths. It is the closest thing to a clean A/B on
  the same CPU.
- The `purego` build tag changes which Go implementation runs, not what the CPU
  is capable of. Numbers move with kernel version, LPAR weight and cache state.

## Reproducing

```bash
scripts/compare-openssl.sh docs/benchmarks/hw-vs-sw-comparison.md
```

Override the knobs if the defaults are too slow or too noisy for your host:

```bash
OPENSSL_SECS=1 ZC_LARGE_N=50 scripts/compare-openssl.sh
```
