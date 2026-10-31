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

## 📄 License

Licensed under the [MIT License](./LICENSE). Contributions and PRs for IBM Z and LinuxONE optimizations are warmly welcomed!
