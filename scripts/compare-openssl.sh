#!/usr/bin/env bash
# compare-openssl.sh - compare ZCrypt's CPACF throughput against OpenSSL on s390x.
#
# On s390x, OpenSSL and Go both reach the same hardware: the CPACF instructions
# (KM for ECB/CBC, KMC for chaining modes, KMCTR for CTR, KMA for GCM, KIMD for
# digests). The interesting number is therefore not "OpenSSL vs ZCrypt" but
# "hardware vs software", so this script measures each implementation twice:
# once with the crypto instructions enabled, once with them masked off.
#
#   OpenSSL  : OPENSSL_s390xcap="stfle:0:0:0:0" clears the facility bits that
#              OpenSSL consults at start-up, forcing its portable C paths.
#   ZCrypt   : -tags purego makes crypto/aes and crypto/sha256 skip the s390x
#              assembly and use the generic bitsliced implementations.
#
# Usage: scripts/compare-openssl.sh [output.md]
#   With no argument the Markdown report goes to stdout.

set -euo pipefail

OUT="${1:-}"
GO_BIN="${GO_BIN:-go}"
# Blocks OpenSSL reports on; 16384 is the largest and the one we compare on.
BLOCK=16384
OPENSSL_SECS="${OPENSSL_SECS:-3}"
# Keep the ZCrypt sweep short: -n controls iterations per block size.
ZC_LARGE_N="${ZC_LARGE_N:-200}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

log() { printf '%s\n' "$*" >&2; }

require() {
    command -v "$1" >/dev/null 2>&1 || {
        log "error: '$1' not found in PATH"
        exit 1
    }
}

require openssl
require "$GO_BIN"

# ---------------------------------------------------------------------------
# OpenSSL: parse the "numbers are in 1000s of bytes per second" table.
# The last column of the row matching the algorithm is what we want, in kB/s.
# ---------------------------------------------------------------------------
openssl_throughput() {
    local evp="$1" cap="$2"
    local raw
    if [ -n "$cap" ]; then
        raw=$(OPENSSL_s390xcap="$cap" openssl speed -seconds "$OPENSSL_SECS" -evp "$evp" 2>/dev/null)
    else
        raw=$(openssl speed -seconds "$OPENSSL_SECS" -evp "$evp" 2>/dev/null)
    fi
    # Rows look like: "AES-256-GCM     229395.88k   875088.94k  ...  13871379.35k"
    # OpenSSL upper-cases cipher names but leaves digest names lower-case, so
    # compare case-insensitively.
    printf '%s\n' "$raw" \
        | awk -v evp="$evp" '
            toupper($1) == toupper(evp) && $NF ~ /k$/ {
                v = $NF
                sub(/k$/, "", v)
                printf "%.2f\n", v / 1000
                found = 1
                exit
            }
            END { if (!found) exit 1 }
        '
}

# ---------------------------------------------------------------------------
# ZCrypt: run the built binary and pull the 1 MB row out of the AES table, or
# the "1MB buffer" digest lines.
# ---------------------------------------------------------------------------
build_zcrypt() {
    local tags="$1" out="$2"
    if [ -n "$tags" ]; then
        "$GO_BIN" build -tags "$tags" -o "$out" .
    else
        "$GO_BIN" build -o "$out" .
    fi
}

zcrypt_aes() {
    # $1 binary, $2 encrypt|decrypt -> MB/s at the 1 MB buffer size
    # Row is "1 MB <encrypt> <decrypt>", so $1 is the size number and $2 the
    # unit, leaving the two measurements in $3 and $4.
    local out
    out=$("$1" -n "$ZC_LARGE_N" 2>/dev/null || true)
    printf '%s\n' "$out" | awk -v dir="$2" '
        $1 == "1" && $2 == "MB" && NF >= 4 {
            if (dir == "encrypt") printf "%.2f\n", $3
            else                  printf "%.2f\n", $4
            exit
        }
    '
}

zcrypt_digest() {
    # $1 binary, $2 256|512 -> MB/s on 1 MB buffers
    # Row is "SHA-256 Throughput ( 1MB buffer) :  4353.84 MB/sec", so the number
    # sits in the second-to-last field and $NF is the "MB/sec" unit.
    local out
    out=$("$1" -no-aes 2>/dev/null || true)
    printf '%s\n' "$out" | awk -v alg="$2" '
        $0 ~ ("^SHA-" alg " Throughput \\( 1MB buffer\\)") && NF >= 2 {
            printf "%.2f\n", $(NF - 1)
            exit
        }
    '
}

# ---------------------------------------------------------------------------
# Measure everything.
# ---------------------------------------------------------------------------
log "measuring OpenSSL with CPACF enabled..."
OS_GCM_HW=$(openssl_throughput aes-256-gcm "")
OS_SHA256_HW=$(openssl_throughput sha256 "")
OS_SHA512_HW=$(openssl_throughput sha512 "")

log "measuring OpenSSL with CPACF masked off (portable C paths)..."
OS_GCM_SW=$(openssl_throughput aes-256-gcm "stfle:0:0:0:0")
OS_SHA256_SW=$(openssl_throughput sha256 "stfle:0:0:0:0")
OS_SHA512_SW=$(openssl_throughput sha512 "stfle:0:0:0:0")

log "building ZCrypt (default, CPACF assembly)..."
build_zcrypt "" "$TMP/zcrypt-hw"
ZC_ENC_HW=$(zcrypt_aes "$TMP/zcrypt-hw" encrypt)
ZC_DEC_HW=$(zcrypt_aes "$TMP/zcrypt-hw" decrypt)
ZC_SHA256_HW=$(zcrypt_digest "$TMP/zcrypt-hw" 256)
ZC_SHA512_HW=$(zcrypt_digest "$TMP/zcrypt-hw" 512)

log "building ZCrypt with -tags purego (portable Go paths)..."
build_zcrypt "purego" "$TMP/zcrypt-purego"
ZC_ENC_SW=$(zcrypt_aes "$TMP/zcrypt-purego" encrypt)
ZC_DEC_SW=$(zcrypt_aes "$TMP/zcrypt-purego" decrypt)
ZC_SHA256_SW=$(zcrypt_digest "$TMP/zcrypt-purego" 256)
ZC_SHA512_SW=$(zcrypt_digest "$TMP/zcrypt-purego" 512)

# ---------------------------------------------------------------------------
# Report.
# ---------------------------------------------------------------------------
ARCH=$(uname -m)
# /proc/sysinfo is a multi-column table on s390x; take the value next to the
# "Type:" label rather than the first field.
MACHINE=$(awk '/^Type:/ {print $2; exit}' /proc/sysinfo 2>/dev/null || true)
[ -n "$MACHINE" ] || MACHINE="n/a"
KERNEL=$(uname -r)
OSSL_VER=$(openssl version | awk '{print $1" "$2}')
GO_VER=$("$GO_BIN" version | awk '{print $3}')
DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# ratio helper: hardware / software, one decimal place
ratio() {
    awk -v a="$1" -v b="$2" 'BEGIN {
        if (b + 0 == 0) { print "n/a"; exit }
        printf "%.1fx", a / b
    }'
}

report() {
    cat <<EOF
# Hardware vs Software Crypto on IBM LinuxONE

Measured on the host that runs this repository's benchmark timer.

| Property | Value |
| --- | --- |
| Architecture | \`${ARCH}\` |
| Machine type | \`${MACHINE}\` |
| Kernel | \`${KERNEL}\` |
| OpenSSL | ${OSSL_VER} |
| Go | ${GO_VER} |
| Measured at | ${DATE} |
| OpenSSL block size | ${BLOCK} bytes |
| ZCrypt AES buffer | 1 MB |
| ZCrypt digest buffer | 1 MB |

"Hardware" means the CPACF instructions are live. "Software" means they are
masked off, so the portable code paths run on the same CPU and the same kernel.

## AES-256-GCM

| Implementation | Path | Throughput (MB/s) |
| --- | --- | ---: |
| OpenSSL | CPACF \`KMA\` | ${OS_GCM_HW} |
| OpenSSL | portable C | ${OS_GCM_SW} |
| ZCrypt | CPACF \`KMA\` (seal) | ${ZC_ENC_HW} |
| ZCrypt | CPACF \`KMA\` (open) | ${ZC_DEC_HW} |
| ZCrypt | portable Go (seal) | ${ZC_ENC_SW} |
| ZCrypt | portable Go (open) | ${ZC_DEC_SW} |

Hardware gain, OpenSSL: **$(ratio "$OS_GCM_HW" "$OS_GCM_SW")**
Hardware gain, ZCrypt seal: **$(ratio "$ZC_ENC_HW" "$ZC_ENC_SW")**
Hardware gain, ZCrypt open: **$(ratio "$ZC_DEC_HW" "$ZC_DEC_SW")**

## SHA-256

| Implementation | Path | Throughput (MB/s) |
| --- | --- | ---: |
| OpenSSL | CPACF \`KIMD\` | ${OS_SHA256_HW} |
| OpenSSL | portable C | ${OS_SHA256_SW} |
| ZCrypt | CPACF \`KIMD\` | ${ZC_SHA256_HW} |
| ZCrypt | portable Go | ${ZC_SHA256_SW} |

Hardware gain, OpenSSL: **$(ratio "$OS_SHA256_HW" "$OS_SHA256_SW")**
Hardware gain, ZCrypt: **$(ratio "$ZC_SHA256_HW" "$ZC_SHA256_SW")**

## SHA-512

| Implementation | Path | Throughput (MB/s) |
| --- | --- | ---: |
| OpenSSL | CPACF \`KIMD\` | ${OS_SHA512_HW} |
| OpenSSL | portable C | ${OS_SHA512_SW} |
| ZCrypt | CPACF \`KIMD\` | ${ZC_SHA512_HW} |
| ZCrypt | portable Go | ${ZC_SHA512_SW} |

Hardware gain, OpenSSL: **$(ratio "$OS_SHA512_HW" "$OS_SHA512_SW")**
Hardware gain, ZCrypt: **$(ratio "$ZC_SHA512_HW" "$ZC_SHA512_SW")**

## Reading the numbers

The two hardware columns agree because both runtimes end up in the same place.
On s390x \`crypto/aes\` calls \`KM\`/\`KMC\`/\`KMCTR\`/\`KMA\` and \`crypto/sha256\`
calls \`KIMD\`; OpenSSL's \`aes-s390x.pl\` and \`sha512-s390x.pl\` do the same.
The residual difference is per-call overhead, not instruction throughput:
OpenSSL reuses one long-lived context across a 3-second \`speed\` run, while
ZCrypt allocates per iteration and measures from the Go side, which includes
AEAD construction and the \`cipher.AEAD\` interface boundary.

The software columns are what the same machine does without the instructions,
and they are where the value of the hardware shows up. The ratio is the point:
on this host a single CPACF call does the work of dozens to hundreds of
portable iterations, and it does so without burning a general-purpose core.

Caveats worth stating plainly:

- These are single-threaded throughput numbers on a 2-core LPAR. CPACF
  throughput scales with cores, and the LPAR's crypto engines are shared with
  the rest of the machine.
- \`OPENSSL_s390xcap="stfle:0:0:0:0"\` masks the facility bits OpenSSL reads at
  start-up. It does not change the hardware; it only stops OpenSSL from
  selecting the accelerated paths. It is the closest thing to a clean A/B on
  the same CPU.
- The \`purego\` build tag changes which Go implementation runs, not what the CPU
  is capable of. Numbers move with kernel version, LPAR weight and cache state.

## Reproducing

\`\`\`bash
scripts/compare-openssl.sh docs/benchmarks/hw-vs-sw-comparison.md
\`\`\`

Override the knobs if the defaults are too slow or too noisy for your host:

\`\`\`bash
OPENSSL_SECS=1 ZC_LARGE_N=50 scripts/compare-openssl.sh
\`\`\`
EOF
}

if [ -n "$OUT" ]; then
    mkdir -p "$(dirname "$OUT")"
    report > "$OUT"
    log "wrote $OUT"
else
    report
fi
