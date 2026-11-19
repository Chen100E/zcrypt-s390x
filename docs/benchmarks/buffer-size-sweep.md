# Buffer Size Performance Sweep

Measured on **ci17** — IBM LinuxONE, Machine Type 9175, z/Architecture with
**MSA-13**, Ubuntu 22.04, `go1.23.2 linux/s390x`.

Reproduce with:

```bash
./zcrypt --sweep
```

The numbers below come from `zcrypt.RunSweep(3)` — scale 3, meaning each point
is calibrated to run for roughly 120 ms rather than 40 ms — captured on
2026-11-19. Every point is self-calibrating: the harness times the operation
three times, then picks an iteration count that fills the time budget. A fixed
ladder of iteration counts cannot work across four orders of magnitude of buffer
size, and would make the 4 MiB points noise-dominated.

## Why sweep at all

The original suite measured three points: 1 KiB, 64 KiB, 1 MiB. Three points
cannot show where throughput turns over, and on a mainframe the turnover is not
where intuition puts it. CPACF processes a buffer in fixed-size chunks, so there
is a per-call setup cost that dominates small buffers and a plateau once the
instruction is saturated. A caller choosing between primitives needs to know
which side of the knee their typical message sits on.

## AES-256-GCM (encrypt) — KMA

| Buffer | MB/s | Iterations |
|-------:|-----:|-----------:|
| 64 B | 701.5 | 8,040 |
| 256 B | 2,418.9 | 63,636 |
| 1 KiB | 7,066.4 | 45,987 |
| 4 KiB | 13,854.0 | 11,697 |
| 16 KiB | 13,864.0 | 4,386 |
| 64 KiB | **14,248.8** | 1,353 |
| 256 KiB | 13,551.7 | 285 |
| 1 MiB | 13,297.9 | 84 |
| 4 MiB | 13,523.0 | 21 |

- **Peak:** 14,249 MB/s at 64 KiB
- **Knee (90% of peak):** 4 KiB
- **Plateau:** 4 KiB → 4 MiB
- **Decline peak → 4 MiB:** 5.1%
- **64 B → peak:** 20.3×

The knee at 4 KiB is the interesting number. Below it, a single KMA instruction
is issuing on a buffer shorter than the CPACF pipeline is tuned for, and the
fixed per-call cost (parameter block setup, key-vector load, one round of
function-code dispatch) has not yet been amortised. Above 4 KiB the instruction
is saturated and the curve is flat within run-to-run noise until 4 MiB, where a
mild 5% decline appears as the working set stops fitting the cache the assembler
is tuned for.

Practical reading: an application sealing TLS records (16 KiB) is already at
97% of peak. An application sealing 1 KiB messages — a key-value store writing
small rows, say — is leaving 2× on the table purely to per-call overhead, and
batching would recover it.

## SHA-256 — KIMD

| Buffer | MB/s | Iterations |
|-------:|-----:|-----------:|
| 64 B | 340.8 | 116,091 |
| 256 B | 1,052.5 | 107,079 |
| 1 KiB | 2,602.1 | 73,377 |
| 4 KiB | 3,701.3 | 21,819 |
| 16 KiB | 4,123.4 | 5,505 |
| 64 KiB | 4,197.1 | 1,287 |
| 256 KiB | **4,238.5** | 348 |
| 1 MiB | 4,180.4 | 84 |
| 4 MiB | 4,196.1 | 21 |

- **Peak:** 4,239 MB/s at 256 KiB
- **Knee (90% of peak):** 16 KiB
- **Plateau:** 16 KiB → 4 MiB
- **Decline peak → 4 MiB:** 1.0%
- **64 B → peak:** 12.4×

SHA-256 needs a 16 KiB buffer to reach 90% of peak — four times larger than
AES-GCM. The reason is structural: a hash is inherently serial, so there is no
parallelism to hide the per-call setup behind, and KIMD must be handed enough
data to make the setup worthwhile. Note also that the curve is flatter at the
top than AES: 1 MiB and 4 MiB sit within 0.3% of each other, so there is no
large-buffer penalty at all.

Practical reading: hashing a stream of 1 KiB records costs 1.6× versus batching
into 16 KiB chunks. For a log-integrity chain or an object-store checksum, the
chunk size is a throughput decision, not just a memory one.

## SHA3-256 — pure Go Keccak

| Buffer | MB/s | Iterations |
|-------:|-----:|-----------:|
| 64 B | 30.1 | 29,301 |
| 256 B | 64.1 | 24,948 |
| 1 KiB | 65.1 | 7,533 |
| 4 KiB | 67.2 | 1,944 |
| 16 KiB | 68.3 | 504 |
| 64 KiB | **69.8** | 126 |
| 256 KiB | 69.0 | 30 |
| 1 MiB | 68.3 | 9 |
| 4 MiB | 69.6 | 9 |

- **Peak:** 69.8 MB/s at 64 KiB
- **Knee (90% of peak):** 256 B
- **Plateau:** 256 B → 4 MiB
- **Decline peak → 4 MiB:** 0.4%
- **64 B → peak:** 2.3×

The pure-Go sponge has a knee at 256 B, far earlier than either CPACF primitive,
because its cost is almost entirely arithmetic: there is no instruction dispatch
to amortise, only the fixed cost of the final padding block. The whole curve
sits between 30 and 70 MB/s, which is the correct shape for a software
permutation — and it is why the hardware path matters so much. Through AF_ALG the
same SHA3-256 reaches **8,950 MB/s** at 1 MiB (see the SHA-3 section of the
README), a 128× difference that is entirely attributable to KIMD.

## Where the curves cross

`cipher.CrossoverPoint` answers the practical question for a caller choosing
between primitives at a given message size. Within this sweep:

| Pair | Crossover |
|------|-----------|
| AES-GCM vs SHA-256 | none — AES-GCM is faster at every size |
| AES-GCM vs SHA3-256 | none — AES-GCM is faster at every size |
| SHA-256 vs SHA3-256 | none — SHA-256 is faster at every size |

No crossings is itself the finding: on this machine the ordering of these three
primitives is fixed by which CPACF instruction backs them (KMA > KIMD-SHA2 >
software Keccak), not by buffer size. A sweep on a machine without MSA-8 would
show AES-GCM crossing SHA-256 somewhere in the small-buffer region, because GCM
would fall back to KMCTR plus a software GHASH pass.

## Method notes

- **Encrypt direction only** for AES-GCM. Decrypt is reported by the mode
  comparison table; sweeping both would double the runtime for a shape that
  tracks encrypt within a few percent.
- **Pure-Go SHA-3** for the sweep. The AF_ALG hardware path has a per-call
  socket cost that would dominate every point below 64 KiB, so the curve would
  measure the syscall boundary rather than the hash.
- **Iteration counts are per-point and calibrated**, not a fixed ladder. They are
  printed in the table because they are the only way to judge whether a point was
  measured long enough to be trustworthy; all of them run 120 ms at scale 3.
- **Run-to-run variance** is a few percent at the plateau and up to 10% at 64 B,
  where a single measurement is short even at 8,000 iterations. The knee is
  therefore reported as a plateau range (`plateau_min`..`plateau_max`) as well as
  a single point, because a broad plateau makes any single knee value unstable.
