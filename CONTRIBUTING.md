# Contributing to ZCrypt-s390x

Thanks for helping improve hardware cryptography support for Linux on IBM Z and
LinuxONE.

## Development Workflow

1. **Fork and clone**

   ```bash
   git clone https://github.com/<you>/zcrypt-s390x.git
   cd zcrypt-s390x
   ```

2. **Install Go 1.22+**

   On s390x, if your distro does not package a recent Go:

   ```bash
   curl -fsSL https://go.dev/dl/go1.23.2.linux-s390x.tar.gz | sudo tar -C /opt -xz
   export PATH=/opt/go/bin:$PATH
   ```

3. **Run the gates before every commit**

   ```bash
   go build ./...
   go vet ./...
   go test ./...
   test -z "$(gofmt -l .)" || gofmt -w .
   ```

   CI enforces all four, so a red local run will be a red PR.

## What We Are Looking For

- **s390x-specific correctness.** Big-endian byte order and CPACF instruction
  paths are the point of this project. A change that works on amd64 but silently
  falls back to the portable path on s390x is a regression.
- **Test vectors, not round-trips.** A test that encrypts then decrypts proves
  nothing about byte order. Assert the exact expected bytes (NIST / SP 800-38A
  vectors are the reference).
- **Honest measurements.** Do not commit estimated throughput numbers. Every
  figure in the README must be reproducible with `./zcrypt` on real s390x
  hardware; say which machine type and MSA level it came from.
- **No third-party dependencies.** The module is standard-library only. If you
  believe a dependency is unavoidable, open an issue first and explain why the
  stdlib path is insufficient.

## Reporting Bugs

Please include:

- `./zcrypt --version` output
- Machine type and MSA level (`grep -E "machine|facilities" /proc/cpuinfo`)
- Kernel crypto backends (`grep -A3 "^name.*: aes" /proc/crypto`)
- The exact command and its output

## Commit Messages

Conventional Commits: `feat(cipher): ...`, `fix(cpacf): ...`, `test(codec): ...`,
`ci: ...`, `docs: ...`.

## License

By contributing you agree your work is licensed under the MIT License.
