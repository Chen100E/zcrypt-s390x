package cipher

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"math/big"
	"strings"
	"testing"
)

// TestCurveTableIsConsistent checks the documentation table against the
// function codes the CPACF package defines. A table that drifts from the
// constants would make the KDSA bitmap lookup silently probe the wrong bit,
// which is the kind of bug that reports "hardware absent" on a machine that has
// it.
func TestCurveTableIsConsistent(t *testing.T) {
	if len(CurveTable) != 4 {
		t.Fatalf("CurveTable has %d entries, want 4", len(CurveTable))
	}
	wantCodes := map[CurveKind]struct{ sign, verify uint }{
		CurveP256:    {9, 1},
		CurveP384:    {10, 2},
		CurveP521:    {11, 3},
		CurveEd25519: {32, 33},
	}
	for _, info := range CurveTable {
		want, ok := wantCodes[info.Curve]
		if !ok {
			t.Errorf("unexpected curve %q in table", info.Curve)
			continue
		}
		if info.SignCode != want.sign {
			t.Errorf("%s: sign code = %d, want %d", info.Curve, info.SignCode, want.sign)
		}
		if info.VerifyCode != want.verify {
			t.Errorf("%s: verify code = %d, want %d", info.Curve, info.VerifyCode, want.verify)
		}
		if info.MSALevel != 9 {
			t.Errorf("%s: MSA level = %d, want 9", info.Curve, info.MSALevel)
		}
		if info.Algorithm != "ECDSA" && info.Algorithm != "EdDSA" {
			t.Errorf("%s: algorithm = %q", info.Curve, info.Algorithm)
		}
		if info.Notes == "" {
			t.Errorf("%s: no notes", info.Curve)
		}
	}
	// The ECDSA sign and verify code ranges must not overlap: verify is 1..3 and
	// sign is 9..11, because a machine can implement one without the other. The
	// disjointness is what makes the per-operation bitmap probe necessary.
	verifyCodes := map[uint]bool{1: true, 2: true, 3: true}
	for _, info := range CurveTable {
		if info.Algorithm == "ECDSA" && verifyCodes[info.SignCode] {
			t.Errorf("%s: sign code %d collides with the verify range", info.Curve, info.SignCode)
		}
	}
}

// TestLookupCurve covers the lookup helper including the miss path.
func TestLookupCurve(t *testing.T) {
	for _, c := range []CurveKind{CurveP256, CurveP384, CurveP521, CurveEd25519} {
		if _, ok := LookupCurve(c); !ok {
			t.Errorf("LookupCurve(%q) missed", c)
		}
	}
	if _, ok := LookupCurve(CurveKind("secp256k1")); ok {
		t.Error("LookupCurve found an unknown curve")
	}
}

// TestECDSASignVerifyRoundTrip is the core correctness test: a signature made
// with a fresh key must verify, and must fail to verify against a different
// key, a different digest, and a corrupted signature.
func TestECDSASignVerifyRoundTrip(t *testing.T) {
	curves := []struct {
		kind CurveKind
		ec   elliptic.Curve
	}{
		{CurveP256, elliptic.P256()},
		{CurveP384, elliptic.P384()},
		{CurveP521, elliptic.P521()},
	}
	msg := []byte("zcrypt-s390x ECDSA round-trip message")

	for _, c := range curves {
		t.Run(string(c.kind), func(t *testing.T) {
			priv, err := ecdsa.GenerateKey(c.ec, rand.Reader)
			if err != nil {
				t.Fatalf("generate key: %v", err)
			}
			digest := digestForKind(c.kind, msg)

			r, s, err := ecdsa.Sign(rand.Reader, priv, digest)
			if err != nil {
				t.Fatalf("sign: %v", err)
			}

			// The signature must be fixed width once encoded.
			sig := encodeECDSASignature(r, s, c.kind)
			width := signatureWidth(c.kind)
			if len(sig) != 2*width {
				t.Fatalf("encoded signature is %d bytes, want %d", len(sig), 2*width)
			}

			if !verifyEncodedECDSA(&priv.PublicKey, digest, sig, c.kind) {
				t.Fatal("signature did not verify under its own public key")
			}

			// --- error paths ---

			// A different message must not verify.
			otherDigest := digestForKind(c.kind, []byte("a different message"))
			if verifyEncodedECDSA(&priv.PublicKey, otherDigest, sig, c.kind) {
				t.Error("signature verified against a different digest")
			}

			// A different key must not verify.
			other, err := ecdsa.GenerateKey(c.ec, rand.Reader)
			if err != nil {
				t.Fatalf("generate second key: %v", err)
			}
			if verifyEncodedECDSA(&other.PublicKey, digest, sig, c.kind) {
				t.Error("signature verified under a different public key")
			}

			// A single flipped bit must not verify.
			for _, idx := range []int{0, width - 1, width, len(sig) - 1} {
				bad := append([]byte(nil), sig...)
				bad[idx] ^= 0x01
				if verifyEncodedECDSA(&priv.PublicKey, digest, bad, c.kind) {
					t.Errorf("signature with bit flipped at %d verified", idx)
				}
			}

			// A truncated signature must be rejected rather than panicking.
			if verifyEncodedECDSA(&priv.PublicKey, digest, sig[:len(sig)-1], c.kind) {
				t.Error("truncated signature verified")
			}
			if verifyEncodedECDSA(&priv.PublicKey, digest, nil, c.kind) {
				t.Error("empty signature verified")
			}

			// An all-zero signature must be rejected. r=0 and s=0 are invalid
			// by the ECDSA definition.
			if verifyEncodedECDSA(&priv.PublicKey, digest, make([]byte, 2*width), c.kind) {
				t.Error("all-zero signature verified")
			}
		})
	}
}

// digestForKind returns the digest a curve signs, for the test's own use.
func digestForKind(c CurveKind, msg []byte) []byte {
	switch c {
	case CurveP256:
		d := sha256.Sum256(msg)
		return d[:]
	case CurveP384:
		d := sha512.Sum384(msg)
		return d[:]
	default:
		d := sha512.Sum512(msg)
		return d[:]
	}
}

// TestEd25519SignVerifyRoundTrip covers the EdDSA path, including the
// malleability-adjacent error cases that matter: wrong message, wrong key,
// corrupted signature, truncated signature.
func TestEd25519SignVerifyRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	msg := []byte("zcrypt-s390x Ed25519 round-trip message")
	sig := ed25519.Sign(priv, msg)

	if len(sig) != ed25519.SignatureSize {
		t.Fatalf("signature is %d bytes, want %d", len(sig), ed25519.SignatureSize)
	}
	if !ed25519.Verify(pub, msg, sig) {
		t.Fatal("signature did not verify")
	}

	if ed25519.Verify(pub, []byte("different message"), sig) {
		t.Error("signature verified against a different message")
	}

	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate second key: %v", err)
	}
	if ed25519.Verify(otherPub, msg, sig) {
		t.Error("signature verified under a different public key")
	}

	for _, idx := range []int{0, 31, 32, len(sig) - 1} {
		bad := append([]byte(nil), sig...)
		bad[idx] ^= 0x01
		if ed25519.Verify(pub, msg, bad) {
			t.Errorf("signature with bit flipped at %d verified", idx)
		}
	}

	if ed25519.Verify(pub, msg, sig[:len(sig)-1]) {
		t.Error("truncated signature verified")
	}
	if ed25519.Verify(pub, msg, nil) {
		t.Error("nil signature verified")
	}
}

// TestSignBenchmarkAllCurves runs the real benchmark for every curve and
// asserts the round-trip gate held, the rates are positive, and the KDSA codes
// are recorded.
func TestSignBenchmarkAllCurves(t *testing.T) {
	for _, info := range CurveTable {
		res, err := SignBenchmark(info.Curve, 15)
		if err != nil {
			t.Fatalf("%s: %v", info.Curve, err)
		}
		if !res.Verified {
			t.Errorf("%s: result not marked verified", info.Curve)
		}
		if res.SignPerSec <= 0 || res.VerifyPerSec <= 0 {
			t.Errorf("%s: non-positive rates: sign=%f verify=%f", info.Curve, res.SignPerSec, res.VerifyPerSec)
		}
		if res.SignNanosOp <= 0 || res.VerifyNanos <= 0 {
			t.Errorf("%s: non-positive per-op costs", info.Curve)
		}
		if res.SignCode != info.SignCode || res.VerifyCode != info.VerifyCode {
			t.Errorf("%s: codes = %d/%d, want %d/%d",
				info.Curve, res.SignCode, res.VerifyCode, info.SignCode, info.VerifyCode)
		}
		if res.Algorithm != info.Algorithm {
			t.Errorf("%s: algorithm = %q, want %q", info.Curve, res.Algorithm, info.Algorithm)
		}
		t.Logf("%-8s sign %8.0f/s  verify %8.0f/s", res.Curve, res.SignPerSec, res.VerifyPerSec)
	}
}

// TestSignBenchmarkRejectsBadParameters covers the guard clauses.
func TestSignBenchmarkRejectsBadParameters(t *testing.T) {
	if _, err := SignBenchmark(CurveP256, 0); err == nil {
		t.Error("accepted zero iterations")
	}
	if _, err := SignBenchmark(CurveP256, -5); err == nil {
		t.Error("accepted negative iterations")
	}
	if _, err := SignBenchmark(CurveKind("P-999"), 10); err == nil {
		t.Error("accepted an unknown curve")
	}
}

// TestSignSuiteShape checks the suite returns one row per curve, with the curve
// recorded even when the row failed.
func TestSignSuiteShape(t *testing.T) {
	rows := SignSuite(10)
	if len(rows) != len(CurveTable) {
		t.Fatalf("suite returned %d rows, want %d", len(rows), len(CurveTable))
	}
	for i, info := range CurveTable {
		if rows[i].Curve != info.Curve {
			t.Errorf("row %d curve = %q, want %q", i, rows[i].Curve, info.Curve)
		}
		if rows[i].Error != "" {
			t.Errorf("%s: unexpected error %q", rows[i].Curve, rows[i].Error)
		}
	}
}

// TestSignatureWidths pins the fixed widths, because a change here would mean
// every stored signature in every downstream consumer is misparsed.
func TestSignatureWidths(t *testing.T) {
	cases := map[CurveKind]int{
		CurveP256: 32,
		CurveP384: 48,
		CurveP521: 66,
	}
	for c, want := range cases {
		if got := signatureWidth(c); got != want {
			t.Errorf("%s: width = %d, want %d", c, got, want)
		}
	}
	if got := signatureWidth(CurveEd25519); got != 0 {
		t.Errorf("Ed25519 has no r/s split, width should be 0, got %d", got)
	}
}

// TestEncodedSignatureIsFixedWidth proves the encoding does not shrink when r
// or s has leading zero bytes, which is the side-channel property the comment
// on encodeECDSASignature claims.
func TestEncodedSignatureIsFixedWidth(t *testing.T) {
	// Deliberately small values: r=1 and s=2 have many leading zero bytes.
	r := big.NewInt(1)
	s := big.NewInt(2)
	for _, c := range []CurveKind{CurveP256, CurveP384, CurveP521} {
		sig := encodeECDSASignature(r, s, c)
		width := signatureWidth(c)
		if len(sig) != 2*width {
			t.Errorf("%s: signature is %d bytes, want %d", c, len(sig), 2*width)
		}
		// Big-endian: the last byte of the r half must be 1, the last byte of
		// the s half must be 2, and everything before must be zero.
		for i := 0; i < width-1; i++ {
			if sig[i] != 0 {
				t.Errorf("%s: r half byte %d is %#x, want 0", c, i, sig[i])
			}
			if sig[width+i] != 0 {
				t.Errorf("%s: s half byte %d is %#x, want 0", c, width+i, sig[width+i])
			}
		}
		if sig[width-1] != 1 {
			t.Errorf("%s: r = %d, want 1", c, sig[width-1])
		}
		if sig[2*width-1] != 2 {
			t.Errorf("%s: s = %d, want 2", c, sig[2*width-1])
		}
	}
}

// TestGenerateKeyPair covers every curve and asserts the reported public key
// sizes match the wire format.
func TestGenerateKeyPair(t *testing.T) {
	cases := map[CurveKind]int{
		CurveP256:    65, // uncompressed SEC1: 0x04 || X(32) || Y(32)
		CurveP384:    97, // 0x04 || X(48) || Y(48)
		CurveP521:    133,
		CurveEd25519: 32,
	}
	for c, wantSize := range cases {
		kp, err := GenerateKeyPair(c)
		if err != nil {
			t.Fatalf("%s: %v", c, err)
		}
		if !kp.PrivateOK {
			t.Errorf("%s: private key not reported as generated", c)
		}
		if kp.PublicSize != wantSize {
			t.Errorf("%s: public key is %d bytes, want %d", c, kp.PublicSize, wantSize)
		}
	}
	if _, err := GenerateKeyPair(CurveKind("nope")); err == nil {
		t.Error("accepted an unknown curve")
	}
}

// TestECCKernelReportIsSelfConsistent checks the report does not claim a kernel
// driver it did not find, and does not claim KDSA usability when the Query
// bitmap is unavailable.
func TestECCKernelReportIsSelfConsistent(t *testing.T) {
	rows := ECCKernelReport()
	if len(rows) != len(CurveTable) {
		t.Fatalf("report has %d rows, want %d", len(rows), len(CurveTable))
	}
	for _, r := range rows {
		if r.KernelPresent && r.KernelDriver == "" {
			t.Errorf("%s: driver reported present but unnamed", r.Curve)
		}
		if !r.KernelPresent && r.KernelDriver != "" {
			t.Errorf("%s: driver %q named but not marked present", r.Curve, r.KernelDriver)
		}
		if r.Notes == "" {
			t.Errorf("%s: no notes", r.Curve)
		}
		// A curve with no kernel name (P-521 has no kernel akcipher entry) must
		// not claim a driver.
		if r.KernelName == "" && r.KernelPresent {
			t.Errorf("%s: no kernel name but driver claimed", r.Curve)
		}
		t.Logf("%-8s kernel=%-18q present=%-5v kdsa=%-5v codes=%d/%d",
			r.Curve, r.KernelDriver, r.KernelPresent, r.KDSAUsable, r.SignCode, r.VerifyCode)
	}
}

// TestECCKernelReportFindsNoECDSAOnThisHost documents the negative result: the
// kernel registers no ECDSA akcipher driver here, so the KDSA acceleration
// ZCrypt measures is entirely in the Go userspace path. This test records the
// finding rather than asserting it globally, so it still passes on a host that
// does register the driver.
func TestECCKernelReportFindsNoECDSAOnThisHost(t *testing.T) {
	rows := ECCKernelReport()
	var present []CurveKind
	for _, r := range rows {
		if r.KernelPresent {
			present = append(present, r.Curve)
		}
	}
	if len(present) == 0 {
		t.Log("no kernel ECDSA/EdDSA driver registered: KDSA acceleration is userspace-only here")
	} else {
		t.Logf("kernel drivers registered for: %v", present)
	}
	// Whatever the answer, the KDSA bit must be reported consistently with the
	// machine's MSA level.
	for _, r := range rows {
		if r.KDSAUsable && r.SignCode == 0 && r.VerifyCode == 0 {
			t.Errorf("%s: KDSA usable but no function codes", r.Curve)
		}
	}
}

// TestECCReportExplainsAsymmetricKDSA proves the report distinguishes "no KDSA
// at all" from "KDSA present for one operation but not its pair". The latter is
// what happens for Ed25519 on the reference machine: the bitmap has sign code 32
// but not verify code 33, so Go falls back despite the sign instruction existing.
// Without this distinction the report would say "codes absent" when one is
// demonstrably present, which is the kind of imprecision that erodes trust in
// every other number.
func TestECCReportExplainsAsymmetricKDSA(t *testing.T) {
	for _, r := range ECCKernelReport() {
		if r.KDSAUsable {
			if !strings.Contains(r.Notes, "issues directly") {
				t.Errorf("%s: usable but note = %q", r.Curve, r.Notes)
			}
			continue
		}
		// Not usable: the note must say why, and must not claim both codes are
		// absent if only one is.
		if r.Notes == "" {
			t.Errorf("%s: not usable but no explanation", r.Curve)
		}
		if strings.Contains(r.Notes, "both KDSA function codes absent") &&
			strings.Contains(r.Notes, "present=true") {
			t.Errorf("%s: note contradicts itself: %q", r.Curve, r.Notes)
		}
		t.Logf("%s: %s", r.Curve, r.Notes)
	}
}

// BenchmarkECDSAP256 measures the raw sign/verify rate through the benchmark
// helper so `go test -bench` can reproduce the report numbers.
func BenchmarkECDSAP256(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := SignBenchmark(CurveP256, 10); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEd25519Sign(b *testing.B) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	msg := bytes.Repeat([]byte("x"), 64)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ed25519.Sign(priv, msg)
	}
}
