package cipher

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestGHASHNISTVectors is the correctness gate for the standalone primitive.
func TestGHASHNISTVectors(t *testing.T) {
	passed, err := VerifyGHASHVectors()
	if err != nil {
		t.Fatalf("GHASH known-answer vectors failed: %v", err)
	}
	if want := len(NISTGHASHVectors); passed != want {
		t.Fatalf("passed = %d, want %d", passed, want)
	}
	t.Logf("%d/%d standalone GHASH vectors bit-exact", passed, len(NISTGHASHVectors))
}

// TestGHASHVectorShape validates the vectors themselves so a mistyped hex
// constant fails as a data error rather than looking like a broken multiply.
func TestGHASHVectorShape(t *testing.T) {
	for _, v := range NISTGHASHVectors {
		h, err := hex.DecodeString(v.H)
		if err != nil {
			t.Errorf("%s: bad H hex: %v", v.Name, err)
			continue
		}
		if len(h) != ghashBlockSize {
			t.Errorf("%s: H is %d bytes, want %d", v.Name, len(h), ghashBlockSize)
		}
		sum, err := hex.DecodeString(v.Sum)
		if err != nil {
			t.Errorf("%s: bad Sum hex: %v", v.Name, err)
			continue
		}
		if len(sum) != ghashBlockSize {
			t.Errorf("%s: Sum is %d bytes, want %d", v.Name, len(sum), ghashBlockSize)
		}
	}
}

// TestGHASHMultiplyAlgebra checks the field multiply directly, on raw 16-byte
// messages rather than through the GCM length block.
//
// GHASH_H(M) for a single block M is M * H, so hashing H itself yields H^2 and
// hashing two copies of H yields (H^2 xor H) * H. Both expected values come from
// the kernel's ghash-s390 driver and were reproduced by the independent Python
// reference. They are the sharpest available test of the reduction step: an
// implementation with the wrong polynomial still gets the first product right
// (it is a single shift-and-xor with no reduction) and gets these wrong.
func TestGHASHMultiplyAlgebra(t *testing.T) {
	cases := []struct {
		name string
		h    string
		msg  string
		want string
	}{
		{
			name: "H1-squared",
			h:    "acbef20579b4b8ebce889bac8732dad7",
			msg:  "acbef20579b4b8ebce889bac8732dad7",
			want: "db9f3b4948607beb8bb753ba40ab627b",
		},
		{
			name: "H0-squared",
			h:    "dc95c078a2408989ad48a21492842087",
			msg:  "dc95c078a2408989ad48a21492842087",
			want: "c7c27e834f1e393c2a82d138ce9261b7",
		},
		{
			name: "H1-twice",
			h:    "acbef20579b4b8ebce889bac8732dad7",
			msg:  "acbef20579b4b8ebce889bac8732dad7acbef20579b4b8ebce889bac8732dad7",
			want: "7d170f6a1403acc0ad612b82ed5ade72",
		},
	}
	for _, c := range cases {
		h, err := hex.DecodeString(c.h)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		msg, err := hex.DecodeString(c.msg)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		got := hex.EncodeToString(GHASHSum(h, msg))
		if got != c.want {
			t.Errorf("%s: got %s want %s", c.name, got, c.want)
		}
	}
}

// TestGHASHMessageLengthBlock pins the GHASH input construction byte for byte.
//
// The length block is the part of GCM most likely to be wrong and least likely
// to be noticed, so it gets its own assertion rather than only being exercised
// through a tag comparison. The expected bytes spell out both facts that are
// easy to get backwards: the lengths are in BITS, and they are big-endian.
func TestGHASHMessageLengthBlock(t *testing.T) {
	cases := []struct {
		name    string
		aadLen  int
		ctLen   int
		wantHex string
	}{
		{"empty", 0, 0, "00000000000000000000000000000000"},
		{"aad-only-20B", 20, 0, "00000000000000a00000000000000000"},
		{"ct-only-16B", 0, 16, "00000000000000000000000000000080"},
		{"aad-20B-ct-60B", 20, 60, "00000000000000a000000000000001e0"},
	}
	for _, c := range cases {
		aad := make([]byte, c.aadLen)
		ct := make([]byte, c.ctLen)
		msg := GHASHMessage(aad, ct)
		if len(msg)%ghashBlockSize != 0 {
			t.Errorf("%s: message length %d is not a multiple of %d", c.name, len(msg), ghashBlockSize)
		}
		if len(msg) < 16 {
			t.Errorf("%s: message too short to carry a length block", c.name)
			continue
		}
		got := hex.EncodeToString(msg[len(msg)-16:])
		if got != c.wantHex {
			t.Errorf("%s: length block = %s, want %s", c.name, got, c.wantHex)
		}
	}
}

// TestGHASHMessagePadding checks that both fields are padded independently: a
// 5-byte AAD must occupy a whole 16-byte block before the ciphertext starts.
func TestGHASHMessagePadding(t *testing.T) {
	aad := []byte{1, 2, 3, 4, 5}
	ct := []byte{6, 7, 8}
	msg := GHASHMessage(aad, ct)

	wantLen := 16 + 16 + 16
	if len(msg) != wantLen {
		t.Fatalf("len(GHASHMessage) = %d, want %d", len(msg), wantLen)
	}
	for i := 5; i < 16; i++ {
		if msg[i] != 0 {
			t.Fatalf("AAD padding byte %d = %#x, want 0", i, msg[i])
		}
	}
	if msg[16] != 6 || msg[17] != 7 || msg[18] != 8 {
		t.Fatalf("ciphertext not at offset 16: % x", msg[16:19])
	}
	for i := 19; i < 32; i++ {
		if msg[i] != 0 {
			t.Fatalf("ct padding byte %d = %#x, want 0", i, msg[i])
		}
	}
}

// TestGHASHStreamingMatchesOneShot proves the buffering logic: writing a message
// in arbitrary chunks must give the same answer as one Write.
//
// Every chunk boundary from 0 to len is walked, which is what catches an
// off-by-one in the partial-block top-up that a few spot checks would miss.
func TestGHASHStreamingMatchesOneShot(t *testing.T) {
	h, err := hex.DecodeString("acbef20579b4b8ebce889bac8732dad7")
	if err != nil {
		t.Fatal(err)
	}
	msg := make([]byte, 67)
	for i := range msg {
		msg[i] = byte(i*13 + 7)
	}
	want := GHASHSum(h, msg)

	for split := 0; split <= len(msg); split++ {
		g, err := NewGHASH(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := g.Write(msg[:split]); err != nil {
			t.Fatalf("split %d: write: %v", split, err)
		}
		if _, err := g.Write(msg[split:]); err != nil {
			t.Fatalf("split %d: write: %v", split, err)
		}
		if got := g.Sum(); !bytes.Equal(got, want) {
			t.Fatalf("split %d: got %s want %s", split, hex.EncodeToString(got), hex.EncodeToString(want))
		}
	}
}

// TestGHASHStreamingByteAtATime is the worst case for the buffering path: one
// byte per Write, so every block is assembled across sixteen calls.
func TestGHASHStreamingByteAtATime(t *testing.T) {
	h, _ := hex.DecodeString("dc95c078a2408989ad48a21492842087")
	msg := make([]byte, 40)
	for i := range msg {
		msg[i] = byte(i)
	}
	want := GHASHSum(h, msg)

	g, err := NewGHASH(h)
	if err != nil {
		t.Fatal(err)
	}
	for i := range msg {
		if _, err := g.Write(msg[i : i+1]); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	if got := g.Sum(); !bytes.Equal(got, want) {
		t.Fatalf("got %s want %s", hex.EncodeToString(got), hex.EncodeToString(want))
	}
}

// TestGHASHSumIsIdempotent checks that Sum does not consume the state: calling
// it twice must give the same answer, and a Write after Sum must extend the
// message rather than start a new one.
func TestGHASHSumIsIdempotent(t *testing.T) {
	h, _ := hex.DecodeString("acbef20579b4b8ebce889bac8732dad7")
	g, err := NewGHASH(h)
	if err != nil {
		t.Fatal(err)
	}
	head := []byte("abcdefghijklmnopq") // 17 bytes: one full block plus one
	if _, err := g.Write(head); err != nil {
		t.Fatal(err)
	}
	first := g.Sum()
	second := g.Sum()
	if !bytes.Equal(first, second) {
		t.Fatalf("Sum is not idempotent: %s then %s",
			hex.EncodeToString(first), hex.EncodeToString(second))
	}

	tail := []byte("rstuvwxyz")
	if _, err := g.Write(tail); err != nil {
		t.Fatal(err)
	}
	want := GHASHSum(h, append(append([]byte(nil), head...), tail...))
	if got := g.Sum(); !bytes.Equal(got, want) {
		t.Fatalf("after continuation: got %s want %s", hex.EncodeToString(got), hex.EncodeToString(want))
	}
}

// TestGHASHReset checks that Reset returns the instance to the empty-message
// state, which must hash to zero regardless of H.
func TestGHASHReset(t *testing.T) {
	h, _ := hex.DecodeString("acbef20579b4b8ebce889bac8732dad7")
	g, err := NewGHASH(h)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.Write([]byte("something")); err != nil {
		t.Fatal(err)
	}
	g.Reset()
	if got := g.Sum(); !bytes.Equal(got, make([]byte, ghashBlockSize)) {
		t.Fatalf("after Reset: got %s want all zero", hex.EncodeToString(got))
	}
}

// TestGHASHSizeAndBlockSize pins the hash-like parameters.
func TestGHASHSizeAndBlockSize(t *testing.T) {
	h, _ := hex.DecodeString("dc95c078a2408989ad48a21492842087")
	g, err := NewGHASH(h)
	if err != nil {
		t.Fatal(err)
	}
	if g.Size() != 16 {
		t.Errorf("Size() = %d, want 16", g.Size())
	}
	if g.BlockSize() != 16 {
		t.Errorf("BlockSize() = %d, want 16", g.BlockSize())
	}
	if n := len(g.Sum()); n != 16 {
		t.Errorf("len(Sum()) = %d, want 16", n)
	}
}

// TestGHASHBadKeyLength checks the constructor rejects H of the wrong size
// rather than silently truncating or zero-extending it.
func TestGHASHBadKeyLength(t *testing.T) {
	for _, n := range []int{0, 8, 15, 17, 32} {
		if _, err := NewGHASH(make([]byte, n)); err == nil {
			t.Errorf("NewGHASH(%d bytes) accepted, want error", n)
		}
	}
	if GHASHSum(make([]byte, 15), []byte("x")) != nil {
		t.Error("GHASHSum with a 15-byte H should return nil")
	}
}

// TestGHASHZeroSubkey checks the degenerate case H = 0, where every product is
// zero and the hash must collapse to all zeros. This is not a valid key in
// practice (H = 0 is a GCM misuse) but it is the sharpest test that the
// multiply's accumulate step is not leaking in something else.
func TestGHASHZeroSubkey(t *testing.T) {
	h := make([]byte, ghashBlockSize)
	got := GHASHSum(h, GHASHMessage([]byte("aad"), []byte("ciphertext")))
	if !bytes.Equal(got, make([]byte, ghashBlockSize)) {
		t.Fatalf("H=0: got %s want all zero", hex.EncodeToString(got))
	}
}

// TestGHASHHardwareVerify exercises the AF_ALG ghash path against the pure-Go
// reference. It skips when the kernel has no reachable ghash, which is the case
// on amd64 CI runners that have no CPACF and may have no ghash at all.
func TestGHASHHardwareVerify(t *testing.T) {
	h, err := hex.DecodeString("acbef20579b4b8ebce889bac8732dad7")
	if err != nil {
		t.Fatal(err)
	}
	aad, _ := hex.DecodeString("feedfacedeadbeeffeedfacedeadbeefabaddad2")
	ct, _ := hex.DecodeString("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f66276fc6ece0f4e1768cddf8853bb2d551b")

	ok, err := GHASHHardwareVerifyGCM(aad, ct, h)
	if err != nil {
		t.Skipf("AF_ALG ghash unavailable: %v", err)
	}
	if !ok {
		t.Fatal("hardware and software GHASH disagree")
	}
	t.Log("ghash-s390 and the pure-Go reference agree on the 20B-AAD/60B-CT case")
}

// TestGHASHHardwareVerifyManyLengths compares the two paths over every message
// length from 0 to 5 blocks plus a partial, because the kernel's zero-padding of
// a trailing partial block is the one behaviour the two implementations have to
// agree on by construction rather than by definition.
func TestGHASHHardwareVerifyManyLengths(t *testing.T) {
	h, _ := hex.DecodeString("dc95c078a2408989ad48a21492842087")

	// Probe once so an unavailable kernel skips the whole test instead of
	// failing on the first case.
	if err := probeAFALGGHash(h); err != nil {
		t.Skipf("AF_ALG ghash unavailable: %v", err)
	}

	for n := 0; n <= 5*ghashBlockSize+7; n++ {
		msg := make([]byte, n)
		for i := range msg {
			msg[i] = byte(i*17 + 3)
		}
		soft := GHASHSum(h, msg)
		hard, err := GHASHHardwareSum(h, msg)
		if err != nil {
			t.Fatalf("len %d: hardware: %v", n, err)
		}
		if !bytes.Equal(soft, hard) {
			t.Fatalf("len %d: soft %s hard %s", n,
				hex.EncodeToString(soft), hex.EncodeToString(hard))
		}
	}
}

// TestGHASHHardwareMatchesVectors runs every standalone vector through AF_ALG as
// well, so the vectors prove both implementations rather than only the software
// one.
func TestGHASHHardwareMatchesVectors(t *testing.T) {
	if err := probeAFALGGHash(make([]byte, ghashBlockSize)); err != nil {
		t.Skipf("AF_ALG ghash unavailable: %v", err)
	}

	for _, v := range NISTGHASHVectors {
		h, _ := hex.DecodeString(v.H)
		aad, _ := hex.DecodeString(v.AAD)
		ct, _ := hex.DecodeString(v.CT)
		got, err := GHASHHardwareSum(h, GHASHMessage(aad, ct))
		if err != nil {
			t.Fatalf("%s: %v", v.Name, err)
		}
		if hex.EncodeToString(got) != v.Sum {
			t.Errorf("%s: hardware got %s want %s", v.Name, hex.EncodeToString(got), v.Sum)
		}
	}
}

// TestGHASHKernelInfo reports what the kernel registered, and skips the
// hardware assertions when there is no CPACF driver. The informational part runs
// everywhere so the test output always says which driver was seen.
func TestGHASHKernelInfo(t *testing.T) {
	info := GHASHKernelInfo()
	if info.KernelDriver == "" {
		t.Skipf("no ghash driver registered: %s", info.Error)
	}
	t.Logf("ghash driver=%s priority=%d hardware=%v af_alg=%v",
		info.KernelDriver, info.KernelPriority, info.Hardware, info.AFALGAvailable)
	if info.Hardware && !info.AFALGAvailable {
		t.Errorf("hardware driver %s is registered but AF_ALG cannot reach it: %s",
			info.KernelDriver, info.Error)
	}
}

// TestGHASHSoftwareBenchmark checks the benchmark returns a plausible figure and
// the same sum the reference produces, so a report never shows throughput for a
// computation that was not actually performed.
func TestGHASHSoftwareBenchmark(t *testing.T) {
	h, _ := hex.DecodeString("acbef20579b4b8ebce889bac8732dad7")
	res, err := GHASHSoftwareBenchmark(h, 1024, 50)
	if err != nil {
		t.Fatalf("benchmark: %v", err)
	}
	if res.MBps <= 0 {
		t.Errorf("MBps = %v, want > 0", res.MBps)
	}
	if res.Backend != "pure-go" {
		t.Errorf("Backend = %q, want pure-go", res.Backend)
	}
	data := ghashBenchData(1024)
	if want := hexEncode(GHASHSum(h, data)); res.Sum != want {
		t.Errorf("Sum = %s, want %s", res.Sum, want)
	}
}

// TestGHASHBenchmarkSumsAgree checks that both benchmarks hash the same bytes,
// so the Sum in a report's software row and hardware row are comparable. Without
// a shared buffer the two rows would each be self-consistent and jointly
// meaningless.
func TestGHASHBenchmarkSumsAgree(t *testing.T) {
	h, _ := hex.DecodeString("acbef20579b4b8ebce889bac8732dad7")
	soft, err := GHASHSoftwareBenchmark(h, 1024, 2)
	if err != nil {
		t.Fatalf("software: %v", err)
	}
	hard, err := GHASHHardwareBenchmark(h, 1024, 2)
	if err != nil {
		t.Skipf("AF_ALG ghash unavailable: %v", err)
	}
	if soft.Sum != hard.Sum {
		t.Fatalf("benchmarks hashed different data: software %s hardware %s", soft.Sum, hard.Sum)
	}
}

// TestGHASHHardwareBenchmark measures the AF_ALG path, skipping when unavailable.
func TestGHASHHardwareBenchmark(t *testing.T) {
	h, _ := hex.DecodeString("acbef20579b4b8ebce889bac8732dad7")
	res, err := GHASHHardwareBenchmark(h, 1024, 50)
	if err != nil {
		t.Skipf("AF_ALG ghash unavailable: %v", err)
	}
	if res.MBps <= 0 {
		t.Errorf("MBps = %v, want > 0", res.MBps)
	}
	if res.Backend != "af_alg" {
		t.Errorf("Backend = %q, want af_alg", res.Backend)
	}
	t.Logf("AF_ALG ghash %.1f MB/s at %d-byte messages", res.MBps, 1024)
}
