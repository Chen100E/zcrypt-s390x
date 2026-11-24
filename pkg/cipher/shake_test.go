package cipher

import (
	"bytes"
	"encoding/hex"
	"io"
	"testing"
)

// TestSHAKENISTVectors is the correctness gate for the XOF: every FIPS 202
// known-answer case, including the 200-byte SHAKE128 case whose output length
// exceeds the 168-byte rate and therefore requires a second permutation during
// squeeze.
func TestSHAKENISTVectors(t *testing.T) {
	passed, err := VerifySHAKEVectors()
	if err != nil {
		t.Fatalf("SHAKE NIST vectors failed: %v", err)
	}
	if want := len(NISTSHAKEVectors); passed != want {
		t.Fatalf("passed = %d, want %d", passed, want)
	}
	t.Logf("%d/%d FIPS 202 SHAKE vectors bit-exact (128/256, incl. a 200-byte squeeze and 1M-byte messages)",
		passed, len(NISTSHAKEVectors))
}

// TestSHAKEVariantCoverage asserts both security levels have at least one
// vector, and that each level has one longer than its own sponge rate. A table
// whose every case fits in one block cannot detect a broken squeeze loop, and a
// case that only exceeds the rate of the wider XOF would leave the narrower one
// unproven.
func TestSHAKEVariantCoverage(t *testing.T) {
	seen := map[SHAKEVariant]int{}
	longerThanRate := map[SHAKEVariant]int{}
	for _, v := range NISTSHAKEVectors {
		seen[v.Variant]++
		if v.OutLen > v.Variant.rate() {
			longerThanRate[v.Variant]++
		}
	}
	for _, v := range []SHAKEVariant{SHAKE128, SHAKE256} {
		if seen[v] == 0 {
			t.Errorf("%s has no NIST vector", v)
		}
		if longerThanRate[v] == 0 {
			t.Errorf("%s has no vector with a squeeze longer than its %d-byte rate", v, v.rate())
		}
	}
}

// TestSHAKERateAndSize pins the sponge parameters against FIPS 202: the rate is
// 200 - 2*securityStrength bytes, and the conventional output length is twice
// the security strength.
func TestSHAKERateAndSize(t *testing.T) {
	cases := []struct {
		v      SHAKEVariant
		rate   int
		size   int
		streng int
		name   string
	}{
		{SHAKE128, 168, 32, 128, "SHAKE128"},
		{SHAKE256, 136, 64, 256, "SHAKE256"},
	}
	for _, c := range cases {
		if got := c.v.rate(); got != c.rate {
			t.Errorf("%s: rate = %d, want %d", c.name, got, c.rate)
		}
		if got := c.v.Size(); got != c.size {
			t.Errorf("%s: Size() = %d, want %d", c.name, got, c.size)
		}
		if got := c.v.SecurityStrength(); got != c.streng {
			t.Errorf("%s: SecurityStrength() = %d, want %d", c.name, got, c.streng)
		}
		if got := c.v.String(); got != c.name {
			t.Errorf("String() = %q, want %q", got, c.name)
		}
		s := NewSHAKE(c.v)
		if s.BlockSize() != c.rate {
			t.Errorf("%s: BlockSize() = %d, want %d", c.name, s.BlockSize(), c.rate)
		}
		if s.Size() != c.size {
			t.Errorf("%s: Size() = %d, want %d", c.name, s.Size(), c.size)
		}
		if s.Variant() != c.v {
			t.Errorf("%s: Variant() = %v, want %v", c.name, s.Variant(), c.v)
		}
	}
	if got := NewSHAKE128().BlockSize(); got != 168 {
		t.Errorf("NewSHAKE128().BlockSize() = %d, want 168", got)
	}
	if got := NewSHAKE256().BlockSize(); got != 136 {
		t.Errorf("NewSHAKE256().BlockSize() = %d, want 136", got)
	}
}

// TestSHAKEChunkedReadEqualsOneShot is the property that makes an XOF an XOF.
//
// Reading 200 bytes in one call, in two chunks of 32+168, and one byte at a time
// must all produce the same 200 bytes, and those bytes must be the first 200 of
// the unbounded stream. An implementation that re-pads or re-permutes between
// reads — or that forgets to permute when the rate is exhausted — passes the
// one-shot check and fails here.
func TestSHAKEChunkedReadEqualsOneShot(t *testing.T) {
	const total = 200

	// Chunkings that straddle the 168-byte SHAKE128 rate and the 136-byte
	// SHAKE256 rate in different places, plus awkward lane-misaligned sizes.
	chunkings := [][]int{
		{total},
		{32, 168},
		{168, 32},
		{1, 199},
		{7, 8, 9, 176},
		{136, 64},
		{135, 1, 64},
		{100, 100},
		{50, 50, 50, 50},
		{0, 200},
	}

	for _, v := range []SHAKEVariant{SHAKE128, SHAKE256} {
		msg := []byte("the quick brown fox jumps over the lazy dog")
		want := SHAKESum(v, msg, total)
		if len(want) != total {
			t.Fatalf("%s: one-shot length = %d, want %d", v, len(want), total)
		}

		for _, chunks := range chunkings {
			if sum(chunks) != total {
				t.Fatalf("%s: bad chunking %v sums to %d, want %d", v, chunks, sum(chunks), total)
			}
			s := NewSHAKE(v)
			if _, err := s.Write(msg); err != nil {
				t.Fatalf("%s: write: %v", v, err)
			}
			var got []byte
			for _, n := range chunks {
				buf := make([]byte, n)
				read, err := s.Read(buf)
				if err != nil {
					t.Fatalf("%s %v: read: %v", v, chunks, err)
				}
				if read != n {
					t.Fatalf("%s %v: Read returned %d, want %d", v, chunks, read, n)
				}
				got = append(got, buf...)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("%s chunked %v differs from one-shot\n got %s\nwant %s",
					v, chunks, hex.EncodeToString(got), hex.EncodeToString(want))
			}
		}
	}
}

// TestSHAKEChunkedReadOneByteAtATime walks the whole 2*rate output one byte per
// Read, which is the most hostile chunking for a squeeze state machine: every
// block boundary is crossed at the exact byte where the permutation is due.
func TestSHAKEChunkedReadOneByteAtATime(t *testing.T) {
	for _, v := range []SHAKEVariant{SHAKE128, SHAKE256} {
		total := 2 * v.rate()
		want := SHAKESum(v, []byte("abc"), total)

		s := NewSHAKE(v)
		if _, err := s.Write([]byte("abc")); err != nil {
			t.Fatalf("%s: write: %v", v, err)
		}
		got := make([]byte, 0, total)
		one := make([]byte, 1)
		for i := 0; i < total; i++ {
			if _, err := io.ReadFull(s, one); err != nil {
				t.Fatalf("%s: byte %d: %v", v, i, err)
			}
			got = append(got, one[0])
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s: byte-at-a-time output differs from one-shot at first mismatch\n got %s\nwant %s",
				v, hex.EncodeToString(got), hex.EncodeToString(want))
		}
	}
}

// TestSHAKEPrefixProperty is the defining property of an extendable-output
// function: a shorter output must be a prefix of a longer one. If it is not,
// the implementation is a truncated hash wearing a XOF interface.
func TestSHAKEPrefixProperty(t *testing.T) {
	lengths := []int{0, 1, 7, 8, 9, 31, 32, 64, 135, 136, 137, 167, 168, 169, 200, 336, 400}
	for _, v := range []SHAKEVariant{SHAKE128, SHAKE256} {
		msg := []byte("prefix property")
		longest := SHAKESum(v, msg, lengths[len(lengths)-1])
		for _, n := range lengths {
			got := SHAKESum(v, msg, n)
			if len(got) != n {
				t.Errorf("%s/%d: length = %d", v, n, len(got))
				continue
			}
			if !bytes.Equal(got, longest[:n]) {
				t.Errorf("%s/%d is not a prefix of the %d-byte output\n got %s\nwant %s",
					v, n, lengths[len(lengths)-1],
					hex.EncodeToString(got), hex.EncodeToString(longest[:n]))
			}
		}
	}
}

// TestSHAKESqueezeAdvancesStream checks that Squeeze consumes: consecutive calls
// return consecutive parts of the stream, which is what distinguishes Squeeze
// (streaming) from Sum (peeking).
func TestSHAKESqueezeAdvancesStream(t *testing.T) {
	for _, v := range []SHAKEVariant{SHAKE128, SHAKE256} {
		whole := SHAKESum(v, []byte("stream"), 300)

		s := NewSHAKE(v)
		if _, err := s.Write([]byte("stream")); err != nil {
			t.Fatalf("%s: write: %v", v, err)
		}
		var got []byte
		for _, n := range []int{1, 135, 2, 162} {
			got = append(got, s.Squeeze(n)...)
		}
		if !bytes.Equal(got, whole) {
			t.Errorf("%s: consecutive Squeeze calls do not concatenate to the stream\n got %s\nwant %s",
				v, hex.EncodeToString(got), hex.EncodeToString(whole))
		}
	}
}

// TestSHAKESumDoesNotConsumeState proves Sum peeks: absorbing more input after a
// Sum must still produce the one-shot answer for the concatenated message, and
// Sum must be repeatable.
func TestSHAKESumDoesNotConsumeState(t *testing.T) {
	s := NewSHAKE256()
	prefix := []byte("the first half ")
	if _, err := s.Write(prefix); err != nil {
		t.Fatal(err)
	}
	mid := s.Sum(64)
	if len(mid) != 64 {
		t.Fatalf("Sum(64) returned %d bytes", len(mid))
	}
	if !bytes.Equal(s.Sum(64), mid) {
		t.Error("Sum is not repeatable: two calls returned different output")
	}

	suffix := []byte("and the second half")
	if _, err := s.Write(suffix); err != nil {
		t.Fatalf("write after Sum: %v", err)
	}
	full := s.Sum(64)

	wantFull := SHAKESum(SHAKE256, append(append([]byte{}, prefix...), suffix...), 64)
	if !bytes.Equal(full, wantFull) {
		t.Errorf("Sum consumed the absorb state\n got %s\nwant %s",
			hex.EncodeToString(full), hex.EncodeToString(wantFull))
	}
	if bytes.Equal(mid, full) {
		t.Error("output did not change after absorbing more input")
	}
}

// TestSHAKESumAfterSqueezeContinuesStream checks Sum's peek semantics once
// streaming has started: it must continue from the current position, not restart
// the stream.
func TestSHAKESumAfterSqueezeContinuesStream(t *testing.T) {
	for _, v := range []SHAKEVariant{SHAKE128, SHAKE256} {
		whole := SHAKESum(v, []byte("peek"), 200)

		s := NewSHAKE(v)
		if _, err := s.Write([]byte("peek")); err != nil {
			t.Fatalf("%s: write: %v", v, err)
		}
		first := s.Squeeze(40)
		peek := s.Sum(20)
		if !bytes.Equal(first, whole[:40]) {
			t.Errorf("%s: first 40 bytes wrong", v)
		}
		if !bytes.Equal(peek, whole[40:60]) {
			t.Errorf("%s: Sum after Squeeze did not continue the stream\n got %s\nwant %s",
				v, hex.EncodeToString(peek), hex.EncodeToString(whole[40:60]))
		}
		// The peek must not have advanced the stream.
		next := s.Squeeze(20)
		if !bytes.Equal(next, whole[40:60]) {
			t.Errorf("%s: Sum advanced the stream\n got %s\nwant %s",
				v, hex.EncodeToString(next), hex.EncodeToString(whole[40:60]))
		}
	}
}

// TestSHAKEZeroAndNegativeLengths covers the degenerate output lengths: zero
// bytes is legal and must not disturb the state, and a negative length must not
// panic.
func TestSHAKEZeroAndNegativeLengths(t *testing.T) {
	for _, v := range []SHAKEVariant{SHAKE128, SHAKE256} {
		s := NewSHAKE(v)
		if _, err := s.Write([]byte("abc")); err != nil {
			t.Fatalf("%s: write: %v", v, err)
		}
		if got := s.Squeeze(0); len(got) != 0 {
			t.Errorf("%s: Squeeze(0) returned %d bytes", v, len(got))
		}
		if got := s.Sum(0); len(got) != 0 {
			t.Errorf("%s: Sum(0) returned %d bytes", v, len(got))
		}
		if got := s.Sum(-1); got != nil {
			t.Errorf("%s: Sum(-1) = %v, want nil", v, got)
		}
		if got := s.Squeeze(-1); got != nil {
			t.Errorf("%s: Squeeze(-1) = %v, want nil", v, got)
		}
		// Zero-length reads must not have advanced the stream: the next read
		// still has to match the one-shot output.
		if got, want := s.Squeeze(32), SHAKESum(v, []byte("abc"), 32); !bytes.Equal(got, want) {
			t.Errorf("%s: zero-length operations disturbed the stream\n got %s\nwant %s",
				v, hex.EncodeToString(got), hex.EncodeToString(want))
		}
	}
}

// TestSHAKEReadIsNotEOF proves Read behaves as an infinite stream reader, so
// io.ReadFull and io.Copy work without special-casing.
func TestSHAKEReadIsNotEOF(t *testing.T) {
	s := NewSHAKE128()
	if _, err := s.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	n, err := io.ReadFull(s, buf)
	if err != nil {
		t.Fatalf("io.ReadFull over 4096 bytes (24 blocks past the rate): %v", err)
	}
	if n != len(buf) {
		t.Fatalf("io.ReadFull read %d bytes, want %d", n, len(buf))
	}
	// A plain Read past the rate must not report EOF either.
	more := make([]byte, 500)
	if n, err := s.Read(more); err != nil || n != 500 {
		t.Errorf("Read past the rate = (%d, %v), want (500, nil)", n, err)
	}
	// The 4096-byte prefix must match the one-shot answer.
	if want := SHAKESum(SHAKE128, []byte("abc"), 4096); !bytes.Equal(buf, want) {
		t.Error("4096-byte read differs from one-shot output")
	}
}

// TestSHAKEWriteAfterSqueezeFails checks the guard: absorbing into a padded
// sponge is undefined, so it is refused rather than silently producing bytes
// that belong to no message.
func TestSHAKEWriteAfterSqueezeFails(t *testing.T) {
	s := NewSHAKE128()
	if _, err := s.Write([]byte("abc")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := s.Read(make([]byte, 4)); err != nil {
		t.Fatalf("read: %v", err)
	}
	n, err := s.Write([]byte("more"))
	if err == nil {
		t.Fatal("Write after Read succeeded, want ErrSHAKESqueezing")
	}
	if n != 0 {
		t.Errorf("Write returned n = %d, want 0", n)
	}
	if !bytes.Contains([]byte(err.Error()), []byte("squeezing")) {
		t.Errorf("error %q does not explain the problem", err)
	}
	// A zero-length Write after squeezing is still a Write into a padded state,
	// but it cannot corrupt anything, so it is allowed to succeed or fail; what
	// matters is that Reset restores a working sponge.
	s.Reset()
	if _, err := s.Write([]byte("abc")); err != nil {
		t.Fatalf("write after reset: %v", err)
	}
	if got, want := s.Squeeze(32), SHAKESum(SHAKE128, []byte("abc"), 32); !bytes.Equal(got, want) {
		t.Error("Reset did not restore the empty-message state")
	}
}

// TestSHAKEResetClearsState proves a reused XOF is equivalent to a fresh one.
func TestSHAKEResetClearsState(t *testing.T) {
	s := NewSHAKE256()
	if _, err := s.Write([]byte("poison the state with a message long enough to fill several blocks")); err != nil {
		t.Fatal(err)
	}
	_ = s.Squeeze(300)
	s.Reset()

	got := s.Sum(64)
	want := SHAKESum(SHAKE256, nil, 64)
	if !bytes.Equal(got, want) {
		t.Errorf("after Reset the output is not the empty-message output\n got %s\nwant %s",
			hex.EncodeToString(got), hex.EncodeToString(want))
	}
}

// TestSHAKEStreamingWriteMatchesOneShot checks the absorb side: arbitrary write
// chunkings must match one Write, at sizes that straddle the rate.
func TestSHAKEStreamingWriteMatchesOneShot(t *testing.T) {
	for _, v := range []SHAKEVariant{SHAKE128, SHAKE256} {
		rate := v.rate()
		for _, size := range []int{0, 1, rate - 1, rate, rate + 1, 2 * rate, 2*rate + 7, 1000} {
			msg := make([]byte, size)
			for i := range msg {
				msg[i] = byte(i*29 + 11)
			}
			want := SHAKESum(v, msg, 64)

			for _, cut := range []int{1, rate - 1, rate, rate + 1, size / 2, size - 1} {
				if cut <= 0 || cut >= size {
					continue
				}
				s := NewSHAKE(v)
				if _, err := s.Write(msg[:cut]); err != nil {
					t.Fatalf("%s/%d: write: %v", v, size, err)
				}
				if _, err := s.Write(msg[cut:]); err != nil {
					t.Fatalf("%s/%d: write: %v", v, size, err)
				}
				if got := s.Sum(64); !bytes.Equal(got, want) {
					t.Errorf("%s/%d split %d: streaming output differs from one-shot\n got %s\nwant %s",
						v, size, cut, hex.EncodeToString(got), hex.EncodeToString(want))
				}
			}
		}
	}
}

// TestSHAKEDomainSeparation checks that SHAKE is not SHA-3 with a different
// output length. Both families share the permutation and the rate, so the only
// thing keeping them apart is the 0x1F vs 0x06 suffix; if that suffix were
// wrong, SHAKE128 would return the first bytes of SHA3-256's digest.
func TestSHAKEDomainSeparation(t *testing.T) {
	msg := []byte("domain separation")
	if bytes.Equal(SHAKESum(SHAKE128, msg, 32), SHA3Sum(SHA3_256, msg)) {
		t.Error("SHAKE128 produced the SHA3-256 digest: the 0x1F suffix is not being applied")
	}
	if bytes.Equal(SHAKESum(SHAKE256, msg, 64), SHA3Sum(SHA3_512, msg)) {
		t.Error("SHAKE256 produced the SHA3-512 digest: the 0x1F suffix is not being applied")
	}
	// The two XOFs share a rate with SHA3-224 and SHA3-256 respectively, so a
	// cross-check against those variants is the tightest available.
	if bytes.Equal(SHAKESum(SHAKE128, msg, 28), SHA3Sum(SHA3_224, msg)) {
		t.Error("SHAKE128 produced the SHA3-224 digest")
	}
	// And the two XOFs must not agree with each other.
	if bytes.Equal(SHAKESum(SHAKE128, msg, 32), SHAKESum(SHAKE256, msg, 32)) {
		t.Error("SHAKE128 and SHAKE256 produce the same output")
	}
}

// TestSHAKEKernelNameMapping checks the /proc/crypto join key.
func TestSHAKEKernelNameMapping(t *testing.T) {
	cases := map[SHAKEVariant]string{
		SHAKE128: "shake128",
		SHAKE256: "shake256",
	}
	for v, want := range cases {
		if got := v.KernelName(); got != want {
			t.Errorf("%s: KernelName() = %q, want %q", v, got, want)
		}
	}
	if got := SHAKEVariant(0).KernelName(); got != "" {
		t.Errorf("invalid variant returned %q, want empty", got)
	}
	if got := SHAKEVariant(0).String(); got != "SHAKE0" {
		t.Errorf("invalid variant String() = %q, want SHAKE0", got)
	}
}

// TestSHAKEKernelInfoIsHonest records the negative result this host actually
// produces: no shake128/shake256 driver in /proc/crypto. The assertion is
// deliberately weak about which answer is correct — a future kernel may register
// one — but strict about self-consistency, so the report cannot claim hardware
// without a "-s390" driver or claim AF_ALG without a driver at all.
func TestSHAKEKernelInfoIsHonest(t *testing.T) {
	all := SHAKEKernelDrivers()
	if len(all) != 2 {
		t.Fatalf("SHAKEKernelDrivers returned %d entries, want 2", len(all))
	}
	for _, info := range all {
		if info.AFALGAvailable && info.KernelDriver == "" {
			t.Error("AF_ALG reported available with no kernel driver")
		}
		if info.Hardware && info.KernelDriver == "" {
			t.Error("Hardware reported true with no kernel driver")
		}
		if info.KernelDriver != "" {
			isS390 := len(info.KernelDriver) > 5 &&
				info.KernelDriver[len(info.KernelDriver)-5:] == "-s390"
			if info.Hardware != isS390 {
				t.Errorf("driver %q: Hardware = %v but the -s390 suffix says %v",
					info.KernelDriver, info.Hardware, isS390)
			}
			if info.Hardware && info.KernelPriority != 300 {
				t.Errorf("driver %q: CPACF driver priority %d, want 300",
					info.KernelDriver, info.KernelPriority)
			}
		} else if info.Error == "" {
			t.Error("no driver registered, yet no error was recorded")
		}
	}
	t.Logf("SHAKE kernel backends: %s -> %q, %s -> %q",
		SHAKE128, all[0].Error, SHAKE256, all[1].Error)
}

// TestSHAKEBenchmarkMeasures checks the pure-Go throughput harness returns a
// positive number and labels the backend honestly. There is no AF_ALG SHAKE on
// this host, so a "hardware" label here would be a fabrication.
func TestSHAKEBenchmarkMeasures(t *testing.T) {
	for _, v := range []SHAKEVariant{SHAKE128, SHAKE256} {
		res, err := BenchmarkSHAKE(v, 64*1024, 20)
		if err != nil {
			t.Fatalf("%s: %v", v, err)
		}
		if res.MBps <= 0 {
			t.Errorf("%s: non-positive throughput %f", v, res.MBps)
		}
		if res.Backend != "pure-go" {
			t.Errorf("%s: backend = %q, want pure-go", v, res.Backend)
		}
		if res.Variant != v.String() {
			t.Errorf("variant label = %q, want %q", res.Variant, v.String())
		}
		if res.OutLen != v.Size() {
			t.Errorf("%s: OutLen = %d, want %d", v, res.OutLen, v.Size())
		}
	}
}

// TestSHAKEBenchmarkRejectsBadParameters covers the guard clauses.
func TestSHAKEBenchmarkRejectsBadParameters(t *testing.T) {
	if _, err := BenchmarkSHAKE(SHAKE128, 0, 10); err == nil {
		t.Error("accepted a zero block size")
	}
	if _, err := BenchmarkSHAKE(SHAKE128, 1024, 0); err == nil {
		t.Error("accepted zero iterations")
	}
	if _, err := BenchmarkSHAKE(SHAKE128, -1, -1); err == nil {
		t.Error("accepted negative parameters")
	}
}

// TestSHAKESuiteShape checks the suite returns one row per XOF.
func TestSHAKESuiteShape(t *testing.T) {
	rows := SHAKESuite(16*1024, 10)
	if len(rows) != 2 {
		t.Fatalf("suite returned %d rows, want 2", len(rows))
	}
	want := []string{"SHAKE128", "SHAKE256"}
	for i, r := range rows {
		if r.Variant != want[i] {
			t.Errorf("row %d variant = %q, want %q", i, r.Variant, want[i])
		}
		if r.Error != "" {
			t.Errorf("row %d (%s): unexpected error %q", i, r.Variant, r.Error)
		}
	}
}

// BenchmarkSHAKEPureGo128_1MB and 256 give `go test -bench` a handle on the XOF
// that is directly comparable to BenchmarkSHA3PureGo256_1MB: same message size,
// same "absorb then squeeze a conventional digest" shape.
func BenchmarkSHAKEPureGo128_1MB(b *testing.B) { benchSHAKE(b, SHAKE128, 1024*1024) }

func BenchmarkSHAKEPureGo256_1MB(b *testing.B) { benchSHAKE(b, SHAKE256, 1024*1024) }

func benchSHAKE(b *testing.B, v SHAKEVariant, size int) {
	b.SetBytes(int64(size))
	data := make([]byte, size)
	out := make([]byte, v.Size())
	s := NewSHAKE(v)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Reset()
		_, _ = s.Write(data)
		s.read(out)
	}
}

// sum adds up a chunking so the test can assert it covers the whole output.
func sum(ns []int) int {
	total := 0
	for _, n := range ns {
		total += n
	}
	return total
}
