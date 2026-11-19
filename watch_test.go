package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Chen100E/zcrypt-s390x/pkg/cipher"
	"github.com/Chen100E/zcrypt-s390x/pkg/cpacf"
)

// syncBuffer is a bytes.Buffer safe for concurrent use. The watch loop writes
// from its own goroutine while the test reads, so an unsynchronised buffer would
// be a data race the race detector would rightly flag.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestParseWatchInterval pins the accepted interval syntaxes and the rejected
// ones. A bare number means seconds, because that is what a user types.
func TestParseWatchInterval(t *testing.T) {
	ok := []struct {
		in   string
		want time.Duration
	}{
		{"60s", 60 * time.Second},
		{"5m", 5 * time.Minute},
		{"1h", time.Hour},
		{"250ms", 250 * time.Millisecond},
		{"60", 60 * time.Second},
		{" 30 ", 30 * time.Second},
		{"1", time.Second},
	}
	for _, c := range ok {
		got, err := parseWatchInterval(c.in)
		if err != nil {
			t.Errorf("%q: unexpected error %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("%q: got %v, want %v", c.in, got, c.want)
		}
	}

	bad := []string{"", "   ", "abc", "0", "0s", "-5s", "-1", "1x"}
	for _, in := range bad {
		if _, err := parseWatchInterval(in); err == nil {
			t.Errorf("%q: accepted an invalid interval", in)
		}
	}
}

// TestWatchLoopEmitsTicksAndStops is the core test for continuous monitoring: the
// loop must emit a tick immediately, keep emitting on the interval, and return
// promptly when the context is cancelled.
func TestWatchLoopEmitsTicksAndStops(t *testing.T) {
	if testing.Short() {
		t.Skip("watch loop runs real benchmarks; skipped under -short")
	}

	out := &syncBuffer{}
	w := &watcher{
		interval: 120 * time.Millisecond,
		scale:    1,
		out:      out,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 900*time.Millisecond)
	defer cancel()

	start := time.Now()
	done := make(chan error, 1)
	go func() { done <- w.run(ctx) }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("watch loop returned an error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("watch loop did not stop within 5s of its context expiring")
	}
	elapsed := time.Since(start)

	// It must have stopped near its deadline, not immediately and not much later.
	if elapsed < 500*time.Millisecond {
		t.Errorf("loop stopped after %s, well before its 900ms deadline", elapsed)
	}

	// Parse every emitted line as JSON. The immediate tick plus roughly seven
	// interval ticks should be present.
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) < 3 {
		t.Fatalf("only %d ticks emitted in %s: %q", len(lines), elapsed, out.String())
	}

	seqs := make([]int, 0, len(lines))
	for i, line := range lines {
		var tick watchTick
		if err := json.Unmarshal([]byte(line), &tick); err != nil {
			t.Fatalf("tick %d is not valid JSON: %v\n%s", i, err, line)
		}
		// Sequence numbers must be 0, 1, 2, ... with no gaps, so a dropped tick
		// is visible.
		if tick.Seq != i {
			t.Errorf("tick %d has seq %d, want %d", i, tick.Seq, i)
		}
		if tick.Timestamp == "" {
			t.Errorf("tick %d has no timestamp", i)
		}
		if tick.Error != "" {
			t.Errorf("tick %d reported an error: %s", i, tick.Error)
		}
		if !tick.VectorsOK {
			t.Errorf("tick %d reported failing NIST vectors", i)
		}
		if tick.AESGCMEnc <= 0 {
			t.Errorf("tick %d has non-positive AES-GCM throughput %v", i, tick.AESGCMEnc)
		}
		if tick.SHA256 <= 0 {
			t.Errorf("tick %d has non-positive SHA-256 throughput %v", i, tick.SHA256)
		}
		if tick.MSALevel <= 0 {
			t.Errorf("tick %d has no MSA level", i)
		}
		seqs = append(seqs, tick.Seq)
	}
	t.Logf("%d ticks in %s, seqs %v", len(seqs), elapsed.Round(time.Millisecond), seqs)
}

// TestWatchLoopRejectsZeroInterval proves a zero interval is refused rather than
// producing a busy loop.
func TestWatchLoopRejectsZeroInterval(t *testing.T) {
	w := &watcher{interval: 0, out: &syncBuffer{}}
	err := w.run(context.Background())
	if err == nil {
		t.Fatal("accepted a zero interval")
	}
	if !strings.Contains(err.Error(), "must be positive") {
		t.Errorf("error = %q, want it to mention positivity", err)
	}

	w.interval = -time.Second
	if err := w.run(context.Background()); err == nil {
		t.Fatal("accepted a negative interval")
	}
}

// TestWatchLoopStopsImmediatelyWhenAlreadyCancelled proves a cancelled context
// does not start a benchmark. This matters because each tick costs a few hundred
// milliseconds; a shutdown path that ran one more benchmark would delay Ctrl-C
// visibly.
func TestWatchLoopStopsImmediatelyWhenAlreadyCancelled(t *testing.T) {
	out := &syncBuffer{}
	w := &watcher{interval: time.Second, out: out}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancelled before the loop starts

	start := time.Now()
	if err := w.run(ctx); err != nil {
		t.Fatalf("run: %v", err)
	}
	elapsed := time.Since(start)

	// The first tick is attempted but must bail out on the context check before
	// doing any work, so this should be near-instant.
	if elapsed > 100*time.Millisecond {
		t.Errorf("cancelled loop took %s to return; it should bail out immediately", elapsed)
	}
}

// TestWatchTickReportsRegressions proves a baseline comparison inside a tick
// surfaces a regression. An impossible baseline (absurdly high throughput) makes
// every measurement a regression, which is the cleanest way to test the path.
func TestWatchTickReportsRegressions(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a real benchmark; skipped under -short")
	}

	// A baseline claiming 1 TB/s for both metrics: unreachable, so both rows must
	// be reported as regressed.
	base := cipher.NewBaseline(machineFingerprint(cipherCaps()), []cipher.BaselineMetric{
		{Name: "aes256gcm.encrypt.1mib", MBps: 1e6, Unit: "MB/s", HigherIsBetter: true},
		{Name: "sha256.1mib", MBps: 1e6, Unit: "MB/s", HigherIsBetter: true},
	}, "impossible baseline")

	out := &syncBuffer{}
	w := &watcher{
		interval:  time.Second,
		scale:     1,
		out:       out,
		baseline:  &base,
		tolerance: 20,
	}
	if err := w.tick(context.Background(), 0); err != nil {
		t.Fatalf("tick: %v", err)
	}

	var tick watchTick
	if err := json.Unmarshal([]byte(strings.TrimSpace(out.String())), &tick); err != nil {
		t.Fatalf("tick output is not valid JSON: %v\n%s", err, out.String())
	}
	if len(tick.Regressed) != 2 {
		t.Errorf("regressed = %v, want both metrics", tick.Regressed)
	}
	for _, r := range tick.Regressed {
		if !strings.Contains(r, "%") {
			t.Errorf("regression line %q does not include a delta percentage", r)
		}
	}
	t.Logf("regressions reported: %v", tick.Regressed)
}

// TestWatchTickWithNoBaselineHasNoRegressions proves the comparison is optional
// and does not produce spurious findings when no baseline is configured.
func TestWatchTickWithNoBaselineHasNoRegressions(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a real benchmark; skipped under -short")
	}
	out := &syncBuffer{}
	w := &watcher{interval: time.Second, out: out}
	if err := w.tick(context.Background(), 0); err != nil {
		t.Fatalf("tick: %v", err)
	}
	var tick watchTick
	if err := json.Unmarshal([]byte(strings.TrimSpace(out.String())), &tick); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if len(tick.Regressed) != 0 {
		t.Errorf("regressions without a baseline: %v", tick.Regressed)
	}
}

// TestJoinErr checks the multi-failure accumulator, which exists so one tick can
// report several independent problems rather than only the last.
func TestJoinErr(t *testing.T) {
	if got := joinErr("", "first"); got != "first" {
		t.Errorf("got %q", got)
	}
	if got := joinErr("first", "second"); got != "first; second" {
		t.Errorf("got %q", got)
	}
	if got := joinErr("a; b", "c"); got != "a; b; c" {
		t.Errorf("got %q", got)
	}
}

// TestMachineFingerprintHasIdentity proves the fingerprint carries the fields the
// comparability rules depend on.
func TestMachineFingerprintHasIdentity(t *testing.T) {
	fp := machineFingerprint(cipherCaps())
	if fp.Arch == "" {
		t.Error("no architecture")
	}
	if fp.MaxMSALevel <= 0 {
		t.Error("no MSA level")
	}
	// The fingerprint must use the Query-refined MSA level, not the unrefined
	// STFLE-only value. On the reference machine those differ (12 vs 13), and
	// since MaxMSALevel is a hard comparability requirement, an unrefined value
	// would make every watch tick incomparable with a report-path baseline.
	refined := cipherCaps()
	refined = cpacfRefine(refined)
	if fp.MaxMSALevel != refined.MaxMSALevel {
		t.Errorf("fingerprint MSA level = %d, want the Query-refined %d",
			fp.MaxMSALevel, refined.MaxMSALevel)
	}
	if fp.GoVersion == "" {
		t.Error("no Go version")
	}
	if fp.Kernel == "" {
		t.Error("no kernel release")
	}
	if fp.Kernel == "unknown" {
		t.Log("kernel release unreadable; /proc/sys/kernel/osrelease missing")
	}
	t.Logf("fingerprint: %+v", fp)
}

// cpacfRefine applies the CPACF Query refinement, mirroring what
// machineFingerprint does internally so the test can assert against it.
func cpacfRefine(caps cpacf.HardwareCapabilities) cpacf.HardwareCapabilities {
	return cpacf.RefineWithQuery(caps, cpacf.ProbeQuery(caps))
}

// TestFirstLine covers the error-compaction helper.
func TestFirstLine(t *testing.T) {
	cases := map[string]string{
		"":                 "",
		"single":           "single",
		"two\nlines":       "two",
		"a\nb\nc":          "a",
		"trailing newline": "trailing newline",
	}
	for in, want := range cases {
		if got := firstLine(in); got != want {
			t.Errorf("firstLine(%q) = %q, want %q", in, got, want)
		}
	}
}
