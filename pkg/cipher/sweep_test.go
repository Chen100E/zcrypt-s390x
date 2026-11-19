package cipher

import (
	"testing"
	"time"
)

// TestSweepSizesAreAscendingAndGeometric guards the ladder itself. A duplicate
// or out-of-order size would make the knee calculation meaningless, because it
// relies on the points being in ascending order.
func TestSweepSizesAreAscendingAndGeometric(t *testing.T) {
	if len(SweepSizes) != 9 {
		t.Fatalf("SweepSizes has %d entries, want 9", len(SweepSizes))
	}
	if SweepSizes[0] != 64 {
		t.Errorf("smallest size is %d, want 64", SweepSizes[0])
	}
	if SweepSizes[len(SweepSizes)-1] != 4*1024*1024 {
		t.Errorf("largest size is %d, want 4 MiB", SweepSizes[len(SweepSizes)-1])
	}
	for i := 1; i < len(SweepSizes); i++ {
		if SweepSizes[i] <= SweepSizes[i-1] {
			t.Errorf("size %d (%d) is not greater than size %d (%d)",
				i, SweepSizes[i], i-1, SweepSizes[i-1])
		}
		// Powers of four, so the ladder is evenly spaced on a log axis. The
		// tolerance allows the first step (64 -> 256) to be exactly 4x.
		ratio := float64(SweepSizes[i]) / float64(SweepSizes[i-1])
		if ratio < 3.9 || ratio > 4.1 {
			t.Errorf("step %d->%d is %.2fx, want ~4x", SweepSizes[i-1], SweepSizes[i], ratio)
		}
	}
}

// TestCalibrateIterationsHitsTheBudget checks the calibration maths: given a
// known per-call cost, the chosen iteration count must land near the 40 ms
// budget, and the clamps must hold at both ends.
func TestCalibrateIterationsHitsTheBudget(t *testing.T) {
	cases := []struct {
		name    string
		perCall time.Duration
		wantMin int
		wantMax int
	}{
		// 1 microsecond per call: 40ms / 1us = 40000 iterations.
		{"1us", time.Microsecond, 39000, 41000},
		// 100 nanoseconds: 400000 iterations.
		{"100ns", 100 * time.Nanosecond, 390000, 410000},
		// 1 second per call: clamped to the minimum, not 0.
		{"1s", time.Second, minSweepIterations, minSweepIterations},
		// 1 nanosecond per call: 40 million, clamped to the maximum.
		{"1ns", time.Nanosecond, maxSweepIterations, maxSweepIterations},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := calibrateIterations(func(n int) (time.Duration, error) {
				// The probe is called with calibrationIterations, so report the
				// matching total.
				return time.Duration(n) * c.perCall, nil
			})
			if err != nil {
				t.Fatalf("calibrate: %v", err)
			}
			if got < c.wantMin || got > c.wantMax {
				t.Errorf("iterations = %d, want %d..%d", got, c.wantMin, c.wantMax)
			}
			if got < minSweepIterations || got > maxSweepIterations {
				t.Errorf("iterations = %d, outside the hard bounds %d..%d",
					got, minSweepIterations, maxSweepIterations)
			}
		})
	}
}

// TestCalibrateIterationsPropagatesErrors proves a failing probe aborts the
// calibration rather than being treated as a zero-duration operation.
func TestCalibrateIterationsPropagatesErrors(t *testing.T) {
	sentinel := errSentinel{}
	_, err := calibrateIterations(func(n int) (time.Duration, error) {
		return 0, sentinel
	})
	if err == nil {
		t.Fatal("calibrate swallowed an error from the probe")
	}
	if err != sentinel {
		t.Errorf("error = %v, want the sentinel", err)
	}
}

// TestCalibrateIterationsHandlesZeroDuration covers a probe that returns no
// elapsed time, which must fall back to the maximum count rather than dividing
// by zero.
func TestCalibrateIterationsHandlesZeroDuration(t *testing.T) {
	got, err := calibrateIterations(func(n int) (time.Duration, error) {
		return 0, nil
	})
	if err != nil {
		t.Fatalf("calibrate: %v", err)
	}
	if got != maxSweepIterations {
		t.Errorf("iterations = %d, want %d", got, maxSweepIterations)
	}
}

type errSentinel struct{}

func (errSentinel) Error() string { return "sentinel" }

// TestFinalizeCurveComputesPeakAndKnee pins the derived statistics against a
// synthetic curve with a known shape: throughput rises to a plateau and then
// falls. The expected peak, knee and decline are worked out by hand.
func TestFinalizeCurveComputesPeakAndKnee(t *testing.T) {
	c := SweepCurve{
		Algorithm:    "synthetic",
		KneeFraction: 0.9,
		Points: []SweepPoint{
			{BlockSize: 64, MBps: 100},
			{BlockSize: 256, MBps: 400},
			{BlockSize: 1024, MBps: 900},
			{BlockSize: 4096, MBps: 1000}, // peak
			{BlockSize: 16384, MBps: 950},
			{BlockSize: 65536, MBps: 800},
		},
	}
	finalizeCurve(&c)

	if c.PeakMBps != 1000 {
		t.Errorf("peak = %v, want 1000", c.PeakMBps)
	}
	if c.PeakSize != 4096 {
		t.Errorf("peak size = %d, want 4096", c.PeakSize)
	}
	if c.FirstMBps != 100 {
		t.Errorf("first = %v, want 100", c.FirstMBps)
	}
	if c.LastMBps != 800 {
		t.Errorf("last = %v, want 800", c.LastMBps)
	}
	// Decline from 1000 to 800 is 20%.
	if c.DeclinePercent != 20 {
		t.Errorf("decline = %v%%, want 20%%", c.DeclinePercent)
	}
	// Knee at 90% of 1000 = 900; the first point reaching 900 is the 1024 one,
	// and the plateau runs from there to the 16384 point (950, still above 900).
	if c.KneeSize != 1024 {
		t.Errorf("knee size = %d, want 1024", c.KneeSize)
	}
	if c.PlateauMin != 1024 {
		t.Errorf("plateau min = %d, want 1024", c.PlateauMin)
	}
	if c.PlateauMax != 16384 {
		t.Errorf("plateau max = %d, want 16384", c.PlateauMax)
	}
}

// TestFinalizeCurveSkipsFailedPoints proves an errored point cannot become the
// peak, which would otherwise report a throughput of zero as the maximum.
func TestFinalizeCurveSkipsFailedPoints(t *testing.T) {
	c := SweepCurve{
		Algorithm:    "synthetic",
		KneeFraction: 0.9,
		Points: []SweepPoint{
			{BlockSize: 64, Error: "boom"},
			{BlockSize: 256, MBps: 500},
			{BlockSize: 1024, Error: "boom"},
			{BlockSize: 4096, MBps: 1000},
		},
	}
	finalizeCurve(&c)
	if c.PeakMBps != 1000 || c.PeakSize != 4096 {
		t.Errorf("peak = %v at %d, want 1000 at 4096", c.PeakMBps, c.PeakSize)
	}
	if c.FirstMBps != 500 {
		t.Errorf("first = %v, want 500 (the first valid point)", c.FirstMBps)
	}
}

// TestFinalizeCurveAllFailed covers the degenerate case: no valid points at all.
// It must leave the derived fields zero rather than dividing by zero.
func TestFinalizeCurveAllFailed(t *testing.T) {
	c := SweepCurve{Algorithm: "synthetic", KneeFraction: 0.9}
	for _, s := range SweepSizes {
		c.Points = append(c.Points, SweepPoint{BlockSize: s, Error: "boom"})
	}
	finalizeCurve(&c)
	if c.PeakMBps != 0 || c.KneeSize != 0 || c.DeclinePercent != 0 ||
		c.PlateauMin != 0 || c.PlateauMax != 0 {
		t.Errorf("all-failed curve has derived fields set: %+v", c)
	}
}

// TestFinalizeCurveDefaultsKneeFraction checks a zero KneeFraction is replaced
// with 0.9 rather than making every point qualify.
func TestFinalizeCurveDefaultsKneeFraction(t *testing.T) {
	c := SweepCurve{
		Algorithm: "synthetic",
		Points: []SweepPoint{
			{BlockSize: 64, MBps: 100},
			{BlockSize: 256, MBps: 1000},
		},
	}
	finalizeCurve(&c)
	if c.KneeFraction != 0.9 {
		t.Errorf("KneeFraction = %v, want 0.9", c.KneeFraction)
	}
	if c.KneeSize != 256 {
		t.Errorf("knee = %d, want 256 (the only point above 90%% of peak)", c.KneeSize)
	}
}

// TestSweepAESGCMProducesAFullCurve runs the real AES sweep. It is the slowest
// test in the package, so it uses scale 1.
func TestSweepAESGCMProducesAFullCurve(t *testing.T) {
	if testing.Short() {
		t.Skip("buffer sweep is slow; skipped under -short")
	}
	curve := SweepAESGCM(256, 1)
	if len(curve.Points) != len(SweepSizes) {
		t.Fatalf("got %d points, want %d", len(curve.Points), len(SweepSizes))
	}
	for _, p := range curve.Points {
		if p.Error != "" {
			t.Errorf("size %d: %s", p.BlockSize, p.Error)
			continue
		}
		if p.MBps <= 0 {
			t.Errorf("size %d: non-positive throughput %v", p.BlockSize, p.MBps)
		}
	}
	if curve.PeakMBps <= 0 {
		t.Fatal("no peak")
	}
	if curve.KneeSize <= 0 {
		t.Fatal("no knee")
	}
	// The knee must not be larger than the peak size: by definition the peak
	// point itself reaches 100% of peak.
	if curve.KneeSize > curve.PeakSize {
		t.Errorf("knee %d is larger than peak size %d", curve.KneeSize, curve.PeakSize)
	}
	t.Logf("AES-256-GCM: peak %.0f MB/s at %s, knee %s (%.0f%% of peak)",
		curve.PeakMBps, humanSizeStr(curve.PeakSize), humanSizeStr(curve.KneeSize),
		curve.KneeFraction*100)
	for _, p := range curve.Points {
		t.Logf("  %-8s %10.1f MB/s", humanSizeStr(p.BlockSize), p.MBps)
	}
}

// TestSweepSHA256ProducesAFullCurve is the same check for the hash path.
func TestSweepSHA256ProducesAFullCurve(t *testing.T) {
	if testing.Short() {
		t.Skip("buffer sweep is slow; skipped under -short")
	}
	curve := SweepSHA256(1)
	if len(curve.Points) != len(SweepSizes) {
		t.Fatalf("got %d points, want %d", len(curve.Points), len(SweepSizes))
	}
	for _, p := range curve.Points {
		if p.Error != "" {
			t.Errorf("size %d: %s", p.BlockSize, p.Error)
		}
	}
	if curve.PeakMBps <= 0 {
		t.Fatal("no peak")
	}
	t.Logf("SHA-256: peak %.0f MB/s at %s, knee %s, first %.0f last %.0f",
		curve.PeakMBps, humanSizeStr(curve.PeakSize), humanSizeStr(curve.KneeSize),
		curve.FirstMBps, curve.LastMBps)
}

// TestRunSweepValidates runs the whole sweep and validates the result. This is
// the test that would catch a mismatch between the size ladder and the curves.
func TestRunSweepValidates(t *testing.T) {
	if testing.Short() {
		t.Skip("buffer sweep is slow; skipped under -short")
	}
	res := RunSweep(1)
	if err := ValidateSweep(res); err != nil {
		t.Fatalf("sweep failed validation: %v", err)
	}
	if len(res.Curves) != 3 {
		t.Errorf("got %d curves, want 3", len(res.Curves))
	}
	if res.Elapsed == "" {
		t.Error("elapsed time not recorded")
	}
	names := map[string]bool{}
	for _, c := range res.Curves {
		names[c.Algorithm] = true
	}
	for _, want := range []string{"AES-256-GCM (encrypt)", "SHA-256", "SHA3-256"} {
		if !names[want] {
			t.Errorf("missing curve %q", want)
		}
	}
	t.Logf("full sweep completed in %s", res.Elapsed)
}

// TestValidateSweepCatchesMismatches proves the validator actually rejects
// malformed results rather than accepting anything.
func TestValidateSweepCatchesMismatches(t *testing.T) {
	good := SweepCurve{
		Algorithm:  "a",
		PeakMBps:   100,
		KneeSize:   64,
		PlateauMin: 64,
		PlateauMax: 256,
		Points: []SweepPoint{
			{BlockSize: 64, MBps: 100},
			{BlockSize: 256, MBps: 200},
		},
	}
	base := SweepResult{Sizes: []int{64, 256}, Curves: []SweepCurve{good}}
	if err := ValidateSweep(base); err != nil {
		t.Fatalf("valid result rejected: %v", err)
	}

	cases := []struct {
		name string
		mut  func(r *SweepResult)
	}{
		{"no sizes", func(r *SweepResult) { r.Sizes = nil }},
		{"no curves", func(r *SweepResult) { r.Curves = nil }},
		{"short curve", func(r *SweepResult) {
			r.Curves[0].Points = r.Curves[0].Points[:1]
		}},
		{"size mismatch", func(r *SweepResult) {
			r.Curves[0].Points[1].BlockSize = 999
		}},
		{"zero throughput", func(r *SweepResult) {
			r.Curves[0].Points[0].MBps = 0
		}},
		{"no peak", func(r *SweepResult) {
			r.Curves[0].PeakMBps = 0
		}},
		{"no knee", func(r *SweepResult) {
			r.Curves[0].KneeSize = 0
		}},
		{"bad plateau", func(r *SweepResult) {
			r.Curves[0].PlateauMin = 0
		}},
		{"inverted plateau", func(r *SweepResult) {
			r.Curves[0].PlateauMin = 4096
			r.Curves[0].PlateauMax = 64
		}},
	}
	for _, c := range cases {
		mutated := SweepResult{Sizes: append([]int{}, base.Sizes...)}
		curve := good
		curve.Points = append([]SweepPoint{}, good.Points...)
		mutated.Curves = []SweepCurve{curve}
		c.mut(&mutated)
		if err := ValidateSweep(mutated); err == nil {
			t.Errorf("%s: validator accepted a malformed result", c.name)
		}
	}
}

// TestCrossoverPointDetectsACrossing checks the crossover helper on a synthetic
// pair: A is faster below 1024, B is faster above it.
func TestCrossoverPointDetectsACrossing(t *testing.T) {
	a := SweepCurve{Algorithm: "A", Points: []SweepPoint{
		{BlockSize: 64, MBps: 500},
		{BlockSize: 256, MBps: 500},
		{BlockSize: 1024, MBps: 500},
		{BlockSize: 4096, MBps: 500},
	}}
	b := SweepCurve{Algorithm: "B", Points: []SweepPoint{
		{BlockSize: 64, MBps: 100},
		{BlockSize: 256, MBps: 200},
		{BlockSize: 1024, MBps: 900},
		{BlockSize: 4096, MBps: 900},
	}}
	// A > B at 64 and 256; B > A at 1024. The crossing is reported as the last
	// size where the ordering still held.
	if got := CrossoverPoint(a, b); got != 256 {
		t.Errorf("crossover = %d, want 256", got)
	}

	// No crossing: A is always faster.
	if got := CrossoverPoint(a, a); got != 0 {
		t.Errorf("identical curves reported a crossover at %d", got)
	}

	// No crossing: A always wins over a much slower B.
	slow := SweepCurve{Points: []SweepPoint{
		{BlockSize: 64, MBps: 1},
		{BlockSize: 256, MBps: 1},
		{BlockSize: 1024, MBps: 1},
		{BlockSize: 4096, MBps: 1},
	}}
	if got := CrossoverPoint(a, slow); got != 0 {
		t.Errorf("dominated curve reported a crossover at %d", got)
	}
}

// TestSortCurvesOrdersByPeak checks the presentation order.
func TestSortCurvesOrdersByPeak(t *testing.T) {
	curves := []SweepCurve{
		{Algorithm: "slow", PeakMBps: 10},
		{Algorithm: "fast", PeakMBps: 1000},
		{Algorithm: "mid", PeakMBps: 100},
	}
	SortCurves(curves)
	want := []string{"fast", "mid", "slow"}
	for i, c := range curves {
		if c.Algorithm != want[i] {
			t.Errorf("position %d is %q, want %q", i, c.Algorithm, want[i])
		}
	}
}

// humanSizeStr mirrors main.humanSize for test logging. Keeping a copy here
// avoids exporting a formatting helper from the package for the sake of test
// output.
func humanSizeStr(n int) string {
	switch {
	case n >= 1024*1024:
		return itoa(n/(1024*1024)) + " MB"
	case n >= 1024:
		return itoa(n/1024) + " KB"
	default:
		return itoa(n) + " B"
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
