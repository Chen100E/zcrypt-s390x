package cipher

// Buffer-size sweep: the throughput curve rather than three sample points.
//
// The original suite measured 1 KiB, 64 KiB and 1 MiB. Three points cannot show
// where a primitive's throughput turns over, and on a mainframe the answer is
// not obvious: CPACF processes a buffer in fixed-size chunks under the covers,
// so there is a per-call setup cost that dominates small buffers, a plateau once
// the instruction is saturated, and — on some primitives — a decline at large
// sizes as the working set stops fitting in the L1/L2 the assembler is tuned
// for.
//
// This file sweeps a geometric ladder from 64 B to 4 MiB, finds the knee (the
// smallest buffer that reaches a given fraction of peak), and reports the curve
// so the knee can be read rather than guessed.

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"sort"
	"time"
)

// SweepSizes is the buffer ladder. The steps are powers of four so the curve has
// roughly even spacing on a log axis: 64 B, 256 B, 1 KiB, 4 KiB, 16 KiB, 64 KiB,
// 256 KiB, 1 MiB, 4 MiB.
var SweepSizes = []int{
	64,
	256,
	1024,
	4 * 1024,
	16 * 1024,
	64 * 1024,
	256 * 1024,
	1024 * 1024,
	4 * 1024 * 1024,
}

// SweepPoint is one (algorithm, buffer size) measurement.
type SweepPoint struct {
	Algorithm  string  `json:"algorithm"`
	BlockSize  int     `json:"block_size"`
	MBps       float64 `json:"mbps"`
	Iterations int     `json:"iterations"`
	NanosTotal int64   `json:"nanos_total"`
	Error      string  `json:"error,omitempty"`
}

// SweepCurve is one algorithm's throughput across the ladder.
type SweepCurve struct {
	Algorithm string       `json:"algorithm"`
	Points    []SweepPoint `json:"points"`
	// PeakMBps is the best throughput seen, and PeakSize the buffer size where
	// it occurred.
	PeakMBps float64 `json:"peak_mbps"`
	PeakSize int     `json:"peak_size"`
	// KneeSize is the smallest buffer that reaches KneeFraction of the peak.
	// It is the number that matters operationally: a caller whose messages are
	// below the knee pays per-call setup for every message.
	KneeSize     int     `json:"knee_size"`
	KneeFraction float64 `json:"knee_fraction"`
	// PlateauMin and PlateauMax bracket the contiguous range of buffer sizes
	// that reach KneeFraction of peak. A single knee point is unstable when the
	// plateau is broad — on this machine AES-GCM reaches 90% of peak anywhere
	// from 4 KiB to 64 KiB depending on scheduling — so the range is reported
	// alongside it and is the more trustworthy figure.
	PlateauMin int `json:"plateau_min"`
	PlateauMax int `json:"plateau_max"`
	// FirstMBps and LastMBps bracket the curve so a reader can see the shape
	// without reading every point.
	FirstMBps float64 `json:"first_mbps"`
	LastMBps  float64 `json:"last_mbps"`
	// DeclinePercent is how much throughput fell from peak to the largest
	// buffer, as a percentage. Negative means it improved.
	DeclinePercent float64 `json:"decline_percent"`
}

// sweepTargetNanos is the wall-clock budget per measurement point.
//
// 40 ms is long enough that timer noise and scheduling jitter are well below the
// measured interval, and short enough that a nine-point sweep of three
// algorithms finishes in about a second. It is a budget rather than an iteration
// count because the right count depends on the primitive: 4 MiB of AES-GCM and
// 4 MiB of pure-Go SHA3-256 differ by two orders of magnitude in cost, so any
// fixed ladder of iteration counts is wrong for one of them.
const sweepTargetNanos = 40 * 1000 * 1000

// calibrationIterations is how many passes the calibration run makes. Three is
// enough to average out a cold first call (page faults on the freshly allocated
// buffer, branch predictor warm-up) without spending measurable time.
const calibrationIterations = 3

// iterationBounds clamp the calibrated count. The lower bound keeps a single
// enormous buffer from being measured once, which would be dominated by page
// faults; the upper bound keeps a tiny buffer from spinning for seconds on a
// machine where the primitive is unexpectedly slow.
const (
	minSweepIterations = 3
	maxSweepIterations = 500000
)

// calibrateIterations runs the operation a few times to learn its per-call cost,
// then returns the iteration count that should take about sweepTargetNanos.
//
// The measured cost is used directly rather than estimated from the buffer size,
// because per-call overhead is the dominant term at small sizes and is entirely
// primitive-specific: a 64-byte AES-GCM seal and a 64-byte SHA-256 digest differ
// by more than an order of magnitude even though both touch one block.
//
// probe is called with the candidate iteration count and must return the elapsed
// time. Returning an error aborts the calibration.
func calibrateIterations(probe func(iters int) (time.Duration, error)) (int, error) {
	calDur, err := probe(calibrationIterations)
	if err != nil {
		return 0, err
	}
	if calDur <= 0 {
		// A sub-nanosecond result means the timer resolution is coarser than the
		// operation; fall back to the maximum count and let the real measurement
		// sort it out.
		return maxSweepIterations, nil
	}

	perIter := float64(calDur.Nanoseconds()) / float64(calibrationIterations)
	iters := int(float64(sweepTargetNanos) / perIter)
	if iters < minSweepIterations {
		iters = minSweepIterations
	}
	if iters > maxSweepIterations {
		iters = maxSweepIterations
	}
	return iters, nil
}

// SweepAESGCM measures AES-256-GCM encrypt throughput across the ladder.
//
// The encrypt direction is used for the curve because it is the operation a
// sender performs; the decrypt direction is reported separately by the mode
// comparison, and putting both on one curve would double the sweep time for a
// shape that is nearly identical.
//
// Each point is calibrated before it is measured: the harness runs the operation
// three times to learn its cost, then picks an iteration count that takes about
// 40 ms. A fixed ladder of counts cannot work here, because a 4 MiB seal is four
// orders of magnitude more expensive than a 64 B one and the two primitives
// differ by another two.
func SweepAESGCM(keyBits int, scale int) SweepCurve {
	curve := SweepCurve{Algorithm: fmt.Sprintf("AES-%d-GCM (encrypt)", keyBits), KneeFraction: 0.9}
	if scale <= 0 {
		scale = 1
	}

	for _, size := range SweepSizes {
		p := SweepPoint{Algorithm: curve.Algorithm, BlockSize: size}
		iters, err := calibrateIterations(func(n int) (time.Duration, error) {
			t0 := time.Now()
			if _, err := AESModeBenchmark(ModeGCM, keyBits, size, n); err != nil {
				return 0, err
			}
			return time.Since(t0), nil
		})
		if err != nil {
			p.Error = err.Error()
			curve.Points = append(curve.Points, p)
			continue
		}
		iters *= scale
		res, err := AESModeBenchmark(ModeGCM, keyBits, size, iters)
		if err != nil {
			p.Error = err.Error()
			curve.Points = append(curve.Points, p)
			continue
		}
		p.MBps = res.EncryptMBps
		p.Iterations = iters
		p.NanosTotal = res.EncryptNanos
		curve.Points = append(curve.Points, p)
	}
	finalizeCurve(&curve)
	return curve
}

// SweepSHA256 measures SHA-256 across the ladder.
func SweepSHA256(scale int) SweepCurve {
	curve := SweepCurve{Algorithm: "SHA-256", KneeFraction: 0.9}
	if scale <= 0 {
		scale = 1
	}
	newHash := func() hash.Hash { return sha256.New() }

	for _, size := range SweepSizes {
		p := SweepPoint{Algorithm: curve.Algorithm, BlockSize: size}
		iters, err := calibrateIterations(func(n int) (time.Duration, error) {
			t0 := time.Now()
			if _, err := BenchmarkHash(newHash, size, n); err != nil {
				return 0, err
			}
			return time.Since(t0), nil
		})
		if err != nil {
			p.Error = err.Error()
			curve.Points = append(curve.Points, p)
			continue
		}
		iters *= scale
		mbps, err := BenchmarkHash(newHash, size, iters)
		if err != nil {
			p.Error = err.Error()
			curve.Points = append(curve.Points, p)
			continue
		}
		p.MBps = mbps
		p.Iterations = iters
		curve.Points = append(curve.Points, p)
	}
	finalizeCurve(&curve)
	return curve
}

// SweepSHA3 measures one SHA-3 variant across the ladder, through the pure-Go
// sponge. The hardware path is not swept because AF_ALG's per-call socket cost
// would dominate every point below 64 KiB and the curve would measure the
// syscall boundary rather than the hash.
func SweepSHA3(v SHA3Variant, scale int) SweepCurve {
	curve := SweepCurve{Algorithm: v.String(), KneeFraction: 0.9}
	if scale <= 0 {
		scale = 1
	}
	newHash := func() hash.Hash { return NewSHA3(v) }

	for _, size := range SweepSizes {
		p := SweepPoint{Algorithm: curve.Algorithm, BlockSize: size}
		iters, err := calibrateIterations(func(n int) (time.Duration, error) {
			t0 := time.Now()
			if _, err := BenchmarkHash(newHash, size, n); err != nil {
				return 0, err
			}
			return time.Since(t0), nil
		})
		if err != nil {
			p.Error = err.Error()
			curve.Points = append(curve.Points, p)
			continue
		}
		iters *= scale
		mbps, err := BenchmarkHash(newHash, size, iters)
		if err != nil {
			p.Error = err.Error()
			curve.Points = append(curve.Points, p)
			continue
		}
		p.MBps = mbps
		p.Iterations = iters
		curve.Points = append(curve.Points, p)
	}
	finalizeCurve(&curve)
	return curve
}

// finalizeCurve fills in the derived fields: peak, knee, endpoints, decline.
func finalizeCurve(c *SweepCurve) {
	var valid []SweepPoint
	for _, p := range c.Points {
		if p.Error == "" && p.MBps > 0 {
			valid = append(valid, p)
		}
	}
	if len(valid) == 0 {
		return
	}

	c.PeakMBps = valid[0].MBps
	c.PeakSize = valid[0].BlockSize
	for _, p := range valid {
		if p.MBps > c.PeakMBps {
			c.PeakMBps = p.MBps
			c.PeakSize = p.BlockSize
		}
	}

	c.FirstMBps = valid[0].MBps
	c.LastMBps = valid[len(valid)-1].MBps
	if c.PeakMBps > 0 {
		c.DeclinePercent = (c.PeakMBps - c.LastMBps) / c.PeakMBps * 100
	}

	// The knee is the smallest buffer that reaches KneeFraction of peak. Points
	// are already in ascending size order, so the first qualifying point wins.
	if c.KneeFraction <= 0 {
		c.KneeFraction = 0.9
	}
	threshold := c.PeakMBps * c.KneeFraction
	c.KneeSize = 0
	c.PlateauMin = 0
	c.PlateauMax = 0
	for _, p := range valid {
		if p.MBps < threshold {
			continue
		}
		if c.KneeSize == 0 {
			c.KneeSize = p.BlockSize
			c.PlateauMin = p.BlockSize
		}
		c.PlateauMax = p.BlockSize
	}
	if c.KneeSize == 0 {
		// Nothing reached the threshold, which can only happen if the peak
		// itself is invalid; fall back to the peak size so the field is usable.
		c.KneeSize = c.PeakSize
		c.PlateauMin = c.PeakSize
		c.PlateauMax = c.PeakSize
	}
}

// SweepResult bundles every curve so one call produces the whole document.
type SweepResult struct {
	Sizes   []int        `json:"sizes"`
	Curves  []SweepCurve `json:"curves"`
	Scale   int          `json:"scale"`
	Elapsed string       `json:"elapsed"`
}

// RunSweep executes the full ladder for AES-GCM, SHA-256 and SHA3-256.
//
// Three algorithms is enough to characterise the machine: one block cipher with
// an authenticated mode, one Merkle-Damgard hash and one sponge. Adding more
// would lengthen the document without changing the shape of any curve.
func RunSweep(scale int) SweepResult {
	if scale <= 0 {
		scale = 1
	}
	t0 := time.Now()
	res := SweepResult{Sizes: SweepSizes, Scale: scale}
	res.Curves = append(res.Curves,
		SweepAESGCM(256, scale),
		SweepSHA256(scale),
		SweepSHA3(SHA3_256, scale),
	)
	res.Elapsed = time.Since(t0).Round(time.Millisecond).String()
	return res
}

// CrossoverPoint returns the buffer size at which algorithm b overtakes a, or 0
// when they do not cross within the ladder.
//
// This is the question the sweep exists to answer for a caller choosing between
// primitives: below the crossover one wins, above it the other does.
func CrossoverPoint(a, b SweepCurve) int {
	bySizeA := map[int]float64{}
	for _, p := range a.Points {
		if p.Error == "" {
			bySizeA[p.BlockSize] = p.MBps
		}
	}
	prevSign := 0
	prevSize := 0
	for _, p := range b.Points {
		if p.Error != "" {
			continue
		}
		av, ok := bySizeA[p.BlockSize]
		if !ok {
			continue
		}
		sign := 0
		switch {
		case av > p.MBps:
			sign = 1
		case av < p.MBps:
			sign = -1
		}
		if prevSign != 0 && sign != 0 && sign != prevSign {
			return prevSize
		}
		if sign != 0 {
			prevSign = sign
			prevSize = p.BlockSize
		}
	}
	return 0
}

// SortCurves orders curves by peak throughput, fastest first, which is the order
// the report should present them in.
func SortCurves(curves []SweepCurve) {
	sort.SliceStable(curves, func(i, j int) bool {
		return curves[i].PeakMBps > curves[j].PeakMBps
	})
}

// ValidateSweep checks a sweep result is internally consistent. It is used by
// the tests and by the report generator so a malformed document cannot be
// committed.
func ValidateSweep(r SweepResult) error {
	if len(r.Sizes) == 0 {
		return errors.New("sweep: no sizes")
	}
	if len(r.Curves) == 0 {
		return errors.New("sweep: no curves")
	}
	for _, c := range r.Curves {
		if len(c.Points) != len(r.Sizes) {
			return fmt.Errorf("sweep: curve %q has %d points, want %d",
				c.Algorithm, len(c.Points), len(r.Sizes))
		}
		for i, p := range c.Points {
			if p.BlockSize != r.Sizes[i] {
				return fmt.Errorf("sweep: curve %q point %d is size %d, want %d",
					c.Algorithm, i, p.BlockSize, r.Sizes[i])
			}
			if p.Error == "" && p.MBps <= 0 {
				return fmt.Errorf("sweep: curve %q size %d has non-positive throughput",
					c.Algorithm, p.BlockSize)
			}
		}
		if c.PeakMBps <= 0 {
			return fmt.Errorf("sweep: curve %q has no peak", c.Algorithm)
		}
		if c.KneeSize <= 0 {
			return fmt.Errorf("sweep: curve %q has no knee", c.Algorithm)
		}
		if c.PlateauMin <= 0 || c.PlateauMax < c.PlateauMin {
			return fmt.Errorf("sweep: curve %q has an invalid plateau %d..%d",
				c.Algorithm, c.PlateauMin, c.PlateauMax)
		}
	}
	return nil
}
