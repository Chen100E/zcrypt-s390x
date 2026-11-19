package cipher

// Performance regression detection.
//
// A benchmark that is only ever run by hand is a benchmark that silently rots:
// a compiler upgrade changes an inlining decision, a refactor adds an
// allocation on the hot path, and nobody notices until a customer does. This
// file makes the comparison mechanical.
//
// The design constraint that shapes everything below: CI runners are not the
// machine the baseline was measured on. GitHub's s390x runners do not exist, and
// even the amd64 runners are shared VMs whose throughput varies by a factor of
// two between runs. So:
//
//   - a baseline records the machine fingerprint alongside the numbers, and a
//     comparison against a different machine reports "not comparable" rather
//     than a false regression;
//   - the threshold is a band, not an equality check, and the default 20% is
//     wide enough to absorb runner noise;
//   - the check is advisory in CI (warn, do not fail) but strict when run
//     deliberately on the reference machine, because that is where a real
//     regression is meaningful.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// BaselineSchemaVersion is bumped when the baseline format changes in a way that
// makes older files incomparable. A reader that finds a different version
// refuses to compare rather than silently misinterpreting fields.
const BaselineSchemaVersion = 1

// BaselineMetric is one named throughput figure in a baseline.
type BaselineMetric struct {
	// Name is a stable identifier such as "aes256gcm.encrypt.1mib". It is the
	// join key between a baseline and a fresh measurement, so it must not change
	// when the human-readable label does.
	Name string `json:"name"`
	// MBps is the measured throughput.
	MBps float64 `json:"mbps"`
	// Unit is "MB/s" for throughput metrics and "ops/s" for signature rates.
	// Mixing units in one baseline is fine as long as the comparison respects
	// them, which it does by comparing ratios rather than absolute values.
	Unit string `json:"unit"`
	// HigherIsBetter is false for latency-style metrics. All current metrics are
	// throughput, but the field exists so a future latency figure cannot be
	// compared backwards.
	HigherIsBetter bool `json:"higher_is_better"`
}

// MachineFingerprint identifies the host a baseline was measured on. Two
// baselines are only comparable when these agree on the fields that affect
// throughput.
type MachineFingerprint struct {
	Arch        string `json:"arch"`
	MachineType string `json:"machine_type"`
	MaxMSALevel int    `json:"max_msa_level"`
	GoVersion   string `json:"go_version"`
	// Kernel is the running kernel release; scheduler and page-size changes move
	// throughput, so it is part of the identity.
	Kernel string `json:"kernel"`
}

// ComparableTo reports whether a measurement on other can be meaningfully
// compared with a baseline taken on b.
//
// Arch and MSA level are hard requirements: an amd64 measurement is not a
// regression against an s390x baseline, it is a different machine. Go version
// and kernel are reported as differences but do not block comparison, because a
// toolchain upgrade is exactly the kind of change that should be allowed to show
// up as a regression.
func (b MachineFingerprint) ComparableTo(other MachineFingerprint) (bool, string) {
	if b.Arch != other.Arch {
		return false, fmt.Sprintf("architecture differs: baseline %s, current %s", b.Arch, other.Arch)
	}
	if b.MaxMSALevel != other.MaxMSALevel {
		return false, fmt.Sprintf("MSA level differs: baseline MSA-%d, current MSA-%d",
			b.MaxMSALevel, other.MaxMSALevel)
	}
	if b.MachineType != "" && other.MachineType != "" && b.MachineType != other.MachineType {
		// A different machine type within the same architecture is still
		// comparable in direction but not in magnitude, so this is a warning
		// rather than a refusal.
		return true, fmt.Sprintf("machine type differs: baseline %s, current %s; "+
			"expect magnitude differences", b.MachineType, other.MachineType)
	}
	return true, ""
}

// Baseline is the on-disk form: a fingerprint, the metrics, and the context
// needed to interpret them.
type Baseline struct {
	SchemaVersion int                `json:"schema_version"`
	CapturedAt    string             `json:"captured_at"`
	Fingerprint   MachineFingerprint `json:"fingerprint"`
	Metrics       []BaselineMetric   `json:"metrics"`
	// Notes is free text explaining how the baseline was produced, so a reader
	// six months later knows whether it came from `zcrypt --baseline` or from a
	// hand-run benchmark.
	Notes string `json:"notes,omitempty"`
}

// Lookup returns the metric with the given name.
func (b Baseline) Lookup(name string) (BaselineMetric, bool) {
	for _, m := range b.Metrics {
		if m.Name == name {
			return m, true
		}
	}
	return BaselineMetric{}, false
}

// MetricNames returns the sorted metric names, for stable reporting.
func (b Baseline) MetricNames() []string {
	names := make([]string, 0, len(b.Metrics))
	for _, m := range b.Metrics {
		names = append(names, m.Name)
	}
	sort.Strings(names)
	return names
}

// Validate checks a baseline is internally consistent before it is written or
// used. A baseline with duplicate names or non-positive throughputs would make
// every comparison against it meaningless.
func (b Baseline) Validate() error {
	if b.SchemaVersion != BaselineSchemaVersion {
		return fmt.Errorf("baseline: schema version %d, this build understands %d",
			b.SchemaVersion, BaselineSchemaVersion)
	}
	if len(b.Metrics) == 0 {
		return errors.New("baseline: no metrics")
	}
	seen := make(map[string]bool, len(b.Metrics))
	for _, m := range b.Metrics {
		if m.Name == "" {
			return errors.New("baseline: metric with an empty name")
		}
		if seen[m.Name] {
			return fmt.Errorf("baseline: duplicate metric %q", m.Name)
		}
		seen[m.Name] = true
		if m.MBps <= 0 {
			return fmt.Errorf("baseline: metric %q has non-positive value %v", m.Name, m.MBps)
		}
		if m.Unit == "" {
			return fmt.Errorf("baseline: metric %q has no unit", m.Name)
		}
	}
	if b.Fingerprint.Arch == "" {
		return errors.New("baseline: no architecture fingerprint")
	}
	return nil
}

// ComparisonVerdict classifies one metric against its baseline.
type ComparisonVerdict string

const (
	// VerdictOK means the metric is within the tolerance band.
	VerdictOK ComparisonVerdict = "ok"
	// VerdictRegressed means throughput dropped by more than the tolerance.
	VerdictRegressed ComparisonVerdict = "regressed"
	// VerdictImproved means throughput rose by more than the tolerance.
	VerdictImproved ComparisonVerdict = "improved"
	// VerdictMissing means the metric exists in one side but not the other.
	VerdictMissing ComparisonVerdict = "missing"
	// VerdictSkipped means the metric could not be compared because the
	// machines are not comparable.
	VerdictSkipped ComparisonVerdict = "skipped"
)

// Comparison is one metric's outcome.
type Comparison struct {
	Name         string            `json:"name"`
	Baseline     float64           `json:"baseline"`
	Current      float64           `json:"current"`
	Unit         string            `json:"unit"`
	DeltaPct     float64           `json:"delta_pct"`
	Verdict      ComparisonVerdict `json:"verdict"`
	TolerancePct float64           `json:"tolerance_pct"`
	Note         string            `json:"note,omitempty"`
}

// ComparisonReport is the whole comparison.
type ComparisonReport struct {
	BaselineCapturedAt string             `json:"baseline_captured_at"`
	Fingerprint        MachineFingerprint `json:"fingerprint"`
	TolerancePct       float64            `json:"tolerance_pct"`
	Comparable         bool               `json:"comparable"`
	ComparableReason   string             `json:"comparable_reason,omitempty"`
	Results            []Comparison       `json:"results"`
	// Regressions is the count of VerdictRegressed rows, which is what the exit
	// status is derived from.
	Regressions int `json:"regressions"`
	// Improvements is reported so a change that speeds everything up is visible
	// rather than silently accepted.
	Improvements int `json:"improvements"`
	// Skipped is the count of rows that could not be compared.
	Skipped int `json:"skipped"`
}

// WorstDelta returns the most negative delta, which is the single number a CI
// log should surface.
func (r ComparisonReport) WorstDelta() float64 {
	worst := 0.0
	for _, c := range r.Results {
		if c.Verdict == VerdictMissing || c.Verdict == VerdictSkipped {
			continue
		}
		if c.DeltaPct < worst {
			worst = c.DeltaPct
		}
	}
	return worst
}

// Summary renders a one-line summary suitable for a CI log.
func (r ComparisonReport) Summary() string {
	if !r.Comparable {
		return fmt.Sprintf("not comparable: %s", r.ComparableReason)
	}
	return fmt.Sprintf("%d regressed, %d improved, %d skipped of %d metrics (tolerance %.0f%%, worst %+.1f%%)",
		r.Regressions, r.Improvements, r.Skipped, len(r.Results),
		r.TolerancePct, r.WorstDelta())
}

// CompareMetrics compares a fresh set of measurements against a baseline.
//
// The comparison is directional: a throughput drop beyond the tolerance is a
// regression, a rise beyond it is an improvement, and anything inside the band
// is noise. The band is symmetric around the baseline, so a 20% tolerance means
// "between 80% and 120% of baseline is acceptable".
//
// Metrics present in only one side are reported as missing rather than ignored,
// because a metric that disappeared from the harness is itself a finding.
func CompareMetrics(base Baseline, current []BaselineMetric, fp MachineFingerprint, tolerancePct float64) ComparisonReport {
	if tolerancePct <= 0 {
		tolerancePct = 20
	}
	rep := ComparisonReport{
		BaselineCapturedAt: base.CapturedAt,
		Fingerprint:        fp,
		TolerancePct:       tolerancePct,
	}

	comparable, reason := base.Fingerprint.ComparableTo(fp)
	rep.Comparable = comparable
	rep.ComparableReason = reason

	curByName := make(map[string]BaselineMetric, len(current))
	for _, m := range current {
		curByName[m.Name] = m
	}
	baseByName := make(map[string]BaselineMetric, len(base.Metrics))
	for _, m := range base.Metrics {
		baseByName[m.Name] = m
	}

	// Walk the union of names in sorted order so the output is stable.
	names := make([]string, 0, len(baseByName)+len(curByName))
	for n := range baseByName {
		names = append(names, n)
	}
	for n := range curByName {
		if _, ok := baseByName[n]; !ok {
			names = append(names, n)
		}
	}
	sort.Strings(names)

	for _, name := range names {
		b, inBase := baseByName[name]
		c, inCur := curByName[name]
		row := Comparison{Name: name, TolerancePct: tolerancePct}

		switch {
		case !inBase:
			row.Verdict = VerdictMissing
			row.Current = c.MBps
			row.Unit = c.Unit
			row.Note = "metric is new; no baseline to compare against"
			rep.Results = append(rep.Results, row)
			continue
		case !inCur:
			row.Verdict = VerdictMissing
			row.Baseline = b.MBps
			row.Unit = b.Unit
			row.Note = "metric is in the baseline but was not measured; did the harness change?"
			rep.Results = append(rep.Results, row)
			continue
		}

		row.Baseline = b.MBps
		row.Current = c.MBps
		row.Unit = b.Unit
		row.DeltaPct = (c.MBps - b.MBps) / b.MBps * 100

		if !comparable {
			row.Verdict = VerdictSkipped
			row.Note = reason
			rep.Skipped++
			rep.Results = append(rep.Results, row)
			continue
		}

		// A unit change makes the ratio meaningless even when both values are
		// positive, so it is reported rather than compared.
		if b.Unit != c.Unit {
			row.Verdict = VerdictSkipped
			row.Note = fmt.Sprintf("unit changed from %s to %s", b.Unit, c.Unit)
			rep.Skipped++
			rep.Results = append(rep.Results, row)
			continue
		}

		switch {
		case row.DeltaPct < -tolerancePct:
			row.Verdict = VerdictRegressed
			rep.Regressions++
		case row.DeltaPct > tolerancePct:
			row.Verdict = VerdictImproved
			rep.Improvements++
		default:
			row.Verdict = VerdictOK
		}
		rep.Results = append(rep.Results, row)
	}

	return rep
}

// BuildBaselineMetrics collects the metrics a baseline should contain.
//
// The set is deliberately small and stable: the largest-buffer figure for each
// primitive, plus the per-curve signature rates. Small-buffer figures are
// excluded on purpose because they are the noisiest rows and would make the
// regression check fire on scheduling jitter rather than on real changes.
func BuildBaselineMetrics(scale int) ([]BaselineMetric, error) {
	if scale <= 0 {
		scale = 1
	}
	var metrics []BaselineMetric

	// AES-256-GCM at 1 MiB, the sustained-throughput figure.
	if res, err := AESModeBenchmark(ModeGCM, 256, 1024*1024, 40*scale); err == nil {
		metrics = append(metrics,
			BaselineMetric{Name: "aes256gcm.encrypt.1mib", MBps: res.EncryptMBps, Unit: "MB/s", HigherIsBetter: true},
			BaselineMetric{Name: "aes256gcm.decrypt.1mib", MBps: res.DecryptMBps, Unit: "MB/s", HigherIsBetter: true},
		)
	} else {
		return nil, fmt.Errorf("baseline: aes256gcm 1 MiB: %w", err)
	}

	// CBC and CTR at 1 MiB, so a regression in either mode is attributable.
	for _, m := range []AESMode{ModeCBC, ModeCTR} {
		res, err := AESModeBenchmark(m, 256, 1024*1024, 40*scale)
		if err != nil {
			return nil, fmt.Errorf("baseline: aes256%s 1 MiB: %w", strings.ToLower(string(m)), err)
		}
		key := fmt.Sprintf("aes256%s.encrypt.1mib", strings.ToLower(string(m)))
		metrics = append(metrics,
			BaselineMetric{Name: key, MBps: res.EncryptMBps, Unit: "MB/s", HigherIsBetter: true})
	}

	// SHA-256 and SHA-512 at 1 MiB.
	sha256MBps, sha512MBps := BenchmarkDigest(1024*1024, 20*scale)
	metrics = append(metrics,
		BaselineMetric{Name: "sha256.1mib", MBps: sha256MBps, Unit: "MB/s", HigherIsBetter: true},
		BaselineMetric{Name: "sha512.1mib", MBps: sha512MBps, Unit: "MB/s", HigherIsBetter: true},
	)

	// SHA3-256 through the pure-Go sponge at 1 MiB.
	if r, err := BenchmarkSHA3(SHA3_256, 1024*1024, 20*scale); err == nil {
		metrics = append(metrics,
			BaselineMetric{Name: "sha3-256.purego.1mib", MBps: r.MBps, Unit: "MB/s", HigherIsBetter: true})
	}

	// Signature rates. These are operations per second, not bytes per second, so
	// they carry a different unit and the comparison treats the ratio the same
	// way.
	for _, info := range CurveTable {
		r, err := SignBenchmark(info.Curve, 40*scale)
		if err != nil {
			continue
		}
		slug := strings.ToLower(strings.ReplaceAll(string(info.Curve), "-", ""))
		metrics = append(metrics,
			BaselineMetric{Name: slug + ".sign", MBps: r.SignPerSec, Unit: "ops/s", HigherIsBetter: true},
			BaselineMetric{Name: slug + ".verify", MBps: r.VerifyPerSec, Unit: "ops/s", HigherIsBetter: true},
		)
	}

	if len(metrics) == 0 {
		return nil, errors.New("baseline: no metrics collected")
	}
	return metrics, nil
}

// WriteBaseline serialises a baseline to path atomically.
//
// The write goes to a temporary file in the same directory and is then renamed,
// so an interrupted run cannot leave a half-written baseline that the next
// comparison would read as corrupt.
func WriteBaseline(path string, b Baseline) error {
	if err := b.Validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return fmt.Errorf("baseline: marshal: %w", err)
	}
	data = append(data, '\n')

	dir := "."
	if i := strings.LastIndex(path, "/"); i >= 0 {
		dir = path[:i]
		if dir == "" {
			dir = "/"
		}
	}
	tmp, err := os.CreateTemp(dir, ".baseline-*.json")
	if err != nil {
		return fmt.Errorf("baseline: create temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		// Best effort: if the rename succeeded the file is gone and Remove fails
		// harmlessly.
		os.Remove(tmpName)
	}()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("baseline: write temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("baseline: close temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("baseline: rename into place: %w", err)
	}
	return nil
}

// ReadBaseline loads and validates a baseline from path.
func ReadBaseline(path string) (Baseline, error) {
	var b Baseline
	data, err := os.ReadFile(path)
	if err != nil {
		return b, fmt.Errorf("baseline: read %s: %w", path, err)
	}
	if err := json.Unmarshal(data, &b); err != nil {
		return b, fmt.Errorf("baseline: parse %s: %w", path, err)
	}
	if err := b.Validate(); err != nil {
		return b, fmt.Errorf("baseline: %s: %w", path, err)
	}
	return b, nil
}

// NewBaseline assembles a baseline from a fingerprint and a metric set.
func NewBaseline(fp MachineFingerprint, metrics []BaselineMetric, notes string) Baseline {
	return Baseline{
		SchemaVersion: BaselineSchemaVersion,
		CapturedAt:    time.Now().UTC().Format(time.RFC3339),
		Fingerprint:   fp,
		Metrics:       metrics,
		Notes:         notes,
	}
}
