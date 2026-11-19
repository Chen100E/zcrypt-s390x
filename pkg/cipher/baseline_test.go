package cipher

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Chen100E/zcrypt-s390x/pkg/cpacf"
)

// fpFor is a test fingerprint matching the reference machine.
func fpFor() MachineFingerprint {
	return MachineFingerprint{
		Arch:        "s390x",
		MachineType: "9175",
		MaxMSALevel: 13,
		GoVersion:   "go1.23.2",
		Kernel:      "6.8.0",
	}
}

// TestFingerprintComparability pins the rules: architecture and MSA level are
// hard requirements, machine type is a soft warning.
func TestFingerprintComparability(t *testing.T) {
	base := fpFor()

	cases := []struct {
		name       string
		other      MachineFingerprint
		wantOK     bool
		wantInNote string
	}{
		{"identical", base, true, ""},
		{
			name:   "different arch",
			other:  MachineFingerprint{Arch: "amd64", MachineType: "9175", MaxMSALevel: 13},
			wantOK: false, wantInNote: "architecture differs",
		},
		{
			name:   "different MSA",
			other:  MachineFingerprint{Arch: "s390x", MachineType: "9175", MaxMSALevel: 12},
			wantOK: false, wantInNote: "MSA level differs",
		},
		{
			name:   "different machine type",
			other:  MachineFingerprint{Arch: "s390x", MachineType: "8561", MaxMSALevel: 13},
			wantOK: true, wantInNote: "machine type differs",
		},
		{
			name:   "go version differs but still comparable",
			other:  MachineFingerprint{Arch: "s390x", MachineType: "9175", MaxMSALevel: 13, GoVersion: "go1.24.0"},
			wantOK: true, wantInNote: "",
		},
		{
			name:   "empty machine type is not a mismatch",
			other:  MachineFingerprint{Arch: "s390x", MaxMSALevel: 13},
			wantOK: true, wantInNote: "",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ok, note := base.ComparableTo(c.other)
			if ok != c.wantOK {
				t.Errorf("comparable = %v, want %v (note %q)", ok, c.wantOK, note)
			}
			if c.wantInNote != "" && !strings.Contains(note, c.wantInNote) {
				t.Errorf("note %q does not mention %q", note, c.wantInNote)
			}
		})
	}
}

// TestBaselineValidateCoversEachFault proves the validator rejects every way a
// baseline can be malformed, rather than only the first one it happens to check.
func TestBaselineValidateCoversEachFault(t *testing.T) {
	good := func() Baseline {
		return Baseline{
			SchemaVersion: BaselineSchemaVersion,
			Fingerprint:   fpFor(),
			Metrics: []BaselineMetric{
				{Name: "a", MBps: 100, Unit: "MB/s", HigherIsBetter: true},
				{Name: "b", MBps: 200, Unit: "MB/s", HigherIsBetter: true},
			},
		}
	}
	if err := good().Validate(); err != nil {
		t.Fatalf("valid baseline rejected: %v", err)
	}

	mutations := []struct {
		name string
		mut  func(*Baseline)
	}{
		{"wrong schema", func(b *Baseline) { b.SchemaVersion = 99 }},
		{"no metrics", func(b *Baseline) { b.Metrics = nil }},
		{"empty name", func(b *Baseline) { b.Metrics[0].Name = "" }},
		{"duplicate name", func(b *Baseline) { b.Metrics[1].Name = b.Metrics[0].Name }},
		{"zero value", func(b *Baseline) { b.Metrics[0].MBps = 0 }},
		{"negative value", func(b *Baseline) { b.Metrics[0].MBps = -1 }},
		{"no unit", func(b *Baseline) { b.Metrics[0].Unit = "" }},
		{"no arch", func(b *Baseline) { b.Fingerprint.Arch = "" }},
	}
	for _, m := range mutations {
		b := good()
		m.mut(&b)
		if err := b.Validate(); err == nil {
			t.Errorf("%s: validator accepted a malformed baseline", m.name)
		}
	}
}

// TestBaselineLookupAndNames covers the accessors.
func TestBaselineLookupAndNames(t *testing.T) {
	b := NewBaseline(fpFor(), []BaselineMetric{
		{Name: "zeta", MBps: 1, Unit: "MB/s", HigherIsBetter: true},
		{Name: "alpha", MBps: 2, Unit: "MB/s", HigherIsBetter: true},
		{Name: "mid", MBps: 3, Unit: "MB/s", HigherIsBetter: true},
	}, "test")

	if m, ok := b.Lookup("alpha"); !ok || m.MBps != 2 {
		t.Errorf("Lookup(alpha) = %+v, %v", m, ok)
	}
	if _, ok := b.Lookup("missing"); ok {
		t.Error("Lookup found a metric that is not present")
	}

	names := b.MetricNames()
	want := []string{"alpha", "mid", "zeta"}
	for i, n := range names {
		if n != want[i] {
			t.Errorf("names[%d] = %q, want %q", i, n, want[i])
		}
	}
}

// TestCompareMetricsClassifiesEveryCase exercises the classifier: regression,
// improvement, within tolerance, missing on each side, unit change, and a
// non-comparable machine.
func TestCompareMetricsClassifiesEveryCase(t *testing.T) {
	base := NewBaseline(fpFor(), []BaselineMetric{
		{Name: "stable", MBps: 1000, Unit: "MB/s", HigherIsBetter: true},
		{Name: "regressed", MBps: 1000, Unit: "MB/s", HigherIsBetter: true},
		{Name: "improved", MBps: 1000, Unit: "MB/s", HigherIsBetter: true},
		{Name: "unitchange", MBps: 1000, Unit: "MB/s", HigherIsBetter: true},
		{Name: "gone", MBps: 500, Unit: "MB/s", HigherIsBetter: true},
	}, "test")

	current := []BaselineMetric{
		{Name: "stable", MBps: 1050, Unit: "MB/s", HigherIsBetter: true},   // +5%, inside 20%
		{Name: "regressed", MBps: 600, Unit: "MB/s", HigherIsBetter: true}, // -40%
		{Name: "improved", MBps: 1500, Unit: "MB/s", HigherIsBetter: true}, // +50%
		{Name: "unitchange", MBps: 1000, Unit: "ops/s", HigherIsBetter: true},
		{Name: "brandnew", MBps: 42, Unit: "MB/s", HigherIsBetter: true},
	}

	rep := CompareMetrics(base, current, fpFor(), 20)
	if !rep.Comparable {
		t.Fatalf("identical fingerprints reported as not comparable: %s", rep.ComparableReason)
	}

	byName := map[string]Comparison{}
	for _, c := range rep.Results {
		byName[c.Name] = c
	}

	checks := []struct {
		name    string
		verdict ComparisonVerdict
	}{
		{"stable", VerdictOK},
		{"regressed", VerdictRegressed},
		{"improved", VerdictImproved},
		{"unitchange", VerdictSkipped},
		{"gone", VerdictMissing},
		{"brandnew", VerdictMissing},
	}
	for _, c := range checks {
		got, ok := byName[c.name]
		if !ok {
			t.Errorf("%s: absent from the report", c.name)
			continue
		}
		if got.Verdict != c.verdict {
			t.Errorf("%s: verdict = %q, want %q (delta %+.1f%%)",
				c.name, got.Verdict, c.verdict, got.DeltaPct)
		}
	}

	if rep.Regressions != 1 {
		t.Errorf("regressions = %d, want 1", rep.Regressions)
	}
	if rep.Improvements != 1 {
		t.Errorf("improvements = %d, want 1", rep.Improvements)
	}
	if rep.Skipped != 1 {
		t.Errorf("skipped = %d, want 1", rep.Skipped)
	}
	if len(rep.Results) != 6 {
		t.Errorf("results = %d, want 6 (the union of both sides)", len(rep.Results))
	}

	// The missing-on-each-side notes must say which side is missing.
	if !strings.Contains(byName["gone"].Note, "in the baseline but was not measured") {
		t.Errorf("gone note = %q", byName["gone"].Note)
	}
	if !strings.Contains(byName["brandnew"].Note, "no baseline") {
		t.Errorf("brandnew note = %q", byName["brandnew"].Note)
	}
}

// TestCompareMetricsToleranceBoundary checks the band is exclusive at the edges:
// exactly -20% with a 20% tolerance is still OK, just past it is a regression.
func TestCompareMetricsToleranceBoundary(t *testing.T) {
	base := NewBaseline(fpFor(), []BaselineMetric{
		{Name: "m", MBps: 1000, Unit: "MB/s", HigherIsBetter: true},
	}, "")

	cases := []struct {
		current float64
		want    ComparisonVerdict
	}{
		{800, VerdictOK},          // exactly -20%
		{799.9, VerdictRegressed}, // just past
		{1200, VerdictOK},         // exactly +20%
		{1200.1, VerdictImproved}, // just past
		{1000, VerdictOK},
	}
	for _, c := range cases {
		rep := CompareMetrics(base, []BaselineMetric{
			{Name: "m", MBps: c.current, Unit: "MB/s", HigherIsBetter: true},
		}, fpFor(), 20)
		if rep.Results[0].Verdict != c.want {
			t.Errorf("current %v (%+.2f%%): verdict = %q, want %q",
				c.current, rep.Results[0].DeltaPct, rep.Results[0].Verdict, c.want)
		}
	}
}

// TestCompareMetricsNonComparableMachine proves a different architecture is
// reported as skipped rather than as a catastrophic regression, which is what
// would otherwise happen when a CI runner is compared against an s390x baseline.
func TestCompareMetricsNonComparableMachine(t *testing.T) {
	base := NewBaseline(fpFor(), []BaselineMetric{
		{Name: "aes", MBps: 14000, Unit: "MB/s", HigherIsBetter: true},
	}, "")
	// An amd64 runner measures maybe 900 MB/s for the same metric.
	amd64 := MachineFingerprint{Arch: "amd64", MachineType: "", MaxMSALevel: 0}
	rep := CompareMetrics(base, []BaselineMetric{
		{Name: "aes", MBps: 900, Unit: "MB/s", HigherIsBetter: true},
	}, amd64, 20)

	if rep.Comparable {
		t.Fatal("amd64 was considered comparable to s390x")
	}
	if rep.Regressions != 0 {
		t.Errorf("regressions = %d, want 0 on a non-comparable machine", rep.Regressions)
	}
	if rep.Skipped != 1 {
		t.Errorf("skipped = %d, want 1", rep.Skipped)
	}
	if rep.Results[0].Verdict != VerdictSkipped {
		t.Errorf("verdict = %q, want skipped", rep.Results[0].Verdict)
	}
	if !strings.Contains(rep.Results[0].Note, "architecture differs") {
		t.Errorf("note = %q", rep.Results[0].Note)
	}
	// The delta is still computed, because it is useful context even when the
	// verdict is skipped.
	if rep.Results[0].DeltaPct > -90 {
		t.Errorf("delta = %+.1f%%, expected a large drop to be recorded", rep.Results[0].DeltaPct)
	}
}

// TestCompareMetricsDefaultTolerance checks a zero tolerance is replaced with 20
// rather than making everything a regression.
func TestCompareMetricsDefaultTolerance(t *testing.T) {
	base := NewBaseline(fpFor(), []BaselineMetric{
		{Name: "m", MBps: 1000, Unit: "MB/s", HigherIsBetter: true},
	}, "")
	rep := CompareMetrics(base, []BaselineMetric{
		{Name: "m", MBps: 900, Unit: "MB/s", HigherIsBetter: true},
	}, fpFor(), 0)
	if rep.TolerancePct != 20 {
		t.Errorf("tolerance = %v, want 20", rep.TolerancePct)
	}
	if rep.Results[0].Verdict != VerdictOK {
		t.Errorf("verdict = %q, want ok at -10%% with a 20%% tolerance", rep.Results[0].Verdict)
	}
}

// TestWorstDeltaAndSummary covers the reporting helpers.
func TestWorstDeltaAndSummary(t *testing.T) {
	base := NewBaseline(fpFor(), []BaselineMetric{
		{Name: "a", MBps: 1000, Unit: "MB/s", HigherIsBetter: true},
		{Name: "b", MBps: 1000, Unit: "MB/s", HigherIsBetter: true},
		{Name: "c", MBps: 1000, Unit: "MB/s", HigherIsBetter: true},
	}, "")
	rep := CompareMetrics(base, []BaselineMetric{
		{Name: "a", MBps: 500, Unit: "MB/s", HigherIsBetter: true},  // -50%
		{Name: "b", MBps: 700, Unit: "MB/s", HigherIsBetter: true},  // -30%
		{Name: "c", MBps: 2000, Unit: "MB/s", HigherIsBetter: true}, // +100%
	}, fpFor(), 20)

	if got := rep.WorstDelta(); got != -50 {
		t.Errorf("worst delta = %v, want -50", got)
	}
	summary := rep.Summary()
	if !strings.Contains(summary, "2 regressed") {
		t.Errorf("summary = %q, want it to mention 2 regressions", summary)
	}
	if !strings.Contains(summary, "1 improved") {
		t.Errorf("summary = %q, want it to mention 1 improvement", summary)
	}

	// A non-comparable report's summary must say so rather than reporting zeros.
	nc := CompareMetrics(base, nil, MachineFingerprint{Arch: "amd64"}, 20)
	if !strings.Contains(nc.Summary(), "not comparable") {
		t.Errorf("non-comparable summary = %q", nc.Summary())
	}
}

// TestBaselineRoundTrip writes and reads a baseline through the real filesystem
// helpers, which also exercises the atomic rename.
func TestBaselineRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")

	b := NewBaseline(fpFor(), []BaselineMetric{
		{Name: "aes256gcm.encrypt.1mib", MBps: 13931.4, Unit: "MB/s", HigherIsBetter: true},
		{Name: "sha256.1mib", MBps: 4196.1, Unit: "MB/s", HigherIsBetter: true},
		{Name: "p256.sign", MBps: 58625, Unit: "ops/s", HigherIsBetter: true},
	}, "round-trip test")

	if err := WriteBaseline(path, b); err != nil {
		t.Fatalf("write: %v", err)
	}

	// The file must be valid JSON and parseable by a generic reader, so a
	// non-Go consumer (the CI shell script) can read it.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read raw: %v", err)
	}
	var generic map[string]interface{}
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("file is not valid JSON: %v", err)
	}
	if _, ok := generic["schema_version"]; !ok {
		t.Error("no schema_version field")
	}
	if _, ok := generic["fingerprint"]; !ok {
		t.Error("no fingerprint field")
	}

	got, err := ReadBaseline(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got.SchemaVersion != b.SchemaVersion {
		t.Errorf("schema version = %d, want %d", got.SchemaVersion, b.SchemaVersion)
	}
	if len(got.Metrics) != len(b.Metrics) {
		t.Fatalf("metrics = %d, want %d", len(got.Metrics), len(b.Metrics))
	}
	for i := range b.Metrics {
		if got.Metrics[i] != b.Metrics[i] {
			t.Errorf("metric %d = %+v, want %+v", i, got.Metrics[i], b.Metrics[i])
		}
	}
	if got.Fingerprint != b.Fingerprint {
		t.Errorf("fingerprint = %+v, want %+v", got.Fingerprint, b.Fingerprint)
	}
	if got.Notes != b.Notes {
		t.Errorf("notes = %q, want %q", got.Notes, b.Notes)
	}
	if got.CapturedAt == "" {
		t.Error("captured_at is empty")
	}

	// The write must not leave a temp file behind.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".baseline-") {
			t.Errorf("temp file %q left behind", e.Name())
		}
	}
}

// TestWriteBaselineRejectsInvalid proves the writer validates before writing, so
// an invalid baseline never reaches disk.
func TestWriteBaselineRejectsInvalid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	bad := Baseline{SchemaVersion: BaselineSchemaVersion, Fingerprint: fpFor()}
	if err := WriteBaseline(path, bad); err == nil {
		t.Fatal("wrote a baseline with no metrics")
	}
	if _, err := os.Stat(path); err == nil {
		t.Error("an invalid baseline was written to disk")
	}
}

// TestReadBaselineRejectsGarbage covers the parse and validate failures.
func TestReadBaselineRejectsGarbage(t *testing.T) {
	dir := t.TempDir()

	// Not JSON.
	bad := filepath.Join(dir, "notjson.json")
	if err := os.WriteFile(bad, []byte("{this is not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadBaseline(bad); err == nil {
		t.Error("parsed invalid JSON")
	}

	// Valid JSON, invalid baseline.
	empty := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(empty, []byte(`{"schema_version":1,"metrics":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadBaseline(empty); err == nil {
		t.Error("accepted a baseline with no metrics")
	}

	// Missing file.
	if _, err := ReadBaseline(filepath.Join(dir, "nope.json")); err == nil {
		t.Error("read a file that does not exist")
	}
}

// TestBuildBaselineMetricsProducesRealNumbers runs the real collection and
// checks the metric set is complete and plausible.
func TestBuildBaselineMetricsProducesRealNumbers(t *testing.T) {
	if testing.Short() {
		t.Skip("baseline collection is slow; skipped under -short")
	}
	metrics, err := BuildBaselineMetrics(1)
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	byName := map[string]BaselineMetric{}
	for _, m := range metrics {
		byName[m.Name] = m
		if m.MBps <= 0 {
			t.Errorf("%s: non-positive value %v", m.Name, m.MBps)
		}
		if m.Unit != "MB/s" && m.Unit != "ops/s" {
			t.Errorf("%s: unexpected unit %q", m.Name, m.Unit)
		}
		if !m.HigherIsBetter {
			t.Errorf("%s: HigherIsBetter is false for a throughput metric", m.Name)
		}
	}

	// The documented metric set must be present.
	want := []string{
		"aes256gcm.encrypt.1mib",
		"aes256gcm.decrypt.1mib",
		"aes256cbc.encrypt.1mib",
		"aes256ctr.encrypt.1mib",
		"sha256.1mib",
		"sha512.1mib",
		"sha3-256.purego.1mib",
		"p256.sign", "p256.verify",
		"p384.sign", "p384.verify",
		"p521.sign", "p521.verify",
		"ed25519.sign", "ed25519.verify",
	}
	for _, n := range want {
		if _, ok := byName[n]; !ok {
			t.Errorf("missing metric %q", n)
		}
	}

	// A baseline built from these must validate, which is the property that
	// matters: the collection cannot produce something the writer would reject.
	b := NewBaseline(fpFor(), metrics, "test")
	if err := b.Validate(); err != nil {
		t.Fatalf("collected metrics produce an invalid baseline: %v", err)
	}
	t.Logf("collected %d metrics; aes256gcm.encrypt.1mib = %.0f MB/s",
		len(metrics), byName["aes256gcm.encrypt.1mib"].MBps)
}

// TestCompareAgainstOwnBaselineIsStable is the end-to-end self-check: a baseline
// compared against a fresh measurement of the same machine should show no
// regressions at a generous tolerance. This is what the CI job does, and if it
// fires here the tolerance or the metric set is wrong.
func TestCompareAgainstOwnBaselineIsStable(t *testing.T) {
	if testing.Short() {
		t.Skip("baseline comparison is slow; skipped under -short")
	}
	// Only meaningful on the reference platform. The 60% tolerance here exists to
	// absorb scheduler jitter on a machine that is otherwise idle; on a shared
	// amd64 CI runner running software AES-GCM, consecutive measurements of the
	// same code can legitimately differ by more than that, and a failure there
	// would be a false alarm about the comparison machinery rather than a real
	// finding.
	if !cpacf.Detect().HasCPACF {
		t.Skip("self-comparison stability is a reference-platform check; no CPACF here")
	}
	metrics, err := BuildBaselineMetrics(1)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	base := NewBaseline(fpFor(), metrics, "self-comparison")

	fresh, err := BuildBaselineMetrics(1)
	if err != nil {
		t.Fatalf("rebuild: %v", err)
	}

	// A 60% tolerance is used here because the point of the test is to prove the
	// machinery works, not to assert that a shared machine is quiet. Real use
	// runs at 20% on the reference machine.
	rep := CompareMetrics(base, fresh, fpFor(), 60)
	if !rep.Comparable {
		t.Fatalf("self-comparison not comparable: %s", rep.ComparableReason)
	}
	if rep.Regressions > 0 {
		for _, c := range rep.Results {
			if c.Verdict == VerdictRegressed {
				t.Logf("regressed beyond 60%%: %s %.0f -> %.0f (%+.1f%%)",
					c.Name, c.Baseline, c.Current, c.DeltaPct)
			}
		}
		t.Errorf("%d metrics regressed by more than 60%% against a fresh measurement of the same machine",
			rep.Regressions)
	}
	t.Logf("self-comparison: %s", rep.Summary())
}
