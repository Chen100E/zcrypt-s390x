package main

// Continuous monitoring mode and the machine-fingerprint plumbing it shares with
// the baseline machinery.
//
// `--watch <interval>` re-runs the benchmark loop on a timer and republishes the
// Prometheus metrics, so a dashboard shows the current state of the machine
// rather than whatever it was when the process started. Two modes:
//
//	zcrypt --serve :9110 --watch 60s   exporter with a self-refreshing collector
//	zcrypt --watch 60s                 console monitor, one line per tick
//
// The design point worth stating: the watch loop does not call the exporter's
// HTTP handler. It drives the same Collector the exporter uses, and the exporter
// serves whatever the Collector last produced. That way a slow benchmark cannot
// block a Prometheus scrape, and a scrape cannot trigger an unscheduled
// benchmark — the two concerns are decoupled by the collector's cache.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Chen100E/zcrypt-s390x/pkg/cipher"
	"github.com/Chen100E/zcrypt-s390x/pkg/cpacf"
	"github.com/Chen100E/zcrypt-s390x/pkg/exporter"
)

// watchTick is one iteration's observation. It is written as a JSON line so the
// console monitor can be piped into anything, and it carries the fields a
// dashboard would want rather than a formatted string.
type watchTick struct {
	Seq       int      `json:"seq"`
	Timestamp string   `json:"timestamp"`
	ElapsedMS int64    `json:"elapsed_ms"`
	AESGCMEnc float64  `json:"aes256gcm_encrypt_mbps"`
	SHA256    float64  `json:"sha256_mbps"`
	VectorsOK bool     `json:"nist_vectors_ok"`
	MSALevel  int      `json:"max_msa_level"`
	Error     string   `json:"error,omitempty"`
	Regressed []string `json:"regressed,omitempty"`
}

// watcher owns the timer loop and the baseline it compares against.
type watcher struct {
	interval time.Duration
	scale    int
	// collector is non-nil in exporter mode, where the loop's job is to refresh
	// the collector's cache rather than to print anything.
	collector *exporter.Collector
	// baseline is optional. When set, each tick is compared against it and any
	// regression is reported.
	baseline  *cipher.Baseline
	tolerance float64
	out       io.Writer
}

// run drives the watch loop until ctx is cancelled.
//
// The first tick fires immediately, because a monitor that waits a full interval
// before showing anything is useless for the first interval. Subsequent ticks
// are on a ticker, so the schedule does not drift when a benchmark takes longer
// than expected — a slow tick means the next one is skipped by the ticker rather
// than shifting the whole schedule.
func (w *watcher) run(ctx context.Context) error {
	if w.interval <= 0 {
		return fmt.Errorf("watch: interval must be positive, got %s", w.interval)
	}
	if w.out == nil {
		w.out = os.Stdout
	}
	if w.scale <= 0 {
		w.scale = 1
	}
	if w.tolerance <= 0 {
		w.tolerance = 20
	}

	// Immediate first tick.
	if err := w.tick(ctx, 0); err != nil {
		return err
	}

	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	seq := 0
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			seq++
			if err := w.tick(ctx, seq); err != nil {
				return err
			}
		}
	}
}

// tick performs one measurement and publishes it.
func (w *watcher) tick(ctx context.Context, seq int) error {
	// A tick that has been cancelled before it starts should not begin a
	// multi-hundred-millisecond benchmark.
	if err := ctx.Err(); err != nil {
		return nil
	}

	start := time.Now()
	t := watchTick{
		Seq:       seq,
		Timestamp: start.UTC().Format(time.RFC3339),
	}

	caps := cpacf.Detect()
	// Refine with the Query result so the reported MSA level matches what the
	// report path and the baseline fingerprint use. Detect() alone reports MSA-12
	// on this machine because MSA-13 has no STFLE bit.
	query := cpacf.ProbeQuery(caps)
	caps = cpacf.RefineWithQuery(caps, query)
	t.MSALevel = caps.MaxMSALevel

	// Correctness first: a monitor that reports throughput for a broken
	// primitive is worse than one that reports nothing.
	if _, err := cipher.VerifyAESGCMVectors(); err != nil {
		t.Error = "AES-GCM vector check: " + err.Error()
	} else if err := cipher.VerifyNISTVectors(); err != nil {
		t.Error = "SHA-2 vector check: " + err.Error()
	} else {
		t.VectorsOK = true
	}

	// Throughput.
	if res, err := cipher.AESModeBenchmark(cipher.ModeGCM, 256, 1024*1024, 40*w.scale); err != nil {
		t.Error = joinErr(t.Error, "aes-gcm: "+err.Error())
	} else {
		t.AESGCMEnc = res.EncryptMBps
	}
	if mbps, err := cipher.BenchmarkHash(newSHA256, 1024*1024, 20*w.scale); err != nil {
		t.Error = joinErr(t.Error, "sha256: "+err.Error())
	} else {
		t.SHA256 = mbps
	}

	// Refresh the exporter's cache so a scrape right after this tick sees the
	// fresh numbers. Collect() does its own benchmark when its cache is stale,
	// which is exactly the work we just did, so the cache is primed by calling
	// it once with the interval already expired.
	if w.collector != nil {
		_ = w.collector.Collect()
	}

	// Baseline comparison.
	if w.baseline != nil && t.VectorsOK {
		fp := machineFingerprint(caps)
		current := []cipher.BaselineMetric{
			{Name: "aes256gcm.encrypt.1mib", MBps: t.AESGCMEnc, Unit: "MB/s", HigherIsBetter: true},
			{Name: "sha256.1mib", MBps: t.SHA256, Unit: "MB/s", HigherIsBetter: true},
		}
		rep := cipher.CompareMetrics(*w.baseline, current, fp, w.tolerance)
		for _, c := range rep.Results {
			if c.Verdict == cipher.VerdictRegressed {
				t.Regressed = append(t.Regressed,
					fmt.Sprintf("%s %.0f -> %.0f (%+.1f%%)", c.Name, c.Baseline, c.Current, c.DeltaPct))
			}
		}
	}

	t.ElapsedMS = time.Since(start).Milliseconds()

	// Emit. In exporter mode a tick is silent unless something is wrong, because
	// the metrics endpoint is the output.
	if w.collector != nil {
		if t.Error != "" || len(t.Regressed) > 0 {
			line, _ := json.Marshal(t)
			fmt.Fprintln(w.out, string(line))
		}
		return nil
	}

	line, err := json.Marshal(t)
	if err != nil {
		return fmt.Errorf("watch: marshal tick: %w", err)
	}
	fmt.Fprintln(w.out, string(line))
	return nil
}

// joinErr appends a message to a possibly-empty error string, so one tick can
// report several independent failures rather than only the last.
func joinErr(existing, add string) string {
	if existing == "" {
		return add
	}
	return existing + "; " + add
}

// machineFingerprint builds the comparability identity for a host.
//
// It refines the capability set with the CPACF Query result before reading the
// MSA level, because Detect() alone only knows what STFLE announced. Several MSA
// levels (1, 2, 6, 7, 10, 11, 13) have no STFLE bit, so an unrefined Detect()
// reports MSA-12 on this machine while the Query-refined value is MSA-13. That
// difference matters: MaxMSALevel is one of the hard comparability requirements,
// so an unrefined fingerprint would declare every measurement incomparable with a
// baseline captured by the report path.
func machineFingerprint(caps cpacf.HardwareCapabilities) cipher.MachineFingerprint {
	query := cpacf.ProbeQuery(caps)
	caps = cpacf.RefineWithQuery(caps, query)
	return cipher.MachineFingerprint{
		Arch:        caps.Arch,
		MachineType: caps.MachineType,
		MaxMSALevel: caps.MaxMSALevel,
		GoVersion:   goVersion(),
		Kernel:      kernelRelease(),
	}
}

// goVersion returns the toolchain version without importing runtime for one
// string; runtime.Version is the same value the build stamped.
func goVersion() string {
	// runtime.Version() is the honest source. Declared here as a variable so a
	// test can substitute a fixed value if it ever needs to.
	return runtimeVersion()
}

// parseWatchInterval accepts either a Go duration ("60s", "5m") or a bare
// integer, which is read as seconds. A bare number is what a user types when
// they mean seconds, and rejecting it would be pedantic.
func parseWatchInterval(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("watch: empty interval")
	}
	if d, err := time.ParseDuration(s); err == nil {
		if d <= 0 {
			return 0, fmt.Errorf("watch: interval must be positive, got %s", d)
		}
		return d, nil
	}
	// A bare integer is read as seconds. strconv.Atoi is used rather than
	// fmt.Sscanf("%d") because Sscanf accepts a numeric prefix and ignores
	// trailing garbage, so "1x" would parse as 1 second instead of being
	// rejected as a typo.
	if secs, err := strconv.Atoi(s); err == nil {
		if secs <= 0 {
			return 0, fmt.Errorf("watch: interval must be positive, got %d seconds", secs)
		}
		return time.Duration(secs) * time.Second, nil
	}
	return 0, fmt.Errorf("watch: cannot parse interval %q (use 60s or 60)", s)
}
