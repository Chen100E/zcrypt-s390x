package cpacf

import (
	"strings"
	"testing"
)

// sampleProcCrypto is a trimmed copy of the real /proc/crypto on the LinuxONE
// host, including both the CPACF ("-s390") and the portable ("-generic")
// registrations of the same algorithm name so that priority election is
// exercised.
const sampleProcCrypto = `name         : aes
driver       : aes-s390
module       : aes_s390
priority     : 300
refcnt       : 1
selftest     : passed
internal     : no
type         : cipher
async        : no

name         : aes
driver       : aes-generic
module       : kernel
priority     : 100
refcnt       : 1
selftest     : passed
internal     : no
type         : cipher
async        : no

name         : gcm(aes)
driver       : gcm-aes-s390
module       : gcm
priority     : 900
refcnt       : 1
selftest     : passed
internal     : no
type         : aead
async        : no

name         : ghash
driver       : ghash-s390
module       : ghash_s390
priority     : 300
refcnt       : 1
selftest     : passed
internal     : no
type         : shash
async        : no

name         : ghash
driver       : ghash-generic
module       : kernel
priority     : 100
refcnt       : 1
selftest     : passed
internal     : no
type         : shash
async        : no

name         : sha256
driver       : sha256-s390
module       : sha256_s390
priority     : 300
refcnt       : 1
selftest     : passed
internal     : no
type         : shash
async        : no

name         : crc32c
driver       : crc32c-vx
module       : crc32c_vx
priority     : 200
refcnt       : 1
selftest     : passed
internal     : no
type         : shash
async        : no

name         : stdrng
driver       : drbg_nopr_hmac_sha256
module       : drbg
priority     : 220
refcnt       : 1
selftest     : passed
internal     : no
type         : rng
async        : no
`

func TestParseKernelCryptoPriorityElection(t *testing.T) {
	rep := ParseKernelCrypto(strings.NewReader(sampleProcCrypto))
	if !rep.Available {
		t.Fatal("report must be Available for a readable stream")
	}

	// "aes" is registered twice; the priority-300 s390 driver must win.
	aes, ok := rep.Lookup("aes")
	if !ok {
		t.Fatal("aes missing from the report")
	}
	if aes.Driver != "aes-s390" {
		t.Errorf("aes driver = %q, want aes-s390 (highest priority)", aes.Driver)
	}
	if aes.Priority != 300 {
		t.Errorf("aes priority = %d, want 300", aes.Priority)
	}
	if !aes.Hardware {
		t.Error("aes-s390 must be classified as hardware")
	}
	if len(aes.Alternatives) != 2 {
		t.Errorf("aes alternatives = %v, want both drivers", aes.Alternatives)
	} else if aes.Alternatives[0] != "aes-s390" {
		t.Errorf("alternatives not sorted by priority: %v", aes.Alternatives)
	}

	// ghash: the s390 driver wins over generic.
	ghash, ok := rep.Lookup("ghash")
	if !ok {
		t.Fatal("ghash missing from the report")
	}
	if ghash.Driver != "ghash-s390" || !ghash.Hardware {
		t.Errorf("ghash = %q hardware=%v, want ghash-s390 hardware=true",
			ghash.Driver, ghash.Hardware)
	}

	// gcm(aes) is the strongest single piece of evidence: priority 900 aead.
	gcm, ok := rep.Lookup("gcm(aes)")
	if !ok {
		t.Fatal("gcm(aes) missing from the report")
	}
	if gcm.Driver != "gcm-aes-s390" || gcm.Priority != 900 {
		t.Errorf("gcm(aes) = %q/%d, want gcm-aes-s390/900", gcm.Driver, gcm.Priority)
	}
	if gcm.Type != "aead" {
		t.Errorf("gcm(aes) type = %q, want aead", gcm.Type)
	}

	// crc32c-vx is vector hardware, not CPACF, but still not generic C.
	crc, ok := rep.Lookup("crc32c")
	if !ok {
		t.Fatal("crc32c missing from the report")
	}
	if !crc.Hardware {
		t.Error("crc32c-vx must be classified as hardware")
	}

	// drbg is neither s390 nor -vx, so it must stay software.
	rng, ok := rep.Lookup("stdrng")
	if !ok {
		t.Fatal("stdrng missing from the report")
	}
	if rng.Hardware {
		t.Error("drbg_nopr_hmac_sha256 must not be classified as hardware")
	}

	if rep.TotalCount != 6 {
		t.Errorf("TotalCount = %d, want 6 distinct algorithm names", rep.TotalCount)
	}
	if rep.HardwareCount != 5 {
		t.Errorf("HardwareCount = %d, want 5 (aes, gcm, ghash, sha256, crc32c)",
			rep.HardwareCount)
	}
}

func TestParseKernelCryptoEmpty(t *testing.T) {
	rep := ParseKernelCrypto(strings.NewReader(""))
	if !rep.Available {
		t.Error("an empty but readable stream is still Available")
	}
	if rep.TotalCount != 0 || len(rep.Algorithms) != 0 {
		t.Errorf("empty stream produced %d algorithms", rep.TotalCount)
	}
}

func TestParseKernelCryptoNilReader(t *testing.T) {
	rep := ParseKernelCrypto(nil)
	if rep.Available {
		t.Error("a nil reader must not report Available")
	}
	if rep.Error == "" {
		t.Error("a nil reader must report an Error")
	}
}

// TestParseKernelCryptoToleratesUnknownFields makes sure a newer kernel adding
// keys does not break the parser.
func TestParseKernelCryptoToleratesUnknownFields(t *testing.T) {
	const in = `name         : sha3-256
driver       : sha3-256-s390
priority     : 300
type         : shash
blocksize    : 64
digestsize   : 32
some_new_key : some_new_value
walk         : yes
`
	rep := ParseKernelCrypto(strings.NewReader(in))
	a, ok := rep.Lookup("sha3-256")
	if !ok {
		t.Fatal("sha3-256 missing despite unknown fields present")
	}
	if a.Driver != "sha3-256-s390" || a.Priority != 300 || a.Type != "shash" {
		t.Errorf("parsed %+v, want sha3-256-s390/300/shash", a)
	}
}

func TestIsHardwareDriver(t *testing.T) {
	cases := []struct {
		driver string
		want   bool
	}{
		{"aes-s390", true},
		{"gcm-aes-s390", true},
		{"cbc-aes-s390", true},
		{"sha3-256-s390", true},
		{"crc32-vx", true},
		{"crc32be-vx", true},
		{"aes-generic", false},
		{"sha256-generic", false},
		{"kernel", false},
		{"drbg_nopr_hmac_sha256", false},
		{"pkcs1pad(rsa-generic,sha512)", false},
		{"", false},
	}
	for _, c := range cases {
		if got := isHardwareDriver(c.driver); got != c.want {
			t.Errorf("isHardwareDriver(%q) = %v, want %v", c.driver, got, c.want)
		}
	}
}

func TestHardwareAlgorithmsRestriction(t *testing.T) {
	rep := ParseKernelCrypto(strings.NewReader(sampleProcCrypto))

	all := rep.HardwareAlgorithms(false)
	restricted := rep.HardwareAlgorithms(true)

	if len(all) < len(restricted) {
		t.Fatalf("restricted list (%d) is longer than the full list (%d)",
			len(restricted), len(all))
	}
	want := map[string]bool{
		"aes": true, "gcm(aes)": true, "ghash": true, "sha256": true,
	}
	for _, a := range restricted {
		if !want[a.Name] {
			t.Errorf("restricted list contains %q, which is not in InterestingAlgorithms", a.Name)
		}
		if !a.Hardware {
			t.Errorf("restricted list contains %q, which is not hardware", a.Name)
		}
	}
	if len(restricted) != len(want) {
		t.Errorf("restricted list has %d entries, want %d", len(restricted), len(want))
	}
}

func TestKernelCryptoLookupMissing(t *testing.T) {
	rep := ParseKernelCrypto(strings.NewReader(sampleProcCrypto))
	if _, ok := rep.Lookup("no-such-algorithm"); ok {
		t.Error("Lookup found an algorithm that was never registered")
	}
}
