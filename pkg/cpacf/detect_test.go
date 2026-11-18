package cpacf

import (
	"strings"
	"testing"
)

// sampleCPUInfo mirrors the shape of /proc/cpuinfo on a LinuxONE host: the
// "features" line carries only the single token "msa", while the real MSA
// extension levels live as STFLE bit numbers on the "facilities" line.
const sampleCPUInfo = `vendor_id       : IBM/S390
# processors    : 2
bogomips per cpu: 28901.00
features	: esan3 zarch stfle msa ldisp eimm dfp edat etf3eh highgprs te vx vxd vxe gs vxe2 vxp sort dflt vxp2 nnpa sie
facilities      : 0 1 2 3 4 6 7 8 9 12 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 30 31 32 33 34 35 36 37 38 40 41 42 43 44 45 46 47 48 49 50 51 52 53 54 55 57 58 59 60 61 69 70 71 72 73 74 75 76 77 80 81 82 84 85 86 87 129 130 131 133 134 135 146 147 148 150 151 152 155 156 165 168 170 192 193 194 196 197 198 199 200 201
processor 0: version = FF,  identification = 09DFD8,  machine = 9175
machine         : 9175
`

func TestDetectFromFullFacilityList(t *testing.T) {
	caps := DetectFrom(strings.NewReader(sampleCPUInfo))

	if !caps.HasCPACF {
		t.Fatal("expected HasCPACF true from the msa feature token")
	}
	if !caps.HasVector {
		t.Error("expected HasVector true from the vx feature token")
	}
	if !caps.HasNNPA {
		t.Error("expected HasNNPA true from the nnpa feature token")
	}
	if caps.MachineType != "9175" {
		t.Errorf("MachineType = %q, want 9175", caps.MachineType)
	}

	// 76=MSA-3, 77=MSA-4, 57=MSA-5, 86=MSA-12, 146=MSA-8, 155=MSA-9.
	// With 86 present the highest level owning a STFLE bit is 12.
	if caps.MaxMSALevel < 12 {
		t.Errorf("MaxMSALevel = %d, want >= 12", caps.MaxMSALevel)
	}
	for _, flag := range []struct {
		name string
		got  bool
	}{
		{"HasAES", caps.HasAES},
		{"HasAESGCM", caps.HasAESGCM},
		{"HasGHASH", caps.HasGHASH},
		{"HasECC", caps.HasECC},
		{"HasPRNO", caps.HasPRNO},
		{"HasWrappedK", caps.HasWrappedK},
	} {
		if !flag.got {
			t.Errorf("%s = false, want true for a full MSA-12 facility list", flag.name)
		}
	}

	if len(caps.FacilityBits) == 0 {
		t.Fatal("FacilityBits is empty, want the parsed STFLE list")
	}
	// The list must be sorted so that callers can binary search it.
	for i := 1; i < len(caps.FacilityBits); i++ {
		if caps.FacilityBits[i-1] >= caps.FacilityBits[i] {
			t.Fatalf("FacilityBits not strictly ascending at %d: %v", i, caps.FacilityBits)
		}
	}
}

// TestDetectFromMSA1Only pins the floor of the ladder: a machine with the base
// MSA facility but none of the extension bits must report exactly MSA-2,
// because KM-AES-128 and KM-AES-192/256 are part of the base.
func TestDetectFromMSA1Only(t *testing.T) {
	const cpuinfo = `features	: msa vx
facilities      : 0 1 2 3 7 17 129
machine         : 8561
`
	caps := DetectFrom(strings.NewReader(cpuinfo))
	if !caps.HasCPACF {
		t.Fatal("expected HasCPACF true")
	}
	if caps.MaxMSALevel != 2 {
		t.Errorf("MaxMSALevel = %d, want 2", caps.MaxMSALevel)
	}
	if !caps.HasAES {
		t.Error("expected HasAES true whenever CPACF is present")
	}
	if caps.HasAESGCM {
		t.Error("HasAESGCM must be false without bit 146 or 77")
	}
	if caps.HasSHA3 {
		t.Error("HasSHA3 must be false without a Query result")
	}
	if caps.HasPRNO || caps.HasECC || caps.HasWrappedK {
		t.Error("extension flags must be false without their facility bits")
	}
}

// TestDetectFromNoCPACF covers an amd64/arm64 /proc/cpuinfo, where neither the
// msa feature token nor any facilities line exists.
func TestDetectFromNoCPACF(t *testing.T) {
	const cpuinfo = `processor	: 0
vendor_id	: GenuineIntel
model name	: Intel(R) Xeon(R) Platinum
flags		: fpu vme de pse sse2 aes avx2
`
	caps := DetectFrom(strings.NewReader(cpuinfo))
	if caps.HasCPACF {
		t.Error("HasCPACF must be false on a host without the msa feature token")
	}
	if caps.MaxMSALevel != 0 {
		t.Errorf("MaxMSALevel = %d, want 0 without CPACF", caps.MaxMSALevel)
	}
	if caps.HasAES {
		t.Error("HasAES must be false without CPACF")
	}
	if len(caps.CryptoFeatures) != 0 {
		t.Errorf("CryptoFeatures = %v, want empty", caps.CryptoFeatures)
	}
}

func TestDetectFromNilReader(t *testing.T) {
	caps := DetectFrom(nil)
	if caps.MachineType == "" {
		t.Error("MachineType must be populated for a nil reader")
	}
	if caps.HasCPACF {
		t.Error("HasCPACF must be false for a nil reader")
	}
	if caps.Endianness == "" {
		t.Error("Endianness must always be reported")
	}
}

// TestFacilityBitConstants guards the STFLE numbering against a careless edit.
// The values are the ones used by IBM s390-tools (cpacfinfo msa2stfle) and by
// Go's own internal/cpu package.
func TestFacilityBitConstants(t *testing.T) {
	want := map[string]struct{ got, exp int }{
		"FacilityMSA":   {FacilityMSA, 17},
		"FacilityMSA3":  {FacilityMSA3, 76},
		"FacilityMSA4":  {FacilityMSA4, 77},
		"FacilityMSA5":  {FacilityMSA5, 57},
		"FacilityMSA8":  {FacilityMSA8, 146},
		"FacilityMSA9":  {FacilityMSA9, 155},
		"FacilityMSA12": {FacilityMSA12, 86},
	}
	for name, v := range want {
		if v.got != v.exp {
			t.Errorf("%s = %d, want %d", name, v.got, v.exp)
		}
	}

	seen := make(map[int]int, len(MSAFacilityBits))
	for _, e := range MSAFacilityBits {
		if prev, dup := seen[e.Bit]; dup {
			t.Errorf("facility bit %d claimed by both MSA-%d and MSA-%d", e.Bit, prev, e.Level)
		}
		seen[e.Bit] = e.Level
	}
}

func TestSplitCPUInfoLine(t *testing.T) {
	cases := []struct {
		in    string
		key   string
		value string
		ok    bool
	}{
		{"features\t: msa vx", "features", "msa vx", true},
		{"machine         : 9175", "machine", "9175", true},
		{"no colon here", "", "", false},
		{": leading colon", "", "", false},
		{"key:", "key", "", true},
	}
	for _, c := range cases {
		key, value, ok := splitCPUInfoLine(c.in)
		if ok != c.ok || key != c.key || value != c.value {
			t.Errorf("splitCPUInfoLine(%q) = (%q, %q, %v), want (%q, %q, %v)",
				c.in, key, value, ok, c.key, c.value, c.ok)
		}
	}
}

// TestRefineWithQueryUsesBitmaps checks that Query evidence can raise the level
// past what the facility bits alone prove.
func TestRefineWithQueryUsesBitmaps(t *testing.T) {
	caps := DetectFrom(strings.NewReader(`features	: msa vx
facilities      : 17 129
`))
	if caps.MaxMSALevel != 2 {
		t.Fatalf("precondition: MaxMSALevel = %d, want 2", caps.MaxMSALevel)
	}

	var kimd FunctionBitmap
	kimd = setFunc(kimd, FuncKIMDSHA3_224)
	kimd = setFunc(kimd, FuncKIMDSHA3_256)
	kimd = setFunc(kimd, FuncKIMDSHA3_384)
	kimd = setFunc(kimd, FuncKIMDSHA3_512)

	refined := RefineWithQuery(caps, Query{Available: true, KIMD: kimd})
	if !refined.HasSHA3 {
		t.Error("expected HasSHA3 true once all four SHA-3 function codes are present")
	}
	if refined.MaxMSALevel < 6 {
		t.Errorf("MaxMSALevel = %d, want >= 6 after SHA-3 confirmation", refined.MaxMSALevel)
	}
}

func TestRefineWithQueryUnavailableIsNoOp(t *testing.T) {
	caps := DetectFrom(strings.NewReader(sampleCPUInfo))
	got := RefineWithQuery(caps, Query{Available: false})
	if got.MaxMSALevel != caps.MaxMSALevel {
		t.Errorf("MaxMSALevel changed from %d to %d on an unavailable Query",
			caps.MaxMSALevel, got.MaxMSALevel)
	}
}

func TestFunctionBitmapHas(t *testing.T) {
	var b FunctionBitmap
	if b.Has(0) {
		t.Error("zero bitmap must report nothing present")
	}
	b = setFunc(b, 0)
	b = setFunc(b, 20)
	b = setFunc(b, 127)
	for _, fc := range []uint{0, 20, 127} {
		if !b.Has(fc) {
			t.Errorf("Has(%d) = false, want true", fc)
		}
	}
	if b.Has(21) {
		t.Error("Has(21) = true, want false")
	}
	// Bit numbering is MSB-first within each byte.
	if b[0]&0x80 == 0 {
		t.Error("function code 0 must live in the MSB of byte 0")
	}
	if b[15]&0x01 == 0 {
		t.Error("function code 127 must live in the LSB of byte 15")
	}
	if got := b.Count(); got != 3 {
		t.Errorf("Count() = %d, want 3", got)
	}
	if b.Has(128) {
		t.Error("function codes >= 128 are out of range and must report false")
	}
}

// setFunc returns b with function code fc marked present.
func setFunc(b FunctionBitmap, fc uint) FunctionBitmap {
	if fc < 128 {
		b[fc/8] |= 0x80 >> (fc % 8)
	}
	return b
}
