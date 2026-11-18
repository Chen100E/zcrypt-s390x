//go:build purego

package cipher

// pureGoAES is set when the binary is compiled with -tags purego, which makes
// crypto/aes skip its s390x assembly and use the portable bitsliced
// implementation. ZCrypt builds both variants and compares them; the ratio is
// the measured value of CPACF.
const pureGoAES = true
