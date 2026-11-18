//go:build !purego

package cipher

// pureGoAES is false for a default build, which on s390x means crypto/aes uses
// its CPACF assembly (KM/KMC/KMCTR/KMA) rather than the portable bitsliced
// implementation.
const pureGoAES = false
