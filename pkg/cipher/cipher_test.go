package cipher

import (
	"testing"
)

func TestVerifyNISTVectors(t *testing.T) {
	if err := VerifyNISTVectors(); err != nil {
		t.Fatalf("NIST vector verification failed: %v", err)
	}
	t.Log("NIST SHA-256 and SHA-512 vectors verified strictly identical on s390x.")
}

func BenchmarkSHA256_1MB(b *testing.B) {
	data := make([]byte, 1024*1024)
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = BenchmarkDigest(len(data), 1)
	}
}
