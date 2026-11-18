//go:build !s390x

package cpacf

// On non-s390x hosts no CPACF instruction exists, so ProbeQuery reports the
// capability set as unavailable and every bitmap stays zero. Keeping this stub
// in a separate build-tagged file is what allows `go build ./...` and
// `go test ./...` to succeed on amd64 and arm64 CI runners.

// ProbeQuery reports CPACF as unavailable off s390x.
func ProbeQuery(caps HardwareCapabilities) Query {
	return Query{Error: "CPACF is an s390x-only instruction set; running on " + caps.Arch}
}
