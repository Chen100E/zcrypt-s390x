package cpacf

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"strings"
)

// HardwareCapabilities details on-chip crypto and vector capabilities.
type HardwareCapabilities struct {
	Arch           string   `json:"arch"`
	MachineType    string   `json:"machine_type"`
	HasCPACF       bool     `json:"has_cpacf"`
	HasVector      bool     `json:"has_vector"`
	HasNNPA        bool     `json:"has_nnpa"`
	CryptoFeatures []string `json:"crypto_features"`
	Endianness     string   `json:"endianness"`
}

// Detect inspects /proc/cpuinfo on LinuxONE for s390x hardware crypto extensions.
func Detect() HardwareCapabilities {
	caps := HardwareCapabilities{
		Arch:       runtime.GOARCH,
		Endianness: "Big-Endian (MSB)",
	}

	file, err := os.Open("/proc/cpuinfo")
	if err != nil {
		caps.MachineType = "generic-s390x"
		return caps
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "machine") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				caps.MachineType = strings.TrimSpace(parts[1])
			}
		} else if strings.HasPrefix(line, "features") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				features := strings.Fields(parts[1])
				for _, f := range features {
					switch f {
					case "msa", "msa1", "msa2", "msa3", "msa4", "msa5", "msa6", "msa7", "msa8", "msa9":
						caps.HasCPACF = true
						caps.CryptoFeatures = append(caps.CryptoFeatures, f)
					case "vx", "vxd", "vxe", "vxe2":
						caps.HasVector = true
					case "nnpa":
						caps.HasNNPA = true
					}
				}
			}
		}
	}

	if caps.MachineType == "" {
		caps.MachineType = fmt.Sprintf("IBM zSeries (%s)", runtime.GOARCH)
	}
	return caps
}
