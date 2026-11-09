# Automated s390x CPACF Crypto Telemetry - 2026-11-09

- **Timestamp**: 2026-11-09 10:30:01 UTC
- **Platform**: IBM LinuxONE III / z15 Express (Machine Type 9175)
- **Architecture**: s390x Big-Endian (MSB)

```json
{
  "capabilities": {
    "arch": "s390x",
    "machine_type": "9175",
    "has_cpacf": true,
    "has_vector": true,
    "has_nnpa": true,
    "crypto_features": [
      "msa"
    ],
    "endianness": "Big-Endian (MSB)"
  },
  "nist_verified": true,
  "throughput_mbps": {
    "sha256_1m": 4357.10676150351,
    "sha256_64k": 4340.056254073143,
    "sha512_1m": 6877.536428692219,
    "sha512_64k": 6825.673926089419
  }
}
```
