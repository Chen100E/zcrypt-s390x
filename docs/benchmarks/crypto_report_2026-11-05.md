# Automated s390x CPACF Crypto Telemetry - 2026-11-05

- **Timestamp**: 2026-11-05 10:30:01 UTC
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
    "sha256_1m": 4350.529126707199,
    "sha256_64k": 4337.753446258358,
    "sha512_1m": 6879.218326561349,
    "sha512_64k": 6831.224488792147
  }
}
```
