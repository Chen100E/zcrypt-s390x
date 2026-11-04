# Automated s390x CPACF Crypto Telemetry - 2026-11-04

- **Timestamp**: 2026-11-04 10:30:01 UTC
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
    "sha256_1m": 3594.3050139920656,
    "sha256_64k": 4316.056905656521,
    "sha512_1m": 6169.193394898658,
    "sha512_64k": 4065.5985959699183
  }
}
```
