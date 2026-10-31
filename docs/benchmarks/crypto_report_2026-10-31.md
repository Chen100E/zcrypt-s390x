# Automated s390x CPACF Crypto Telemetry - 2026-10-31

- **Timestamp**: 2026-10-31 10:02:08 UTC
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
    "sha256_1m": 4341.103852482822,
    "sha256_64k": 4109.323792688888,
    "sha512_1m": 6854.111842171576,
    "sha512_64k": 6799.723659230489
  }
}
```
