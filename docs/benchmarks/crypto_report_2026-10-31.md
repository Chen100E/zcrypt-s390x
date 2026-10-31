# Automated s390x CPACF Crypto Telemetry - 2026-10-31

- **Timestamp**: 2026-10-31 10:30:01 UTC
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
    "sha256_1m": 4349.395280547936,
    "sha256_64k": 4320.674218744329,
    "sha512_1m": 6881.702322655495,
    "sha512_64k": 6590.254858335881
  }
}
```
