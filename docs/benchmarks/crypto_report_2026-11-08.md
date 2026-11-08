# Automated s390x CPACF Crypto Telemetry - 2026-11-08

- **Timestamp**: 2026-11-08 10:30:01 UTC
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
    "sha256_1m": 4248.727860066565,
    "sha256_64k": 4318.535152876145,
    "sha512_1m": 6271.1158307064325,
    "sha512_64k": 4656.109094498528
  }
}
```
