# Automated s390x CPACF Crypto Telemetry - 2026-11-19

- **Timestamp**: 2026-11-19 22:35:30 CST
- **Platform**: IBM LinuxONE III / z15 Express (Machine Type 9175)
- **Architecture**: s390x Big-Endian (MSB)

```json
{
  "aes256gcm": [
    {
      "block_size": 1024,
      "encrypt_mbps": 6904.324488845793,
      "decrypt_mbps": 6552.3912852399135,
      "iterations": 20000,
      "bytes_per_iter": 1024
    },
    {
      "block_size": 65536,
      "encrypt_mbps": 14096.983865720025,
      "decrypt_mbps": 14084.170609107703,
      "iterations": 2000,
      "bytes_per_iter": 65536
    },
    {
      "block_size": 1048576,
      "encrypt_mbps": 14076.161464551404,
      "decrypt_mbps": 13685.672804440015,
      "iterations": 200,
      "bytes_per_iter": 1048576
    }
  ],
  "aes_impl": {
    "arch": "s390x",
    "assembly_path": true,
    "purego_build": false,
    "endianness": "Big-Endian (MSB)",
    "description": "CPACF KM/KMC/KMCTR/KMA assembly path selected by crypto/aes"
  },
  "aes_mode_table": [
    {
      "mode": "ECB",
      "cpacf_instruction": "KM",
      "msa_level": 1,
      "go_path": "crypto/aes.(*aesCipherAsm).Encrypt",
      "parallel": false,
      "authenticated": false,
      "notes": "one block per instruction; reference cost only, never for data"
    },
    {
      "mode": "CBC",
      "cpacf_instruction": "KMC",
      "msa_level": 1,
      "go_path": "crypto/aes.(*aesCipherAsm).NewCBCEncrypter -\u003e kmc()",
      "parallel": false,
      "authenticated": false,
      "notes": "chaining value lives in the instruction parameter block, so the IV never round-trips through memory"
    },
    {
      "mode": "CTR",
      "cpacf_instruction": "KM",
      "msa_level": 1,
      "go_path": "crypto/aes.(*aesctr).refill -\u003e cryptBlocks(KM) + Go-side xorBytes",
      "parallel": true,
      "authenticated": false,
      "notes": "Go refills a 512-byte ECB keystream buffer and XORs in software; KMCTR is NOT issued on this path"
    },
    {
      "mode": "GCM",
      "cpacf_instruction": "KMA",
      "msa_level": 8,
      "go_path": "crypto/aes.(*aesCipherAsm).NewGCM -\u003e gcmKMA (KMA) or gcmAsm (KMCTR + KIMD-GHASH)",
      "parallel": true,
      "authenticated": true,
      "notes": "AES rounds and GHASH fused in one instruction; KMCTR + KIMD-GHASH is the MSA-4..7 fallback"
    }
  ],
  "aes_modes": [
    {
      "mode": "ECB",
      "key_bits": 256,
      "block_size": 1024,
      "encrypt_mbps": 394.352458876547,
      "decrypt_mbps": 256.9836224542997,
      "iterations": 4000,
      "cpacf_instruction": "KM",
      "round_trip_verified": true,
      "setup_nanos": 2308,
      "encrypt_nanos": 9905479,
      "decrypt_nanos": 15200385
    },
    {
      "mode": "CBC",
      "key_bits": 256,
      "block_size": 1024,
      "encrypt_mbps": 2744.1783025680943,
      "decrypt_mbps": 6401.484734763442,
      "iterations": 4000,
      "cpacf_instruction": "KMC",
      "round_trip_verified": true,
      "setup_nanos": 960,
      "encrypt_nanos": 1423468,
      "decrypt_nanos": 610210
    },
    {
      "mode": "CTR",
      "key_bits": 256,
      "block_size": 1024,
      "encrypt_mbps": 1011.8272077583996,
      "decrypt_mbps": 1980.5757803151685,
      "iterations": 4000,
      "cpacf_instruction": "KM",
      "round_trip_verified": true,
      "setup_nanos": 570,
      "encrypt_nanos": 3860590,
      "decrypt_nanos": 1972280
    },
    {
      "mode": "GCM",
      "key_bits": 256,
      "block_size": 1024,
      "encrypt_mbps": 6641.463816880072,
      "decrypt_mbps": 6880.798586584887,
      "iterations": 4000,
      "cpacf_instruction": "KMA",
      "round_trip_verified": true,
      "setup_nanos": 3078,
      "encrypt_nanos": 588161,
      "decrypt_nanos": 567703
    },
    {
      "mode": "ECB",
      "key_bits": 256,
      "block_size": 65536,
      "encrypt_mbps": 416.59745594265274,
      "decrypt_mbps": 400.7353011894465,
      "iterations": 400,
      "cpacf_instruction": "KM",
      "round_trip_verified": true,
      "setup_nanos": 653,
      "encrypt_nanos": 60009968,
      "decrypt_nanos": 62385320
    },
    {
      "mode": "CBC",
      "key_bits": 256,
      "block_size": 65536,
      "encrypt_mbps": 3662.678449356731,
      "decrypt_mbps": 15521.760887894392,
      "iterations": 400,
      "cpacf_instruction": "KMC",
      "round_trip_verified": true,
      "setup_nanos": 6478,
      "encrypt_nanos": 6825606,
      "decrypt_nanos": 1610642
    },
    {
      "mode": "CTR",
      "key_bits": 256,
      "block_size": 65536,
      "encrypt_mbps": 2829.09888900155,
      "decrypt_mbps": 2716.303011641205,
      "iterations": 400,
      "cpacf_instruction": "KM",
      "round_trip_verified": true,
      "setup_nanos": 622,
      "encrypt_nanos": 8836736,
      "decrypt_nanos": 9203686
    },
    {
      "mode": "GCM",
      "key_bits": 256,
      "block_size": 65536,
      "encrypt_mbps": 14374.003522205823,
      "decrypt_mbps": 14178.30752975885,
      "iterations": 400,
      "cpacf_instruction": "KMA",
      "round_trip_verified": true,
      "setup_nanos": 6826,
      "encrypt_nanos": 1739251,
      "decrypt_nanos": 1763257
    },
    {
      "mode": "ECB",
      "key_bits": 256,
      "block_size": 1048576,
      "encrypt_mbps": 405.9345191086571,
      "decrypt_mbps": 404.6899641350601,
      "iterations": 40,
      "cpacf_instruction": "KM",
      "round_trip_verified": true,
      "setup_nanos": 2326,
      "encrypt_nanos": 98538060,
      "decrypt_nanos": 98841097
    },
    {
      "mode": "CBC",
      "key_bits": 256,
      "block_size": 1048576,
      "encrypt_mbps": 3650.6093095100655,
      "decrypt_mbps": 15365.078096850697,
      "iterations": 40,
      "cpacf_instruction": "KMC",
      "round_trip_verified": true,
      "setup_nanos": 3907,
      "encrypt_nanos": 10957075,
      "decrypt_nanos": 2603306
    },
    {
      "mode": "CTR",
      "key_bits": 256,
      "block_size": 1048576,
      "encrypt_mbps": 3067.3722236255453,
      "decrypt_mbps": 3093.4128711650765,
      "iterations": 40,
      "cpacf_instruction": "KM",
      "round_trip_verified": true,
      "setup_nanos": 4014,
      "encrypt_nanos": 13040478,
      "decrypt_nanos": 12930702
    },
    {
      "mode": "GCM",
      "key_bits": 256,
      "block_size": 1048576,
      "encrypt_mbps": 13996.834615851625,
      "decrypt_mbps": 14016.227287141688,
      "iterations": 40,
      "cpacf_instruction": "KMA",
      "round_trip_verified": true,
      "setup_nanos": 7422,
      "encrypt_nanos": 2857789,
      "decrypt_nanos": 2853835
    }
  ],
  "capabilities": {
    "arch": "s390x",
    "machine_type": "9175",
    "has_cpacf": true,
    "has_vector": true,
    "has_nnpa": true,
    "crypto_features": [
      "msa",
      "msa1",
      "msa2",
      "msa3",
      "msa4",
      "msa5",
      "msa6",
      "msa7",
      "msa8",
      "msa9",
      "msa10",
      "msa11",
      "msa12",
      "msa13"
    ],
    "endianness": "Big-Endian (MSB)",
    "max_msa_level": 13,
    "has_aes": true,
    "has_aes_gcm": true,
    "has_sha3": true,
    "has_ecc": true,
    "has_ghash": true,
    "has_prno": true,
    "has_wrapped_key": true,
    "facility_bits": [
      0,
      1,
      2,
      3,
      4,
      6,
      7,
      8,
      9,
      12,
      14,
      15,
      16,
      17,
      18,
      19,
      20,
      21,
      22,
      23,
      24,
      25,
      26,
      27,
      28,
      30,
      31,
      32,
      33,
      34,
      35,
      36,
      37,
      38,
      40,
      41,
      42,
      43,
      44,
      45,
      46,
      47,
      48,
      49,
      50,
      51,
      52,
      53,
      54,
      55,
      57,
      58,
      59,
      60,
      61,
      69,
      70,
      71,
      72,
      73,
      74,
      75,
      76,
      77,
      80,
      81,
      82,
      84,
      85,
      86,
      87,
      129,
      130,
      131,
      133,
      134,
      135,
      146,
      147,
      148,
      150,
      151,
      152,
      155,
      156,
      165,
      168,
      170,
      192,
      193,
      194,
      196,
      197,
      198,
      199,
      200,
      201
    ]
  },
  "cpacf_query": {
    "available": true,
    "km": [
      240,
      112,
      56,
      56,
      0,
      0,
      40,
      40,
      0,
      0,
      40,
      40,
      0,
      0,
      0,
      1
    ],
    "kmc": [
      240,
      112,
      56,
      56,
      0,
      0,
      0,
      0,
      16,
      0,
      0,
      0,
      0,
      0,
      0,
      1
    ],
    "kmctr": [
      240,
      112,
      56,
      56,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      1
    ],
    "kma": [
      128,
      0,
      56,
      56,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      1
    ],
    "kimd": [
      240,
      0,
      0,
      0,
      252,
      0,
      0,
      0,
      64,
      0,
      0,
      0,
      0,
      0,
      0,
      1
    ],
    "klmd": [
      240,
      0,
      0,
      0,
      252,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      1
    ],
    "kdsa": [
      240,
      112,
      112,
      0,
      136,
      136,
      136,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      1
    ]
  },
  "curve_table": [
    {
      "curve": "P-256",
      "algorithm": "ECDSA",
      "kdsa_sign_function_code": 9,
      "kdsa_verify_function_code": 1,
      "msa_level": 9,
      "digest": "SHA-256",
      "public_key_bytes": 64,
      "private_key_bits": 256,
      "notes": "one KDSA instruction per operation; the parameter block is 4096 bytes so the sign path zeroes it each call"
    },
    {
      "curve": "P-384",
      "algorithm": "ECDSA",
      "kdsa_sign_function_code": 10,
      "kdsa_verify_function_code": 2,
      "msa_level": 9,
      "digest": "SHA-384",
      "public_key_bytes": 96,
      "private_key_bits": 384,
      "notes": "same instruction, wider parameter block"
    },
    {
      "curve": "P-521",
      "algorithm": "ECDSA",
      "kdsa_sign_function_code": 11,
      "kdsa_verify_function_code": 3,
      "msa_level": 9,
      "digest": "SHA-512",
      "public_key_bytes": 132,
      "private_key_bits": 521,
      "notes": "521 bits is not a whole number of bytes, so the hash is truncated to 66 bytes before KDSA sees it"
    },
    {
      "curve": "Ed25519",
      "algorithm": "EdDSA",
      "kdsa_sign_function_code": 32,
      "kdsa_verify_function_code": 33,
      "msa_level": 9,
      "digest": "SHA-512 (internal to Ed25519)",
      "public_key_bytes": 32,
      "private_key_bits": 256,
      "notes": "Ed25519 hashes internally, so there is no separate digest step to measure"
    }
  ],
  "ecc_kernel": [
    {
      "curve": "P-256",
      "kernel_name": "ecdsa-nist-p256",
      "kernel_driver_present": false,
      "kdsa_usable": true,
      "kdsa_sign_function_code": 9,
      "kdsa_verify_function_code": 1,
      "notes": "KDSA issues directly from the Go crypto/ecdsa path; no kernel driver needed"
    },
    {
      "curve": "P-384",
      "kernel_name": "ecdsa-nist-p384",
      "kernel_driver_present": false,
      "kdsa_usable": true,
      "kdsa_sign_function_code": 10,
      "kdsa_verify_function_code": 2,
      "notes": "KDSA issues directly from the Go crypto/ecdsa path; no kernel driver needed"
    },
    {
      "curve": "P-521",
      "kernel_name": "",
      "kernel_driver_present": false,
      "kdsa_usable": true,
      "kdsa_sign_function_code": 11,
      "kdsa_verify_function_code": 3,
      "notes": "KDSA issues directly from the Go crypto/ecdsa path; no kernel driver needed"
    },
    {
      "curve": "Ed25519",
      "kernel_name": "ed25519",
      "kernel_driver_present": false,
      "kdsa_usable": false,
      "kdsa_sign_function_code": 32,
      "kdsa_verify_function_code": 33,
      "notes": "KDSA is asymmetric here: sign code 32 present=true, verify code 33 present=false; Go requires both, so it uses the portable fallback"
    }
  ],
  "kernel_crypto": {
    "available": true,
    "algorithms": [
      {
        "name": "aes",
        "driver": "aes-s390",
        "module": "aes_s390",
        "priority": 300,
        "type": "cipher",
        "async": false,
        "selftest": "passed",
        "hardware": true,
        "alternatives": [
          "aes-s390",
          "aes-generic"
        ]
      },
      {
        "name": "blake2b-160",
        "driver": "blake2b-160-generic",
        "module": "blake2b_generic",
        "priority": 100,
        "type": "shash",
        "async": false,
        "selftest": "passed",
        "hardware": false,
        "alternatives": [
          "blake2b-160-generic"
        ]
      },
      {
        "name": "blake2b-256",
        "driver": "blake2b-256-generic",
        "module": "blake2b_generic",
        "priority": 100,
        "type": "shash",
        "async": false,
        "selftest": "passed",
        "hardware": false,
        "alternatives": [
          "blake2b-256-generic"
        ]
      },
      {
        "name": "blake2b-384",
        "driver": "blake2b-384-generic",
        "module": "blake2b_generic",
        "priority": 100,
        "type": "shash",
        "async": false,
        "selftest": "passed",
        "hardware": false,
        "alternatives": [
          "blake2b-384-generic"
        ]
      },
      {
        "name": "blake2b-512",
        "driver": "blake2b-512-generic",
        "module": "blake2b_generic",
        "priority": 100,
        "type": "shash",
        "async": false,
        "selftest": "passed",
        "hardware": false,
        "alternatives": [
          "blake2b-512-generic"
        ]
      },
      {
        "name": "cbc(aes)",
        "driver": "cbc-aes-s390",
        "module": "aes_s390",
        "priority": 402,
        "type": "skcipher",
        "async": false,
        "selftest": "passed",
        "hardware": true,
        "alternatives": [
          "cbc-aes-s390"
        ]
      },
      {
        "name": "cbc(des)",
        "driver": "cbc-des-s390",
        "module": "des_s390",
        "priority": 400,
        "type": "skcipher",
        "async": false,
        "selftest": "passed",
        "hardware": true,
        "alternatives": [
          "cbc-des-s390"
        ]
      },
      {
        "name": "cbc(des3_ede)",
        "driver": "cbc-des3_ede-s390",
        "module": "des_s390",
        "priority": 400,
        "type": "skcipher",
        "async": false,
        "selftest": "passed",
        "hardware": true,
        "alternatives": [
          "cbc-des3_ede-s390"
        ]
      },
      {
        "name": "chacha20",
        "driver": "chacha20-s390",
        "module": "chacha_s390",
        "priority": 900,
        "type": "skcipher",
        "async": false,
        "selftest": "passed",
        "hardware": true,
        "alternatives": [
          "chacha20-s390"
        ]
      },
      {
        "name": "cipher_null",
        "driver": "cipher_null-generic",
        "module": "kernel",
        "priority": 0,
        "type": "cipher",
        "async": false,
        "selftest": "passed",
        "hardware": false,
        "alternatives": [
          "cipher_null-generic"
        ]
      },
      {
        "name": "compress_null",
        "driver": "compress_null-generic",
        "module": "kernel",
        "priority": 0,
        "type": "compression",
        "async": false,
        "selftest": "passed",
        "hardware": false,
        "alternatives": [
          "compress_null-generic"
        ]
      },
      {
        "name": "crc32",
        "driver": "crc32-vx",
        "module": "crc32_vx_s390",
        "priority": 200,
        "type": "shash",
        "async": false,
        "selftest": "passed",
        "hardware": true,
        "alternatives": [
          "crc32-vx"
        ]
      },
      {
        "name": "crc32be",
        "driver": "crc32be-vx",
        "module": "crc32_vx_s390",
        "priority": 200,
        "type": "shash",
        "async": false,
        "selftest": "passed",
        "hardware": true,
        "alternatives": [
          "crc32be-vx"
        ]
      },
      {
        "name": "crc32c",
        "driver": "crc32c-vx",
        "module": "crc32_vx_s390",
        "priority": 200,
        "type": "shash",
        "async": false,
        "selftest": "passed",
        "hardware": true,
        "alternatives": [
          "crc32c-vx",
          "crc32c-generic"
        ]
      },
      {
        "name": "crct10dif",
        "driver": "crct10dif-generic",
        "module": "kernel",
        "priority": 100,
        "type": "shash",
        "async": false,
        "selftest": "passed",
        "hardware": false,
        "alternatives": [
          "crct10dif-generic"
        ]
      },
      {
        "name": "ctr(aes)",
        "driver": "ctr-aes-s390",
        "module": "aes_s390",
        "priority": 402,
        "type": "skcipher",
        "async": false,
        "selftest": "passed",
        "hardware": true,
        "alternatives": [
          "ctr-aes-s390"
        ]
      },
      {
        "name": "ctr(des)",
        "driver": "ctr-des-s390",
        "module": "des_s390",
        "priority": 400,
        "type": "skcipher",
        "async": false,
        "selftest": "passed",
        "hardware": true,
        "alternatives": [
          "ctr-des-s390"
        ]
      },
      {
        "name": "ctr(des3_ede)",
        "driver": "ctr-des3_ede-s390",
        "module": "des_s390",
        "priority": 400,
        "type": "skcipher",
        "async": false,
        "selftest": "passed",
        "hardware": true,
        "alternatives": [
          "ctr-des3_ede-s390"
        ]
      },
      {
        "name": "des",
        "driver": "des-s390",
        "module": "des_s390",
        "priority": 300,
        "type": "cipher",
        "async": false,
        "selftest": "passed",
        "hardware": true,
        "alternatives": [
          "des-s390"
        ]
      },
      {
        "name": "des3_ede",
        "driver": "des3_ede-s390",
        "module": "des_s390",
        "priority": 300,
        "type": "cipher",
        "async": false,
        "selftest": "passed",
        "hardware": true,
        "alternatives": [
          "des3_ede-s390"
        ]
      },
      {
        "name": "dh",
        "driver": "dh-generic",
        "module": "kernel",
        "priority": 100,
        "type": "kpp",
        "async": false,
        "selftest": "passed",
        "hardware": false,
        "alternatives": [
          "dh-generic"
        ]
      },
      {
        "name": "digest_null",
        "driver": "digest_null-generic",
        "module": "kernel",
        "priority": 0,
        "type": "shash",
        "async": false,
        "selftest": "passed",
        "hardware": false,
        "alternatives": [
          "digest_null-generic"
        ]
      },
      {
        "name": "ecb(aes)",
        "driver": "ecb-aes-s390",
        "module": "aes_s390",
        "priority": 401,
        "type": "skcipher",
        "async": false,
        "selftest": "passed",
        "hardware": true,
        "alternatives": [
          "ecb-aes-s390"
        ]
      },
      {
        "name": "ecb(cipher_null)",
        "driver": "ecb-cipher_null",
        "module": "kernel",
        "priority": 100,
        "type": "skcipher",
        "async": false,
        "selftest": "passed",
        "hardware": false,
        "alternatives": [
          "ecb-cipher_null"
        ]
      },
      {
        "name": "ecb(des)",
        "driver": "ecb-des-s390",
        "module": "des_s390",
        "priority": 400,
        "type": "skcipher",
        "async": false,
        "selftest": "passed",
        "hardware": true,
        "alternatives": [
          "ecb-des-s390"
        ]
      },
      {
        "name": "ecb(des3_ede)",
        "driver": "ecb-des3_ede-s390",
        "module": "des_s390",
        "priority": 400,
        "type": "skcipher",
        "async": false,
        "selftest": "passed",
        "hardware": true,
        "alternatives": [
          "ecb-des3_ede-s390"
        ]
      },
      {
        "name": "gcm(aes)",
        "driver": "gcm-aes-s390",
        "module": "aes_s390",
        "priority": 900,
        "type": "aead",
        "async": false,
        "selftest": "passed",
        "hardware": true,
        "alternatives": [
          "gcm-aes-s390"
        ]
      },
      {
        "name": "ghash",
        "driver": "ghash-s390",
        "module": "ghash_s390",
        "priority": 300,
        "type": "shash",
        "async": false,
        "selftest": "passed",
        "hardware": true,
        "alternatives": [
          "ghash-s390",
          "ghash-generic"
        ]
      },
      {
        "name": "jitterentropy_rng",
        "driver": "jitterentropy_rng",
        "module": "kernel",
        "priority": 100,
        "type": "rng",
        "async": false,
        "selftest": "passed",
        "hardware": false,
        "alternatives": [
          "jitterentropy_rng"
        ]
      },
      {
        "name": "lzo",
        "driver": "lzo-generic",
        "module": "kernel",
        "priority": 0,
        "type": "compression",
        "async": false,
        "selftest": "passed",
        "hardware": false,
        "alternatives": [
          "lzo-generic",
          "lzo-scomp"
        ]
      },
      {
        "name": "lzo-rle",
        "driver": "lzo-rle-generic",
        "module": "kernel",
        "priority": 0,
        "type": "compression",
        "async": false,
        "selftest": "passed",
        "hardware": false,
        "alternatives": [
          "lzo-rle-generic",
          "lzo-rle-scomp"
        ]
      },
      {
        "name": "md5",
        "driver": "md5-generic",
        "module": "kernel",
        "priority": 0,
        "type": "shash",
        "async": false,
        "selftest": "passed",
        "hardware": false,
        "alternatives": [
          "md5-generic"
        ]
      },
      {
        "name": "pkcs1pad(rsa,sha512)",
        "driver": "pkcs1pad(rsa-generic,sha512)",
        "module": "kernel",
        "priority": 100,
        "type": "akcipher",
        "async": false,
        "selftest": "passed",
        "hardware": false,
        "alternatives": [
          "pkcs1pad(rsa-generic,sha512)"
        ]
      },
      {
        "name": "rsa",
        "driver": "rsa-generic",
        "module": "kernel",
        "priority": 100,
        "type": "akcipher",
        "async": false,
        "selftest": "passed",
        "hardware": false,
        "alternatives": [
          "rsa-generic"
        ]
      },
      {
        "name": "sha1",
        "driver": "sha1-s390",
        "module": "sha1_s390",
        "priority": 300,
        "type": "shash",
        "async": false,
        "selftest": "passed",
        "hardware": true,
        "alternatives": [
          "sha1-s390",
          "sha1-generic"
        ]
      },
      {
        "name": "sha224",
        "driver": "sha224-s390",
        "module": "sha256_s390",
        "priority": 300,
        "type": "shash",
        "async": false,
        "selftest": "passed",
        "hardware": true,
        "alternatives": [
          "sha224-s390",
          "sha224-generic"
        ]
      },
      {
        "name": "sha256",
        "driver": "sha256-s390",
        "module": "sha256_s390",
        "priority": 300,
        "type": "shash",
        "async": false,
        "selftest": "passed",
        "hardware": true,
        "alternatives": [
          "sha256-s390",
          "sha256-generic"
        ]
      },
      {
        "name": "sha3-224",
        "driver": "sha3-224-s390",
        "module": "sha3_256_s390",
        "priority": 300,
        "type": "shash",
        "async": false,
        "selftest": "passed",
        "hardware": true,
        "alternatives": [
          "sha3-224-s390"
        ]
      },
      {
        "name": "sha3-256",
        "driver": "sha3-256-s390",
        "module": "sha3_256_s390",
        "priority": 300,
        "type": "shash",
        "async": false,
        "selftest": "passed",
        "hardware": true,
        "alternatives": [
          "sha3-256-s390"
        ]
      },
      {
        "name": "sha3-384",
        "driver": "sha3-384-s390",
        "module": "sha3_512_s390",
        "priority": 300,
        "type": "shash",
        "async": false,
        "selftest": "passed",
        "hardware": true,
        "alternatives": [
          "sha3-384-s390"
        ]
      },
      {
        "name": "sha3-512",
        "driver": "sha3-512-s390",
        "module": "sha3_512_s390",
        "priority": 300,
        "type": "shash",
        "async": false,
        "selftest": "passed",
        "hardware": true,
        "alternatives": [
          "sha3-512-s390"
        ]
      },
      {
        "name": "sha384",
        "driver": "sha384-s390",
        "module": "sha512_s390",
        "priority": 300,
        "type": "shash",
        "async": false,
        "selftest": "passed",
        "hardware": true,
        "alternatives": [
          "sha384-s390",
          "sha384-generic"
        ]
      },
      {
        "name": "sha512",
        "driver": "sha512-s390",
        "module": "sha512_s390",
        "priority": 300,
        "type": "shash",
        "async": false,
        "selftest": "passed",
        "hardware": true,
        "alternatives": [
          "sha512-s390",
          "sha512-generic"
        ]
      },
      {
        "name": "stdrng",
        "driver": "drbg_nopr_hmac_sha512",
        "module": "kernel",
        "priority": 221,
        "type": "rng",
        "async": false,
        "selftest": "passed",
        "hardware": false,
        "alternatives": [
          "drbg_nopr_hmac_sha512",
          "drbg_nopr_hmac_sha256",
          "drbg_nopr_hmac_sha384",
          "drbg_nopr_hmac_sha1",
          "drbg_nopr_sha256",
          "drbg_nopr_sha512",
          "drbg_nopr_sha384",
          "drbg_nopr_sha1",
          "drbg_nopr_ctr_aes256",
          "drbg_nopr_ctr_aes192",
          "drbg_nopr_ctr_aes128",
          "drbg_pr_hmac_sha512",
          "drbg_pr_hmac_sha256",
          "drbg_pr_hmac_sha384",
          "drbg_pr_hmac_sha1",
          "drbg_pr_sha256",
          "drbg_pr_sha512",
          "drbg_pr_sha384",
          "drbg_pr_sha1",
          "drbg_pr_ctr_aes256",
          "drbg_pr_ctr_aes192",
          "drbg_pr_ctr_aes128"
        ]
      },
      {
        "name": "xts(aes)",
        "driver": "xts-aes-s390",
        "module": "aes_s390",
        "priority": 402,
        "type": "skcipher",
        "async": false,
        "selftest": "passed",
        "hardware": true,
        "alternatives": [
          "xts-aes-s390"
        ]
      }
    ],
    "hardware_count": 28,
    "total_count": 45
  },
  "nist_gcm_vectors_passed": 4,
  "nist_mode_vectors_passed": 8,
  "nist_sha3_vectors_passed": 11,
  "nist_verified": true,
  "prng": {
    "crypto_rand": {
      "source": "crypto/rand",
      "block_size": 65536,
      "iterations": 100,
      "mbps": 402.04048734254326,
      "bytes_total": 6553600,
      "nanos_total": 15545698
    },
    "hwrng": {
      "source": "/dev/hwrng",
      "block_size": 65536,
      "iterations": 100,
      "mbps": 4.042172457373521,
      "bytes_total": 6553600,
      "nanos_total": 1546198255
    },
    "entropy_pool": {
      "entropy_avail": 256,
      "pool_size": 256,
      "read_wakeup_threshold": 0,
      "write_wakeup_threshold": 256,
      "urandom_min_reseed_secs": 60,
      "pool_full": true
    },
    "hwrng_status": {
      "device_exists": true,
      "readable": true,
      "prno_facility": true,
      "max_msa_level": 13
    },
    "randomness": {
      "sample_bytes": 262144,
      "byte_chi_square": 246.38671875,
      "histogram_min": 931,
      "histogram_max": 1134,
      "bit_balance": 0.5000333786010742,
      "ones": 1048646,
      "zeros": 1048506,
      "distinct_blocks": 16384,
      "duplicate_blocks": 0,
      "total_blocks": 16384,
      "longest_run": 3,
      "serial_correlation": 0.000620565664298218,
      "entropy_per_byte": 7.9993234110385645
    },
    "sample_source": "crypto/rand"
  },
  "prng_info": {
    "prno_facility": true,
    "go_crypto_rand_uses_prno": false,
    "kernel_trng_driver": "s390-trng",
    "notes": "PRNO exists on this machine (MSA-5); Go's crypto/rand does not issue it, so the crypto/rand throughput is the DRBG cost and the TRNG is reached via /dev/hwrng"
  },
  "sha3": [
    {
      "variant": "SHA3-224",
      "block_size": 1048576,
      "mbps": 71.9518345374233,
      "iterations": 21,
      "backend": "pure-go",
      "digest": ""
    },
    {
      "variant": "SHA3-256",
      "block_size": 1048576,
      "mbps": 68.87963824413994,
      "iterations": 21,
      "backend": "pure-go",
      "digest": ""
    },
    {
      "variant": "SHA3-384",
      "block_size": 1048576,
      "mbps": 51.64787157989885,
      "iterations": 21,
      "backend": "pure-go",
      "digest": ""
    },
    {
      "variant": "SHA3-512",
      "block_size": 1048576,
      "mbps": 36.408382170757,
      "iterations": 21,
      "backend": "pure-go",
      "digest": ""
    }
  ],
  "sha3_kernel": [
    {
      "kernel_driver": "sha3-224-s390",
      "kernel_priority": 300,
      "hardware": true,
      "af_alg_available": true
    },
    {
      "kernel_driver": "sha3-256-s390",
      "kernel_priority": 300,
      "hardware": true,
      "af_alg_available": true
    },
    {
      "kernel_driver": "sha3-384-s390",
      "kernel_priority": 300,
      "hardware": true,
      "af_alg_available": true
    },
    {
      "kernel_driver": "sha3-512-s390",
      "kernel_priority": 300,
      "hardware": true,
      "af_alg_available": true
    }
  ],
  "signatures": [
    {
      "curve": "P-256",
      "algorithm": "ECDSA",
      "sign_per_sec": 39081.460614876436,
      "verify_per_sec": 20881.49999331792,
      "sign_count": 50,
      "verify_count": 50,
      "sign_nanos_per_op": 25587.58,
      "verify_nanos_per_op": 47889.28,
      "kdsa_sign_function_code": 9,
      "kdsa_verify_function_code": 1,
      "round_trip_verified": true
    },
    {
      "curve": "P-384",
      "algorithm": "ECDSA",
      "sign_per_sec": 25994.70020052312,
      "verify_per_sec": 9340.513074383176,
      "sign_count": 50,
      "verify_count": 50,
      "sign_nanos_per_op": 38469.38,
      "verify_nanos_per_op": 107060.5,
      "kdsa_sign_function_code": 10,
      "kdsa_verify_function_code": 2,
      "round_trip_verified": true
    },
    {
      "curve": "P-521",
      "algorithm": "ECDSA",
      "sign_per_sec": 17865.890762941428,
      "verify_per_sec": 6233.760275262905,
      "sign_count": 50,
      "verify_count": 50,
      "sign_nanos_per_op": 55972.58,
      "verify_nanos_per_op": 160416.82,
      "kdsa_sign_function_code": 11,
      "kdsa_verify_function_code": 3,
      "round_trip_verified": true
    },
    {
      "curve": "Ed25519",
      "algorithm": "EdDSA",
      "sign_per_sec": 17574.420641649125,
      "verify_per_sec": 5830.207564717636,
      "sign_count": 50,
      "verify_count": 50,
      "sign_nanos_per_op": 56900.88,
      "verify_nanos_per_op": 171520.48,
      "kdsa_sign_function_code": 32,
      "kdsa_verify_function_code": 33,
      "round_trip_verified": true
    }
  ],
  "throughput_mbps": {
    "sha256_1m": 4217.432633749467,
    "sha256_64k": 4217.633961333407,
    "sha512_1m": 6270.452741441938,
    "sha512_64k": 6669.772112562276
  }
}
```
