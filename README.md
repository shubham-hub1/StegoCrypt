# StegoCrypt

> **Hybrid Cryptographic & Transform-Domain Data Hiding Pipeline**

StegoCrypt is an end-to-end covert communication pipeline that combines authenticated symmetric cryptography with transform-domain steganography. It embeds encrypted, integrity-verified payloads into digital media (DCT/DWT domains) while preserving statistical and visual fidelity to resist steganalysis.

---

## Architecture Overview
|   Secret Data /   |
                  |     Payload       |
                  +---------+---------+
                            |
                            v
                  +-------------------+
                  |  AES-GCM-256 /    |
                  |  ChaCha20-Poly    |  <--- Encryption Key / KDF
                  +---------+---------+
                            |
               (Ciphertext + Auth Tag)
                            |
                            v
+-------------+       +-------------------+
| Cover Image | ----> | Domain Transform  |
+-------------+       | (DCT / DWT / LSB) |
+---------+---------+
|
v
+-------------------+
|  Adaptive Coeff.  |  <--- PRNG Embedding Key
|    Quantization   |
+---------+---------+
|
v
+-------------------+
| Inverse Transform |
+---------+---------+
|
v
+-------------------+
|    Stego Image    |
+-------------------+

---

## Features

- **Dual-Layer Security (Defense-in-Depth):**
  - **Cryptographic Layer:** Authenticated encryption using AES-256-GCM or ChaCha20-Poly1305 ensures confidentiality, tamper detection, and replay resistance.
  - **Steganographic Layer:** Transform-domain embedding conceals the very existence of the encrypted payload.
- **Transform Domains Supported:**
  - **2D-DCT (Discrete Cosine Transform):** Frequency-domain coefficient modification resistant to JPEG compression.
  - **DWT (Discrete Wavelet Transform - Haar/Daubechies):** High/mid-frequency subband allocation (LH, HL) balancing payload and visual quality.
  - **Spatial Domain (Optional/Fallback):** Multi-bit adaptive LSB for high-throughput requirements.
- **Key-Dependent Pseudo-Random Embedding:** Embeds payload bits into pseudo-randomly selected transform coefficients seeded via a user-defined stego-key, preventing sequential pattern detection.
- **Integrity & Metrics Reporting:**
  - Automated evaluation via **PSNR** (Peak Signal-to-Noise Ratio), **SSIM** (Structural Similarity Index Measure), and **BER** (Bit Error Rate).

---

## Project Structure

```text
stegocrypt/
│
├── stegocrypt/
│   ├── __init__.py
│   ├── crypto/
│   │   ├── __init__.py
│   │   ├── ciphers.py         # AES-GCM and ChaCha20 wrappers
│   │   └── kdf.py             # PBKDF2 / Argon2 key derivation
│   ├── transform/
│   │   ├── __init__.py
│   │   ├── dct.py             # Block DCT implementation
│   │   └── dwt.py             # 2D Wavelet decomposition & reconstruction
│   ├── pipeline/
│   │   ├── __init__.py
│   │   ├── embedder.py        # Core hiding workflow
│   │   └── extractor.py       # Core recovery workflow
│   └── utils/
│       ├── metrics.py         # PSNR, SSIM, capacity calculators
│       └── image_io.py        # Image loading and formatting helpers
│
├── tests/
│   ├── test_crypto.py
│   ├── test_transforms.py
│   └── test_pipeline.py
│
├── sample_data/
│   └── cover.png
│
├── requirements.txt
├── setup.py
└── README.md
