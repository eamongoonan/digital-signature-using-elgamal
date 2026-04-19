# ElGamal Digital Signature

A Java implementation of the ElGamal digital signature scheme over a 1024-bit prime modulus, with SHA-256 message hashing and a hand-rolled Extended Euclidean Algorithm for modular inverse computation.

## How to Build & Run

**Compile:**
```bash
javac ElGamalSigner.java
```

**Sign a file:**
```bash
java ElGamalSigner <file>
```
Produces three output files: `y.txt` (public key), `r.txt` and `s.txt` (signature components), all in hexadecimal.

**Verify a signature:**
```bash
java ElGamalSigner --verify <file> y.txt r.txt s.txt
```
Exits with code 0 on a valid signature, 1 on invalid.

---

## Overview

- Signature scheme: ElGamal over a 1024-bit prime modulus
- Hash function: SHA-256
- Modular inverse: manually implemented Extended Euclidean Algorithm
- Nonce `k` is generated with `gcd(k, p-1) = 1` enforced; signing retries if `s = 0`
- All output values are lowercase hexadecimal with no whitespace

## How It Works

### Key Generation

- Prime modulus `p` and generator `g` are predefined 1024-bit values
- Generate private key `x` where `1 < x < p−1`
- Compute public key `y = g^x mod p`

### Signing

1. Choose random `k` where `1 < k < p−1` and `gcd(k, p−1) = 1`
2. Compute `r = g^k mod p`
3. Compute `H(m) = SHA-256(message bytes)`
4. Compute `s = (H(m) − x·r) · k⁻¹ mod (p−1)`  
   — `k⁻¹` computed via the Extended Euclidean Algorithm
5. If `s = 0`, retry with a new `k`
6. Signature is the pair `(r, s)`

### Verification

Check that `g^H(m) mod p == y^r · r^s mod p`

Range checks enforced: `0 < r < p` and `0 < s < p−1`

## Parameters

**Prime modulus p (1024 bits):**
```
b59dd79568817b4b9f6789822d22594f376e6a9abc0241846de426e5dd8f6edd
ef00b465f38f509b2b18351064704fe75f012fa346c5e2c442d7c99eac79b2bc
8a202c98327b96816cb8042698ed3734643c4c05164e739cb72fba24f6156b6f
47a7300ef778c378ea301e1141a6b25d48f1924268c62ee8dd3134745cdf7323
```

**Generator g:**
```
44ec9d52c8f9189e49cd7c70253c2eb3154dd4f08467a64a0267c9defe4119f2
e373388cfa350a4e66e432d638ccdc58eb703e31d4c84e50398f9f91677e8864
1a2d2f6157e2f4ec538088dcf5940b053c622e53bab0b4e84b1465f5738f5496
64bd7430961d3e5a2e7bceb62418db747386a58ff267a9939833beefb7a6fd68
```

## Tech

- Language: Java (no external dependencies)
- `java.math.BigInteger` for arbitrary-precision arithmetic
- `java.security.MessageDigest` for SHA-256
- `java.security.SecureRandom` for nonce generation
