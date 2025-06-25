📌 Overview

    The message is signed using the ElGamal digital signature scheme over a 1024-bit prime modulus.

    Hashing is performed with SHA-256.

    The signature is generated using:

        A manually implemented Extended Euclidean Algorithm to calculate modular inverses

        Random nonce generation with validity checks

    The ElGamal key pair and signature values are saved in hex format.

🧠 How It Works
🔐 Key Generation

    Prime modulus p and generator g are predefined (1024-bit values).

    Generate private key x where:
    1 < x < p−1

    Compute public key y as:
    y = g^x mod p

✍️ Message Signing

To sign a binary message m (in this case, the compiled .class file):

    Choose random k where:
    1 < k < p−1 and gcd(k, p−1) = 1

    Compute r = g^k mod p

    Compute SHA-256 hash of message:
    H(m)

    Compute signature component s as:
    s = (H(m) - x·r)·k⁻¹ mod (p−1)

        k⁻¹ is computed using your own implementation of the Extended Euclidean Algorithm.

    If s = 0, retry with a new k.

    The digital signature is the pair (r, s).

📂 Project Output

After running the signing process, the following files are generated:

    y.txt – Public key y in hexadecimal

    r.txt – Signature value r in hexadecimal

    s.txt – Signature value s in hexadecimal

    Assignment2.java – Java source code

    Assignment2.class – Compiled code file (used as the message)

    Declaration.txt – Statement of academic integrity

🧪 Signature Verification

To verify the signature of m (performed manually or by instructor):

    Check 0 < r < p and 0 < s < p−1

    Compute hash of the message:
    H(m) = SHA-256(m)

    Verify the equation:
    g^H(m) mod p == y^r · r^s mod p

🛠 Tech Details

    Language: Java

    Cryptographic libraries used:

        java.math.BigInteger

        java.security.MessageDigest (SHA-256)

    Manual implementation of:

        Extended Euclidean Algorithm for modular inverse

        ElGamal signing process

    All outputs are in hexadecimal, no whitespace.

🔒 Parameters
Prime modulus p (1024 bits):

b59dd79568817b4b9f6789822d22594f376e6a9abc0241846de426e5dd8f6edd
ef00b465f38f509b2b18351064704fe75f012fa346c5e2c442d7c99eac79b2bc
8a202c98327b96816cb8042698ed3734643c4c05164e739cb72fba24f6156b6f
47a7300ef778c378ea301e1141a6b25d48f1924268c62ee8dd3134745cdf7323

Generator g:

44ec9d52c8f9189e49cd7c70253c2eb3154dd4f08467a64a0267c9defe4119f2
e373388cfa350a4e66e432d638ccdc58eb703e31d4c84e50398f9f91677e8864
1a2d2f6157e2f4ec538088dcf5940b053c622e53bab0b4e84b1465f5738f5496
64bd7430961d3e5a2e7bceb62418db747386a58ff267a9939833beefb7a6fd68

⚠️ Common Mistakes Avoided

This implementation handles or mitigates the following common pitfalls:

    Incorrect domain/range for x, k, r, or s

    Failing to ensure gcd(k, p-1) == 1

    Incorrect calculation of s (modular inverse + multiplication)

    Use of unsupported BigInteger methods for GCD/inverse

    Incorrect SHA-256 hashing (should use raw byte content of .class file)

    Misuse of BigInteger.toByteArray() (twos-complement issues)

    Output in decimal or negative hex
