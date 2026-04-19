import java.io.IOException;
import java.io.FileWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class ElGamalSigner
{
    private static final BigInteger PRIME_MODULUS = new BigInteger("b59dd79568817b4b9f6789822d22594f376e6a9abc0241846de426e5dd8f6eddef00b465f38f509b2b18351064704fe75f012fa346c5e2c442d7c99eac79b2bc8a202c98327b96816cb8042698ed3734643c4c05164e739cb72fba24f6156b6f47a7300ef778c378ea301e1141a6b25d48f1924268c62ee8dd3134745cdf7323", 16);
    private static final BigInteger GENERATOR = new BigInteger("44ec9d52c8f9189e49cd7c70253c2eb3154dd4f08467a64a0267c9defe4119f2e373388cfa350a4e66e432d638ccdc58eb703e31d4c84e50398f9f91677e88641a2d2f6157e2f4ec538088dcf5940b053c622e53bab0b4e84b1465f5738f549664bd7430961d3e5a2e7bceb62418db747386a58ff267a9939833beefb7a6fd68", 16);

    private static byte[] hashSHA256(byte[] data) throws NoSuchAlgorithmException
    {
        MessageDigest shaDigest = MessageDigest.getInstance("SHA-256");
        return shaDigest.digest(data);
    }

    public static void writeContentToFile(String filename, String content) throws IOException
    {
        try (FileWriter fileWriter = new FileWriter(filename))
        {
            fileWriter.write(content);
        }
    }

    public static BigInteger calculateGCD(BigInteger first, BigInteger second)
    {
        return (second.equals(BigInteger.ZERO)) ? first : calculateGCD(second, first.mod(second));
    }

    public static BigInteger findModInverse(BigInteger number, BigInteger modulo)
    {
        BigInteger[] euclidResults = extendedEuclid(number, modulo);
        BigInteger inverse = euclidResults[1];
        return (inverse.compareTo(BigInteger.ZERO) < 0) ? inverse.add(modulo) : inverse;
    }

    private static BigInteger[] extendedEuclid(BigInteger a, BigInteger b)
    {
        if (b.equals(BigInteger.ZERO))
            return new BigInteger[] {a, BigInteger.ONE, BigInteger.ZERO};

        BigInteger[] vals = extendedEuclid(b, a.mod(b));
        BigInteger d = vals[0];
        BigInteger x = vals[2];
        BigInteger y = vals[1].subtract(a.divide(b).multiply(vals[2]));
        return new BigInteger[] {d, x, y};
    }

    public static BigInteger[] createKeyPair()
    {
        SecureRandom randomGenerator = new SecureRandom();
        BigInteger privateKey = new BigInteger(PRIME_MODULUS.bitLength() - 1, randomGenerator);
        BigInteger publicKey = GENERATOR.modPow(privateKey, PRIME_MODULUS);
        return new BigInteger[] { privateKey, publicKey };
    }

    public static BigInteger[] generateSignature(byte[] message, BigInteger privateKey)
    {
        try
        {
            byte[] messageHash = hashSHA256(message);
            BigInteger hashValue = new BigInteger(1, messageHash);

            BigInteger randomValue, signatureR, signatureS;
            do
            {
                do
                {
                    randomValue = new BigInteger(PRIME_MODULUS.bitLength() - 2, new SecureRandom()).add(BigInteger.TWO);
                }
                while (!(calculateGCD(randomValue, PRIME_MODULUS.subtract(BigInteger.ONE)).equals(BigInteger.ONE)));

                signatureR = GENERATOR.modPow(randomValue, PRIME_MODULUS);
                signatureS = findModInverse(randomValue, PRIME_MODULUS.subtract(BigInteger.ONE))
                        .multiply(hashValue.subtract(privateKey.multiply(signatureR)))
                        .mod(PRIME_MODULUS.subtract(BigInteger.ONE));
            }
            while (signatureS.equals(BigInteger.ZERO));

            return new BigInteger[] { signatureR, signatureS };
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new RuntimeException("Error encountered computing SHA-256 hash", e);
        }
    }

    // Verifies signature (r, s) against message using public key y.
    // Checks: g^H(m) mod p == y^r * r^s mod p
    public static boolean verifySignature(byte[] message, BigInteger publicKey, BigInteger r, BigInteger s)
    {
        // Range checks
        if (r.compareTo(BigInteger.ONE) <= 0 || r.compareTo(PRIME_MODULUS) >= 0)
            return false;
        if (s.compareTo(BigInteger.ONE) <= 0 || s.compareTo(PRIME_MODULUS.subtract(BigInteger.ONE)) >= 0)
            return false;

        try
        {
            BigInteger hashValue = new BigInteger(1, hashSHA256(message));
            BigInteger lhs = GENERATOR.modPow(hashValue, PRIME_MODULUS);
            BigInteger rhs = publicKey.modPow(r, PRIME_MODULUS)
                    .multiply(r.modPow(s, PRIME_MODULUS))
                    .mod(PRIME_MODULUS);
            return lhs.equals(rhs);
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new RuntimeException("Error encountered computing SHA-256 hash", e);
        }
    }

    public static void main(String[] args)
    {
        if (args.length < 1)
        {
            System.err.println("Usage:");
            System.err.println("  Sign:   java ElGamalSigner <file>");
            System.err.println("  Verify: java ElGamalSigner --verify <file> <y.txt> <r.txt> <s.txt>");
            System.exit(1);
        }

        try
        {
            if (args[0].equals("--verify"))
            {
                if (args.length < 5)
                {
                    System.err.println("Usage: java ElGamalSigner --verify <file> <y.txt> <r.txt> <s.txt>");
                    System.exit(1);
                }

                byte[] fileBytes = Files.readAllBytes(Paths.get(args[1]));
                BigInteger publicKey  = new BigInteger(new String(Files.readAllBytes(Paths.get(args[2]))).trim(), 16);
                BigInteger sigR       = new BigInteger(new String(Files.readAllBytes(Paths.get(args[3]))).trim(), 16);
                BigInteger sigS       = new BigInteger(new String(Files.readAllBytes(Paths.get(args[4]))).trim(), 16);

                boolean valid = verifySignature(fileBytes, publicKey, sigR, sigS);
                System.out.println(valid ? "Signature VALID." : "Signature INVALID.");
                System.exit(valid ? 0 : 1);
            }
            else
            {
                BigInteger[] keys = createKeyPair();
                BigInteger secretKey = keys[0];
                BigInteger publicKey = keys[1];

                writeContentToFile("y.txt", publicKey.toString(16));

                byte[] fileToSign = Files.readAllBytes(Paths.get(args[0]));
                BigInteger[] signature = generateSignature(fileToSign, secretKey);

                writeContentToFile("r.txt", signature[0].toString(16));
                writeContentToFile("s.txt", signature[1].toString(16));
                System.out.println("File signed. Output: y.txt (public key), r.txt, s.txt (signature).");
            }
        }
        catch (Exception e)
        {
            System.err.println("Error: " + e.getMessage());
        }
    }
}
