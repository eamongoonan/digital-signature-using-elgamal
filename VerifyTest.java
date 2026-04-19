public class VerifyTest
{
    private static int passed = 0;
    private static int failed = 0;

    public static void main(String[] args)
    {
        testValidSignature();
        testTamperedMessage();
        testTamperedR();
        testTamperedS();
        testSignMultipleFiles();

        System.out.println("\nResults: " + passed + " passed, " + failed + " failed.");
        System.exit(failed > 0 ? 1 : 0);
    }

    private static void testValidSignature()
    {
        byte[] message = "hello elgamal".getBytes();
        java.math.BigInteger[] keys = ElGamalSigner.createKeyPair();
        java.math.BigInteger[] sig = ElGamalSigner.generateSignature(message, keys[0]);
        assertCondition("Valid signature verifies", ElGamalSigner.verifySignature(message, keys[1], sig[0], sig[1]));
    }

    private static void testTamperedMessage()
    {
        byte[] original = "original message".getBytes();
        byte[] tampered = "tampered message".getBytes();
        java.math.BigInteger[] keys = ElGamalSigner.createKeyPair();
        java.math.BigInteger[] sig = ElGamalSigner.generateSignature(original, keys[0]);
        assertCondition("Tampered message rejected", !ElGamalSigner.verifySignature(tampered, keys[1], sig[0], sig[1]));
    }

    private static void testTamperedR()
    {
        byte[] message = "test message".getBytes();
        java.math.BigInteger[] keys = ElGamalSigner.createKeyPair();
        java.math.BigInteger[] sig = ElGamalSigner.generateSignature(message, keys[0]);
        java.math.BigInteger badR = sig[0].add(java.math.BigInteger.ONE);
        assertCondition("Tampered r rejected", !ElGamalSigner.verifySignature(message, keys[1], badR, sig[1]));
    }

    private static void testTamperedS()
    {
        byte[] message = "test message".getBytes();
        java.math.BigInteger[] keys = ElGamalSigner.createKeyPair();
        java.math.BigInteger[] sig = ElGamalSigner.generateSignature(message, keys[0]);
        java.math.BigInteger badS = sig[1].add(java.math.BigInteger.ONE);
        assertCondition("Tampered s rejected", !ElGamalSigner.verifySignature(message, keys[1], sig[0], badS));
    }

    private static void testSignMultipleFiles()
    {
        java.math.BigInteger[] keys = ElGamalSigner.createKeyPair();
        byte[] msg1 = "file one contents".getBytes();
        byte[] msg2 = "file two contents".getBytes();
        java.math.BigInteger[] sig1 = ElGamalSigner.generateSignature(msg1, keys[0]);
        java.math.BigInteger[] sig2 = ElGamalSigner.generateSignature(msg2, keys[0]);
        assertCondition("Sig1 verifies msg1", ElGamalSigner.verifySignature(msg1, keys[1], sig1[0], sig1[1]));
        assertCondition("Sig2 verifies msg2", ElGamalSigner.verifySignature(msg2, keys[1], sig2[0], sig2[1]));
        assertCondition("Sig1 does not verify msg2", !ElGamalSigner.verifySignature(msg2, keys[1], sig1[0], sig1[1]));
    }

    private static void assertCondition(String name, boolean condition)
    {
        if (condition)
        {
            System.out.println("  PASS  " + name);
            passed++;
        }
        else
        {
            System.out.println("  FAIL  " + name);
            failed++;
        }
    }
}
