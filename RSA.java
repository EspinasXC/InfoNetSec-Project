
import java.math.BigInteger;
import java.util.Random;

public class RSA {

    private static final int BIT_LENGTH = 512;

    public static void main(String[] args) {

        // (a) RSA key generate
        for (int i = 0; i < 10; i++) {
            KeyPair keyPair = generateKeyPair(3);
            System.out.println("Key Pair " + (i + 1) + ": " + keyPair);
        }

        // (b) RSA encrypt and (c) RSA decrypt
        BigInteger e = new BigInteger("65537");
        KeyPair keyPair = generateKeyPair(e.intValue());

        System.out.println("\nPublic Key: " + keyPair.getPublicKey());
        System.out.println("Private Key: " + keyPair.getPrivateKey());

        // Encrypt and Decrypt
        BigInteger originalMessage = new BigInteger("123456789");
        BigInteger ciphertext = encrypt(originalMessage, keyPair.getPublicKey());
        BigInteger decryptedMessage = decrypt(ciphertext, keyPair.getPrivateKey());

        System.out.println("\nOriginal Message: " + originalMessage);
        System.out.println("Ciphertext: " + ciphertext);
        System.out.println("Decrypted Message: " + decryptedMessage);

        // Verify with another message
        String message = "hello world!";
        BigInteger messageInt = new BigInteger(message.getBytes());
        ciphertext = encrypt(messageInt, keyPair.getPublicKey());
        decryptedMessage = decrypt(ciphertext, keyPair.getPrivateKey());

        System.out.println("\nOriginal Message: " + message);
        System.out.println("Ciphertext: " + ciphertext);
        System.out.println("Decrypted Message: " + new String(decryptedMessage.toByteArray()));
    }

    private static KeyPair generateKeyPair(int e) {
        BigInteger p = generateRandomPrime();
        BigInteger q = generateRandomPrime();

        BigInteger n = p.multiply(q);
        BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

        // Ensure e and phi(n) are coprime and e < phi(n)
        while (!phi.gcd(BigInteger.valueOf(e)).equals(BigInteger.ONE) || e >= phi.intValue()) {
            p = generateRandomPrime();
            q = generateRandomPrime();
            n = p.multiply(q);
            phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        }

        // Calculate d (private key)
        BigInteger d = BigInteger.valueOf(e).modInverse(phi);

        return new KeyPair(new PublicKey(BigInteger.valueOf(e), n), new PrivateKey(d, n));
    }

    private static BigInteger generateRandomPrime() {
        return BigInteger.probablePrime(BIT_LENGTH, new Random());
    }

    private static BigInteger encrypt(BigInteger message, PublicKey publicKey) {
        return message.modPow(publicKey.getExponent(), publicKey.getModulus());
    }

    private static BigInteger decrypt(BigInteger ciphertext, PrivateKey privateKey) {
        return ciphertext.modPow(privateKey.getExponent(), privateKey.getModulus());
    }

    static class KeyPair {
        private final PublicKey publicKey;
        private final PrivateKey privateKey;

        public KeyPair(PublicKey publicKey, PrivateKey privateKey) {
            this.publicKey = publicKey;
            this.privateKey = privateKey;
        }

        public PublicKey getPublicKey() {
            return publicKey;
        }

        public PrivateKey getPrivateKey() {
            return privateKey;
        }

        @Override
        public String toString() {
            return "Public Key: " + publicKey + ", Private Key: " + privateKey;
        }
    }

    static class PublicKey {
        private final BigInteger exponent;
        private final BigInteger modulus;

        public PublicKey(BigInteger exponent, BigInteger modulus) {
            this.exponent = exponent;
            this.modulus = modulus;
        }

        public BigInteger getExponent() {
            return exponent;
        }

        public BigInteger getModulus() {
            return modulus;
        }

        @Override
        public String toString() {
            return "(" + exponent + ", " + modulus + ")";
        }
    }

    static class PrivateKey {
        private final BigInteger exponent;
        private final BigInteger modulus;

        public PrivateKey(BigInteger exponent, BigInteger modulus) {
            this.exponent = exponent;
            this.modulus = modulus;
        }

        public BigInteger getExponent() {
            return exponent;
        }

        public BigInteger getModulus() {
            return modulus;
        }

        @Override
        public String toString() {
            return "(" + exponent + ", " + modulus + ")";
        }
    }
}

