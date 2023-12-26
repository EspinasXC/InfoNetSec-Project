import java.math.BigInteger;
import java.security.SecureRandom;


public class secureKeyExchange {

    // Diffie-Hellman Key Exchange
    public static class DiffieHellman {
        private static final BigInteger P = new BigInteger("102188617217178804476387977160129334431745945009730065519337094992129677228373");
        private static final BigInteger G = new BigInteger("2");

        public static BigInteger generatePublicKey(BigInteger privateKey) {
            return G.modPow(privateKey, P);
        }

        public static BigInteger generateSharedKey(BigInteger publicKey, BigInteger privateKey) {
            return publicKey.modPow(privateKey, P);
        }
    }

    // Linear Feedback Shift Register (LFSR) for key generation
    public static class LFSR {
        private int register;
        private final int tap;

        public LFSR(int tap, int seed) {
            this.tap = tap;
            this.register = seed;
        }

        public int shift() {
            int feedback = Integer.bitCount(register & tap) % 2;
            register = (register << 1) | feedback;
            return register;
        }

        public int getRegister() {
            return register;
        }
    }

    // RSA Key Exchange
    public static class RSA {
        public static BigInteger encrypt(BigInteger message, BigInteger N, BigInteger E) {
            return ((message.modPow(E, N)));
        }

        public static BigInteger decrypt(BigInteger ciphertext, BigInteger N, BigInteger D) {
            return ciphertext.modPow(D, N);
        }
    }

    private static BigInteger generatePrime() {
        return BigInteger.probablePrime(512, new SecureRandom());
    }

    private static BigInteger choosePublicExponent(BigInteger phiN) {
        // Commonly used public exponent: 65537 (0x10001)
        BigInteger e = new BigInteger("65537");
        
        // Ensure e is coprime to φ(N)
        while (!phiN.gcd(e).equals(BigInteger.ONE)) {
            e = e.add(BigInteger.ONE);
        }
        
        return e;
    }
    

    public static void main(String[] args) {
        // Diffie-Hellman Key Exchange
        BigInteger privateKeyU1 = new BigInteger("6");  // U1's private key
        BigInteger privateKeyU2 = new BigInteger("15"); // U2's private key

        BigInteger publicKeyU1 = DiffieHellman.generatePublicKey(privateKeyU1);
        BigInteger publicKeyU2 = DiffieHellman.generatePublicKey(privateKeyU2);

        BigInteger sharedKeyU1 = DiffieHellman.generateSharedKey(publicKeyU2, privateKeyU1);
        BigInteger sharedKeyU2 = DiffieHellman.generateSharedKey(publicKeyU1, privateKeyU2);

        System.out.println("Diffie-Hellman Shared Keys:");
        System.out.println("U1's Shared Key: " + sharedKeyU1);
        System.out.println("U2's Shared Key: " + sharedKeyU2);
        System.out.println("Keys Match: " + sharedKeyU1.equals(sharedKeyU2));

        // LFSR Initialization
        LFSR lfsrU1 = new LFSR(0b10101, 0b11011); // Use a non-zero seed
        int keyU1 = lfsrU1.shift(); // Shift to get a non-zero initial value

        // Generate two large prime numbers, p and q
        BigInteger p = generatePrime();
        BigInteger q = generatePrime();

        // Calculate modulus N = p * q
        BigInteger rsaN = p.multiply(q);

        // Calculate Euler's totient function φ(N) = (p - 1) * (q - 1)
        BigInteger phiN = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

        // Choose a public exponent e such that 1 < e < φ(N) and e is coprime to φ(N)
        BigInteger rsaE = choosePublicExponent(phiN);

        // Calculate private exponent d such that d * e ≡ 1 (mod φ(N))
        BigInteger rsaD = rsaE.modInverse(phiN);

        // RSA for Secure Key Exchange
        BigInteger bigKeyU1 = BigInteger.valueOf(54);
        BigInteger rsaCiphertext = RSA.encrypt(bigKeyU1, rsaN, rsaE);
        BigInteger rsaPlaintext = RSA.decrypt(rsaCiphertext, rsaN, rsaD);

        System.out.println("\nLFSR and RSA Key Exchange:");
        System.out.println("U1's Generated Key: " + keyU1);
        System.out.println("Encrypted Key: " + rsaCiphertext);
        System.out.println("Decrypted Key: " + rsaPlaintext);

        // Convert the decrypted key to int for comparison
        int intDecryptedKey = rsaPlaintext.intValue();
        System.out.println("Keys Match: " + (keyU1 == intDecryptedKey));
    }
}




