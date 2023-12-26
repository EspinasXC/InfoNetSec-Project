import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;

public class digitalSignature {

    public static void main(String[] args) {
        try {
            // Step 1: Read the document content from a file
            String documentFilePath = "document.txt";
            String documentContent = new String(Files.readAllBytes(Paths.get(documentFilePath)));

            // Step 2: Key Generation for Digital Signature
            KeyPair keyPair = generateKeyPair();
            PrivateKey privateKeyU1 = keyPair.getPrivate();
            PublicKey publicKeyU1 = keyPair.getPublic();

            // Step 3: Signing with Timestamp
            String timestampedDocument = addTimestamp(documentContent);
            byte[] signatureU1 = sign(timestampedDocument, privateKeyU1);

            // Print the base64-encoded signature for the original document
            System.out.println("Signature for Original Document: " + encodeBase64(signatureU1));

            // Step 4: Verification
            boolean isVerified = verify(timestampedDocument, signatureU1, publicKeyU1);
            System.out.println("Signature Verification: " + isVerified);

            // Step 5: Modifying the Document
            documentContent = modifyDocument(documentContent);  // Modify the original document
            String timestampedModifiedDocument = addTimestamp(documentContent);

            // Step 6: Encryption with AES
            SecretKey aesKey = generateAESKey();
            byte[] encryptedDocument = encrypt(timestampedModifiedDocument, aesKey);

            // Print the base64-encoded encrypted document
            System.out.println("Encrypted Document: " + encodeBase64(encryptedDocument));

            // Step 7: Decryption with AES
            String decryptedDocument = decrypt(encryptedDocument, aesKey);

            // Print the decrypted document
            System.out.println("Decrypted Document:\n" + decryptedDocument);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048); // Adjust key size as needed
        return keyGen.generateKeyPair();
    }

    private static byte[] sign(String document, PrivateKey privateKey) throws NoSuchAlgorithmException,
            InvalidKeyException, SignatureException {
        byte[] documentBytes = document.getBytes();
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(documentBytes);

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(hash);
        return signature.sign();
    }

    private static boolean verify(String document, byte[] signature, PublicKey publicKey) throws NoSuchAlgorithmException,
            InvalidKeyException, SignatureException {
        byte[] documentBytes = document.getBytes();
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(documentBytes);

        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(publicKey);
        verifier.update(hash);
        return verifier.verify(signature);
    }

    private static String addTimestamp(String document) {
        // Add timestamp to the document
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        String timestamp = dateFormat.format(new Date());
        return document + "\nTimestamp: " + timestamp;
    }

    private static String modifyDocument(String document) {
        // Modify the document content as needed
        return document + "\nModified: true";
    }

    private static SecretKey generateAESKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        return keyGenerator.generateKey();
    }

    private static byte[] encrypt(String data, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(data.getBytes());
    }

    private static String decrypt(byte[] encryptedData, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedBytes = cipher.doFinal(encryptedData);
        return new String(decryptedBytes);
    }

    private static String encodeBase64(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }
}
