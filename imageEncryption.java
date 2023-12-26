import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec; // Add this import statement
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;

public class imageEncryption {

    public static void main(String[] args) {
        try {
            // Step 1: Generate RSA KeyPair
            KeyPair rsaKeyPair = generateKeyPair();

            // Step 2: Get the public and private keys for RSA
            PublicKey rsaPublicKey = rsaKeyPair.getPublic();
            PrivateKey rsaPrivateKey = rsaKeyPair.getPrivate();

            // Step 3: Generate AES Secret Key
            SecretKey aesSecretKey = generateAESSecretKey();

            // Step 4: Read the image file into a byte array
            String imagePath = "MJ.jpg";
            byte[] imageData = Files.readAllBytes(Paths.get(imagePath));

            // Step 5: Encrypt the AES key using the RSA public key
            byte[] encryptedAESKey = encryptAESKey(aesSecretKey.getEncoded(), rsaPublicKey);

            // Step 6: Encrypt the image using AES
            byte[] encryptedImage = encryptAES(imageData, aesSecretKey);

            // Step 7: Save the encrypted AES key and image to files
            String encryptedKeyPath = "encrypted_aes_key";
            String encryptedImagePath = "encrypted_image.jpg";

            saveToFile(encryptedKeyPath, encryptedAESKey);
            saveToFile(encryptedImagePath, encryptedImage);

            // Step 8: Decrypt the AES key using the RSA private key
            byte[] decryptedAESKey = decryptAESKey(encryptedAESKey, rsaPrivateKey);

            // Step 9: Decrypt the image using AES
            byte[] decryptedImage = decryptAES(encryptedImage, new SecretKeySpec(decryptedAESKey, "AES"));

            // Step 10: Save the decrypted image to a file
            String decryptedImagePath = "decrypted_image.jpg";
            saveToFile(decryptedImagePath, decryptedImage);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    private static SecretKey generateAESSecretKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        return keyGenerator.generateKey();
    }

    private static byte[] encryptAESKey(byte[] key, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(key);
    }

    private static byte[] decryptAESKey(byte[] encryptedKey, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedKey);
    }

    private static byte[] encryptAES(byte[] data, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(data);
    }

    private static byte[] decryptAES(byte[] encryptedData, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        return cipher.doFinal(encryptedData);
    }

    private static void saveToFile(String filePath, byte[] data) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(filePath)) {
            fos.write(data);
        }
    }
}
