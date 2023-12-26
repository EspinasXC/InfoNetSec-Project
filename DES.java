import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class DES{

    public static String encryptDES(String message, SecretKey key, String mode, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("DES/" + mode + "/PKCS5Padding");
        if (mode.equals("CBC")) {
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, key);
        }
        byte[] encryptedBytes = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static String decryptDES(String ciphertext, SecretKey key, String mode, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("DES/" + mode + "/PKCS5Padding");
        if (mode.equals("CBC")) {
            cipher.init(Cipher.DECRYPT_MODE, key, iv);
        } else {
            cipher.init(Cipher.DECRYPT_MODE, key);
        }
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(ciphertext));
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) throws Exception {

        // Generate DES key
        KeyGenerator keyGen = KeyGenerator.getInstance("DES");
        SecretKey keyDES = keyGen.generateKey();


        // Generate random IV for CBC mode
        byte[] ivBytes = new byte[8];
        IvParameterSpec iv = new IvParameterSpec(ivBytes);


        // ECB Mode
        System.out.println("ECB Mode:");
        System.out.println("Original (Short): Make the best use of what is in your power, and take the rest as it happens. A ship should not ride on a single anchor, nor life on a single hope.");
        String encryptedShortECB = encryptDES("Make the best use of what is in your power, and take the rest as it happens. A ship should not ride on a single anchor, nor life on a single hope.", keyDES, "ECB", null);
        System.out.println("Encrypted: " + encryptedShortECB);
        System.out.println("Decrypted: " + decryptDES(encryptedShortECB, keyDES, "ECB", null));


        // CBC Mode
        System.out.println("\nCBC Mode:");
        System.out.println("Original (Short): Make the best use of what is in your power, and take the rest as it happens. A ship should not ride on a single anchor, nor life on a single hope.");
        String encryptedShortCBC = encryptDES("Make the best use of what is in your power, and take the rest as it happens. A ship should not ride on a single anchor, nor life on a single hope.", keyDES, "CBC", iv);
        System.out.println("Encrypted: " + encryptedShortCBC);
        System.out.println("Decrypted: " + decryptDES(encryptedShortCBC, keyDES, "CBC", iv));

        // You can continue to exchange messages of different lengths and evaluate the results
    }
}

