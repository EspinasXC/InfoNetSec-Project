import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AES {

    public static String encryptAES(String message, SecretKey key, String mode, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/" + mode + "/PKCS5Padding");
        if (mode.equals("CBC")) {
            cipher.init(Cipher.ENCRYPT_MODE, key, iv); 
            //uses iniitialization vector to produce 
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, key);
        }
        byte[] encryptedBytes = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static String decryptAES(String ciphertext, SecretKey key, String mode, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/" + mode + "/PKCS5Padding");
        if (mode.equals("CBC")) {
            cipher.init(Cipher.DECRYPT_MODE, key, iv);
        } else {
            cipher.init(Cipher.DECRYPT_MODE, key);
        }
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(ciphertext));
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) throws Exception {
        
        // Generate AES key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SecretKey keyAES = keyGen.generateKey();


        // Generate random IV for CBC mode
        byte[] ivBytes = new byte[16];
        // You may want to use a secure method to generate the IV in a real scenario
        IvParameterSpec iv = new IvParameterSpec(ivBytes);


        // ECB Mode
        System.out.println("ECB Mode:");
        System.out.println("Original (Short): Everybody has talent, but ability takes hard work. Never say never, because limits, like fears, are often just an illusion.");
        //set equal to null so the ECB mode is chosen
        String encryptedShortECB = encryptAES("Everybody has talent, but ability takes hard work. Never say never, because limits, like fears, are often just an illusion.", keyAES, "ECB", null);
        System.out.println("Encrypted: " + encryptedShortECB);
        System.out.println("Decrypted: " + decryptAES(encryptedShortECB, keyAES, "ECB", null));


        // CBC Mode
        System.out.println("\nCBC Mode:");
        System.out.println("Original (Short): Everybody has talent, but ability takes hard work. Never say never, because limits, like fears, are often just an illusion.");
        String encryptedShortCBC = encryptAES("Everybody has talent, but ability takes hard work. Never say never, because limits, like fears, are often just an illusion.", keyAES, "CBC", iv);
        //existence of iv will choose CBC method
        System.out.println("Encrypted: " + encryptedShortCBC);
        System.out.println("Decrypted: " + decryptAES(encryptedShortCBC, keyAES, "CBC", iv));

    }
}


