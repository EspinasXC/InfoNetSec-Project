public class streamCipher {

    public static String textToBitStream(String text) {
        StringBuilder bitStream = new StringBuilder();
        for (char c : text.toCharArray()) {
            bitStream.append(String.format("%8s", Integer.toBinaryString(c)).replace(' ', '0'));
        }
        return bitStream.toString();
    }

    public static String encryptStream(String bitStream, String key) {
        StringBuilder ciphertext = new StringBuilder();
        for (int i = 0; i < bitStream.length(); i++) {
            ciphertext.append((char) (bitStream.charAt(i) ^ key.charAt(i % key.length())));
        }
        return ciphertext.toString();
    }

    public static String decryptStream(String ciphertext, String key) {
        return encryptStream(ciphertext, key); // XORing twice cancels out the encryption
    }

    public static String bitStreamToText(String bitStream) {
        StringBuilder text = new StringBuilder();
        for (int i = 0; i < bitStream.length(); i += 8) {
            String byteString = bitStream.substring(i, i + 8);
            text.append((char) Integer.parseInt(byteString, 2));
        }
        return text.toString();
    }

    public static void main(String[] args) {
        String message = "Kyle";
        String key = "SecretKey123";

        String bitStream = textToBitStream(message);
        String encryptedMessage = encryptStream(bitStream, key);
        String decryptedMessage = bitStreamToText(decryptStream(encryptedMessage, key));

        System.out.println("Original Message: " + message);
        System.out.println("Bitsteam: " + bitStream);
        System.out.println("Encrypted Message: " + encryptedMessage);
        System.out.println("Decrypted Message: " + decryptedMessage);
    }
    
}
