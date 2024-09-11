import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.security.Security;

public class CipherSpiTest {

    public static void main(String[] args) throws Exception {
        // Add BouncyCastle provider
        Security.addProvider(new BouncyCastleProvider());

        // Create a Cipher instance with the desired algorithm and mode
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding", "BC");

        // Generate a random key
        byte[] keyBytes = new byte[16];
        new SecureRandom().nextBytes(keyBytes);
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");

        // Initialize the cipher for encryption
        cipher.init(Cipher.ENCRYPT_MODE, key);

        // Data to be encrypted
        byte[] plainText = "Hello, world!".getBytes();

        // Encrypt the data
        byte[] cipherText = cipher.doFinal(plainText);

        // Initialize the cipher for decryption
        cipher.init(Cipher.DECRYPT_MODE, key);

        // Decrypt the data
        byte[] decryptedText = cipher.doFinal(cipherText);

        // Verify the decrypted data
        String decryptedString = new String(decryptedText);
        System.out.println("Decrypted text: " + decryptedString);

        // Check if the decrypted text matches the original plain text
        if (decryptedString.equals("Hello, world!")) {
            System.out.println("Cipher operations successful");
        } else {
            System.out.println("Cipher operations failed");
        }
    }
}