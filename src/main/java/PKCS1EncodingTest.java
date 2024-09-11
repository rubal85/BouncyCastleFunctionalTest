import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.RSADigestSigner;
import org.bouncycastle.util.encoders.Base64;
//import org.junit.Test;

import java.math.BigInteger;
import java.security.SecureRandom;

public class PKCS1EncodingTest {


    public static void main(String[] args) throws Exception {
        testPKCS1Encoding();
    }
    //@Test
    public static void testPKCS1Encoding() throws Exception {
        // Generate RSA key pair
        //SecureRandom random = new SecureRandom();
        //int certainty = 100; // Adjust certainty as needed
        //int publicExponent = 10;

        // **Corrected constructor call:**
        RSAKeyGenerationParameters params = new RSAKeyGenerationParameters(BigInteger.valueOf(0x11), new SecureRandom(), 512, 25);

        RSAKeyPairGenerator keyPairGenerator = new RSAKeyPairGenerator();
        keyPairGenerator.init(params);
        AsymmetricCipherKeyPair keyPair = keyPairGenerator.generateKeyPair();

        // Print public and private key details (modulus and exponent)
        System.out.println("Public Key:");
        RSAKeyParameters publicKey = (RSAKeyParameters) keyPair.getPublic();
        System.out.println("  Modulus: " + publicKey.getModulus());
        System.out.println("  Exponent: " + publicKey.getExponent());

        System.out.println("\nPrivate Key:");
        RSAKeyParameters privateKey = (RSAKeyParameters) keyPair.getPrivate();
        System.out.println("  Modulus: " + privateKey.getModulus());
        System.out.println("  Exponent: " + privateKey.getExponent());


        // Create RSADigestSigner instance
        SHA256Digest digest = new SHA256Digest();
        RSADigestSigner signer = new RSADigestSigner(digest);
        signer.init(true, keyPair.getPrivate());

        // Data to be signed
        byte[] data = "Hello, world!".getBytes();

        // Sign the data
        byte[] signature = signer.generateSignature();

        // Verify the signature
        signer.init(false, keyPair.getPublic());
        boolean isVerified = signer.verifySignature(data);

        // Assert that the signature is verified
        assert isVerified;
    }
}