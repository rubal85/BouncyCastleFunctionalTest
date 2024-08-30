package org.example;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.asn1.x9.X9ECParameters;
//import org.bouncycastle.crypto.util.ECKeyUtil;
//import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

import java.math.BigInteger;
import java.security.Security;
import java.security.SecureRandom;

public class ECCurveF2mDemo {
    public static void main(String[] args) {
        // Add Bouncy Castle as a security provider
        Security.addProvider(new BouncyCastleProvider());
/*
        // Define the parameters for the binary field elliptic curve
        int m = 163; // Field size (e.g., 163 bits)
        int k1 = 3;
        int k2 = 6;
        int k3 = 7;

        // Create the binary field elliptic curve (F2m)
        ECCurve.F2m curve = new ECCurve.F2m(m, k1, k2, k3,
                new BigInteger("1"), // a coefficient
                new BigInteger("1")); // b coefficient

        // Generate key pair
        AsymmetricCipherKeyPair keyPair = generateKeyPair(curve);

                // Define the base point (G) and the order (n) of the curve
        ECPoint G = curve.createPoint(new BigInteger("2"), new BigInteger("3"));
        BigInteger n = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16);
*/

        // Load predefined curve parameters (sect163r2)
        X9ECParameters ecParams = org.bouncycastle.crypto.ec.CustomNamedCurves.getByName("sect163r2");
        if (ecParams == null) {
            throw new IllegalArgumentException("Curve not found");
        }

        ECCurve curve = ecParams.getCurve();
        ECPoint G = ecParams.getG();
        BigInteger n = ecParams.getN();
        BigInteger h = ecParams.getH();
        ECDomainParameters domainParameters = new ECDomainParameters(curve, G, n, h);

        // Generate key pair
        AsymmetricCipherKeyPair keyPair = generateKeyPair(domainParameters);
        ECPrivateKeyParameters privateKeyParams = (ECPrivateKeyParameters) keyPair.getPrivate();
        ECPublicKeyParameters publicKeyParams = (ECPublicKeyParameters) keyPair.getPublic();

        BigInteger privateKey = privateKeyParams.getD();
        ECPoint publicKey = publicKeyParams.getQ();

        System.out.println("Private Key: " + privateKey.toString(16));
        System.out.println("Public Key: " + publicKey);

        // Sign a message
        String message = "Hello, Bouncy Castle!";
        BigInteger[] signature = signMessage(privateKey, message.getBytes(), domainParameters);
        System.out.println("Signature: r=" + signature[0].toString(16) + ", s=" + signature[1].toString(16));

        // Verify the signature
        boolean isVerified = verifySignature(publicKey, message.getBytes(), signature, domainParameters);
        System.out.println("Signature Verified: " + isVerified);
    }
/*
    public static AsymmetricCipherKeyPair generateKeyPair(ECCurve.F2m curve) {
        ECKeyPairGenerator keyPairGenerator = new ECKeyPairGenerator();
        SecureRandom random = new SecureRandom();
        ECKeyGenerationParameters keyGenParams = new ECKeyGenerationParameters(new ECPublicKeyParameters(curve.getInfinity(), null).getParameters(), random);
        keyPairGenerator.init(keyGenParams);

        return keyPairGenerator.generateKeyPair();
    }
    */
/*
    public static AsymmetricCipherKeyPair generateKeyPair(ECDomainParameters domainParameters) {
        ECKeyPairGenerator keyPairGenerator = new ECKeyPairGenerator();
        SecureRandom random = new SecureRandom();
        ECKeyGenerationParameters keyGenParams = new ECKeyGenerationParameters(domainParameters, random);
        keyPairGenerator.init(keyGenParams);

        return keyPairGenerator.generateKeyPair();
    }
*/
    public static AsymmetricCipherKeyPair generateKeyPair(ECDomainParameters domainParameters) {
        ECKeyPairGenerator keyPairGenerator = new ECKeyPairGenerator();
        SecureRandom random = new SecureRandom();
        ECKeyGenerationParameters keyGenParams = new ECKeyGenerationParameters(domainParameters, random);
        keyPairGenerator.init(keyGenParams);

        return keyPairGenerator.generateKeyPair();
    }

    public static BigInteger[] signMessage(BigInteger privateKey, byte[] message, ECDomainParameters domainParameters) {
        ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
        ECPrivateKeyParameters privateKeyParams = new ECPrivateKeyParameters(privateKey, domainParameters);
        signer.init(true, privateKeyParams);
        return signer.generateSignature(message);
    }

    public static boolean verifySignature(ECPoint publicKey, byte[] message, BigInteger[] signature, ECDomainParameters domainParameters) {
        ECDSASigner signer = new ECDSASigner();
        ECPublicKeyParameters publicKeyParams = new ECPublicKeyParameters(publicKey, domainParameters);
        signer.init(false, publicKeyParams);
        return signer.verifySignature(message, signature[0], signature[1]);
    }
}

