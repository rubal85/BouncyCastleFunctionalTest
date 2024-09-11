import java.security.*;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsCryptoException;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.tls.crypto.impl.bc.BcDefaultTlsCredentialedDecryptor;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCertificate;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCertificate;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCryptoProvider;
import org.bouncycastle.tls.test.TlsTestUtils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;

import static org.bouncycastle.tls.CachedInformationType.cert;

public class BcDefaultTlsCredentialedDecryptorTest {

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        // Generate RSA key pair (assuming server private key)
        RSAKeyPairGenerator keyPairGenerator = new RSAKeyPairGenerator();
       // keyPairGenerator.initialize(2048);
        RSAKeyGenerationParameters keyGenParams = new RSAKeyGenerationParameters(2048, SecureRandom.getInstance("SHA1PRNG"));
        keyPairGenerator.init(keyGenParams);
        AsymmetricCipherKeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = (PrivateKey) keyPair.getPrivate();
        PublicKey publicKey = (PublicKey) keyPair.getPublic();

        // Mock a certificate (replace with your actual certificate logic)
        JcaTlsCrypto crypto = (JcaTlsCrypto)new JcaTlsCryptoProvider().create(new SecureRandom());

                X509Certificate cert = ((JcaTlsCertificate) TlsTestUtils.loadCertificateResource(crypto,
                "x509-server-rsa-sign.pem")).getX509Certificate();
        Certificate bcCert = new Certificate(null, cert.getEncoded()); // Convert X509Certificate to BcTlsCertificate

        // Simulate encrypted pre-master secret (dummy data for testing)
        byte[] encryptedPreMasterSecret = new byte[48];
        new SecureRandom().nextBytes(encryptedPreMasterSecret);

        // Create BcTlsCrypto instance
        BcTlsCrypto bctlscrypto = new BcTlsCrypto(new SecureRandom());

        // Decryptor with server private key and certificate
        BcDefaultTlsCredentialedDecryptor decryptor = new BcDefaultTlsCredentialedDecryptor(bctlscrypto, bcCert, (AsymmetricKeyParameter) privateKey);

        // Simulate TLS crypto parameters (replace with actual values)
        TlsCryptoParameters cryptoParams = new TlsCryptoParameters.Builder().build();

        try {
            // Decrypt the pre-master secret
            TlsSecret decryptedSecret = decryptor.decrypt(cryptoParams, encryptedPreMasterSecret);
            System.out.println("Decryption successful!");
        } catch (Exception e) {
            System.out.println("Decryption failed: " + e.getMessage());
        }
    }

   /* private static X509Certificate generateDummyCertificate(PublicKey publicKey) throws IOException {
        // Replace this logic with your actual certificate creation process
        // This is just a placeholder to create a basic certificate for testing purposes
        // You might want to use libraries like BouncyCastle to create a proper certificate

        // Assuming a self-signed certificate for simplicity
        // ... (certificate generation logic) ...

        // Mock certificate (replace with actual certificate data)
        byte[] certData = new byte[100]; // Replace with actual certificate data
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(certData));

        return cert;
    }*/


    public static X509Certificate parseCertificate(JcaJceHelper helper, byte[] encoding)
            throws IOException
    {
        try
        {
            /*
             * NOTE: We want to restrict 'encoding' to a binary BER encoding, but
             * CertificateFactory.generateCertificate claims to require DER encoding, and also
             * supports Base64 encodings (in PEM format), which we don't support.
             *
             * Re-encoding validates as BER and produces DER.
             */
            ASN1Primitive asn1 = TlsUtils.readASN1Object(encoding);
            byte[] derEncoding = org.bouncycastle.asn1.x509.Certificate.getInstance(asn1).getEncoded(ASN1Encoding.DER);

            ByteArrayInputStream input = new ByteArrayInputStream(derEncoding);
            X509Certificate certificate = (X509Certificate)helper.createCertificateFactory("X.509")
                    .generateCertificate(input);
            if (input.available() != 0)
            {
                throw new IOException("Extra data detected in stream");
            }
            return certificate;
        }
        catch (GeneralSecurityException e)
        {
            throw new TlsCryptoException("unable to decode certificate", e);
        }
    }
}
