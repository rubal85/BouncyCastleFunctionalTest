import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.icao.DataGroupHash;
import org.bouncycastle.asn1.icao.LDSSecurityObject;
import org.bouncycastle.asn1.icao.LDSVersionInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.X509Name;

import java.io.IOException;
import java.util.logging.Logger;

public class LDSSecurityObjectTest {

    private final Logger logger = Logger.getLogger(LDSSecurityObjectTest.class.getName());

    // Test cases

    private static ASN1ObjectIdentifier getAlgorithmOID(String algorithmName) {
        if (algorithmName.equals("SHA-256")) {
            return new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.1"); // OID for SHA-256
        } else {
            // Implement logic to handle other algorithms and their OIDs
            throw new IllegalArgumentException("Unsupported algorithm: " + algorithmName);
        }
    }

    public void testValidData() throws IOException {

        AlgorithmIdentifier digestAlgorithmIdentifier = new AlgorithmIdentifier(getAlgorithmOID("SHA-256"));
        DataGroupHash[] dataGroupHash = {
                new DataGroupHash(1, new DEROctetString(new byte[]{1, 2, 3})),
                new DataGroupHash(2, new DEROctetString(new byte[]{4, 5, 6}))
        };
        LDSVersionInfo versionInfo = new LDSVersionInfo("1.0", "Version 1.0");

        // Create LDSSecurityObject
        LDSSecurityObject ldsSecurityObject = new LDSSecurityObject(digestAlgorithmIdentifier, dataGroupHash, versionInfo);

        // Convert to ASN.1 sequence
        byte[] encodedData = ldsSecurityObject.toASN1Primitive().getEncoded();

        System.out.println("Encoded data (hex):");
        for (byte b : encodedData) {
            System.out.printf("%02X ", b); // Print encoded data in hex format
        }
        System.out.println();

        ASN1InputStream asn1InputStream = new ASN1InputStream(encodedData);
        ASN1Sequence asn1Sequence = (ASN1Sequence) asn1InputStream.readObject();

        System.out.println("ASN.1 sequence size: " + asn1Sequence.size());

        // You can further inspect the ASN.1 sequence elements here
        // ...
    }

    public void testInvalidDataGroupHashSize() {
        // Test with size less than 2
        AlgorithmIdentifier digestAlgorithmIdentifier = null;
        try {
            new LDSSecurityObject(digestAlgorithmIdentifier, new DataGroupHash[1]);
            logger.severe("Expected IllegalArgumentException for size less than 2");
        } catch (IllegalArgumentException e) {
            // Expected exception
        }

        // Test with size greater than ub_DataGroups
        try {
            DataGroupHash[] dataGroupHash = new DataGroupHash[LDSSecurityObject.ub_DataGroups + 1];
            new LDSSecurityObject(digestAlgorithmIdentifier, dataGroupHash);
            logger.severe("Expected IllegalArgumentException for size greater than ub_DataGroups");
        } catch (IllegalArgumentException e) {
            // Expected exception
        }
    }





    public static void main(String[] args) throws IOException {
        LDSSecurityObjectTest test = new LDSSecurityObjectTest();
        test.testValidData();
        test.testInvalidDataGroupHashSize();

    }
}