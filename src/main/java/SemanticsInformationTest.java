import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.qualified.SemanticsInformation;

import java.io.IOException;

public class SemanticsInformationTest {

    public static void main(String[] args) {
        // Create test data
        ASN1ObjectIdentifier semanticsIdentifier = new ASN1ObjectIdentifier("1.2.3.4.5");
        GeneralName[] nameRegistrationAuthorities = {
                new GeneralName(GeneralName.directoryName, "CN=Example Authority, O=Example Organization"),
                new GeneralName(GeneralName.directoryName, "CN=Another Authority, O=Example Organization")
        };

        // Create SemanticsInformation instance
        SemanticsInformation semanticsInfo = new SemanticsInformation(semanticsIdentifier, nameRegistrationAuthorities);

        // Print the semantics identifier
        System.out.println("Semantics Identifier: " + semanticsInfo.getSemanticsIdentifier());

        // Print the name registration authorities
        System.out.println("Name Registration Authorities:");
        for (GeneralName authority : semanticsInfo.getNameRegistrationAuthorities()) {
            System.out.println(authority.toString());
        }

        // Verify ASN.1 encoding/decoding
        byte[] encodedBytes = new byte[0];
        try {
            encodedBytes = semanticsInfo.toASN1Primitive().getEncoded();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        SemanticsInformation decodedInfo = SemanticsInformation.getInstance(encodedBytes);

        if (!decodedInfo.equals(semanticsInfo)) {
            System.out.println("Error: Encoding/decoding mismatch");
        } else {
            System.out.println("Encoding/decoding successful");
        }
    }
}