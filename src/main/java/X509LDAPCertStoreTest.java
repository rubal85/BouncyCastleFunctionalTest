import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;
import com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.schema.ObjectClassDefinition;
import com.unboundid.ldap.sdk.schema.ObjectClassType;
import com.unboundid.ldif.LDIFException;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jce.X509LDAPCertStoreParameters;
import org.bouncycastle.jce.exception.ExtCertPathBuilderException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import junit.framework.TestCase;

import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;
import java.io.*;
import java.net.InetAddress;
import java.security.*;
import java.security.cert.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class X509LDAPCertStoreTest {
    public static void main(String[] args) throws Exception {
        X509LDAPCertStoreTest test = new X509LDAPCertStoreTest();
        test.setUp();
        test.testLdapFilter();
    }

     public void setUp ()
     {
         if (Security.getProvider("BC") == null) {
             Security.addProvider(new BouncyCastleProvider());
         }
     }

     public void testLdapFilter ()
            throws Exception
     {
         BcFilterCheck filterCheck = new BcFilterCheck();

         //start mock ldap server for logging
         InMemoryDirectoryServer ds = mockLdapServer(filterCheck);
         ds.startListening();

         KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");

         kpg.initialize(256);

         //generate malicious certificate
         String subject = "CN=chars[*()\\\0]";
         X509Certificate cert = createSelfSignedCert(new X500Name(subject), "SHA256withECDSA", kpg.generateKeyPair());


       readEntriesFromFile(ds);


         verifyCert(cert);


         ds.shutDown(true);

         assertTrue(filterCheck.isUsed());
     }

    public static X509Certificate createSelfSignedCert(X500Name dn, String sigName, KeyPair keyPair)
            throws Exception
    {
        AtomicLong serialNumber = new AtomicLong(System.currentTimeMillis());
        Map algIds = new HashMap();


            algIds.put("GOST3411withGOST3410", new AlgorithmIdentifier(CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_94));
            algIds.put("SHA1withRSA", new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption, DERNull.INSTANCE));
            algIds.put("SHA256withRSA", new AlgorithmIdentifier(PKCSObjectIdentifiers.sha256WithRSAEncryption, DERNull.INSTANCE));
            algIds.put("SHA1withECDSA", new AlgorithmIdentifier(X9ObjectIdentifiers.ecdsa_with_SHA1));
            algIds.put("SHA256withECDSA", new AlgorithmIdentifier(X9ObjectIdentifiers.ecdsa_with_SHA256));
            algIds.put("Ed448", new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed448));


        V1TBSCertificateGenerator certGen = new V1TBSCertificateGenerator();

        long time = System.currentTimeMillis();

        certGen.setSerialNumber(new ASN1Integer(serialNumber.getAndIncrement()));
        certGen.setIssuer(dn);
        certGen.setSubject(dn);
        certGen.setStartDate(new Time(new Date(time - 5000)));
        certGen.setEndDate(new Time(new Date(time + 30 * 60 * 1000)));
        certGen.setSignature((AlgorithmIdentifier)algIds.get(sigName));
        certGen.setSubjectPublicKeyInfo(SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded()));

        Signature sig = Signature.getInstance(sigName, "BC");

        sig.initSign(keyPair.getPrivate());

        sig.update(certGen.generateTBSCertificate().getEncoded(ASN1Encoding.DER));

        TBSCertificate tbsCert = certGen.generateTBSCertificate();

        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(tbsCert);
        v.add((AlgorithmIdentifier)algIds.get(sigName));
        v.add(new DERBitString(sig.sign()));

        return (X509Certificate)CertificateFactory.getInstance("X.509", "BC").generateCertificate(new ByteArrayInputStream(new DERSequence(v).getEncoded(ASN1Encoding.DER)));
    }
    private static InMemoryDirectoryServer mockLdapServer(BcFilterCheck filterCheck)
            throws Exception
    {
        InMemoryDirectoryServerConfig serverConfig = new InMemoryDirectoryServerConfig("dc=test");
        serverConfig.setListenerConfigs(new InMemoryListenerConfig(
                "listen",
                InetAddress.getByName("0.0.0.0"),
                1389,
                ServerSocketFactory.getDefault(),
                SocketFactory.getDefault(),
                (SSLSocketFactory) SSLSocketFactory.getDefault()));

        serverConfig.addInMemoryOperationInterceptor(filterCheck);

        return new InMemoryDirectoryServer(serverConfig);
    }
    public static void readEntriesFromFile(InMemoryDirectoryServer ds) throws IOException, LDAPException, LDIFException
    {
        InputStream src = TestResourceFinder.findTestResource("ldap/", "X509LDAPCertTest.ldif");
        BufferedReader bin = new BufferedReader(new InputStreamReader(src));
        String line = null;
        List<String> entry = new ArrayList<String>();
        while ((line = bin.readLine()) != null)
        {
            if (line.isEmpty())
            {
                // End of entry, add to list and reset
                if (entry.size() > 0)
                {
                    addEntry(ds, entry.toArray(new String[0]));
                    entry.clear();
                }
            }
            else
            {
                // Add entry line and attributes
                line = line.replaceAll("\\\\0", "\0");
                entry.add(line);
            }
        }
        bin.close();
        if (entry.size() > 0)
        {
            addEntry(ds, entry.toArray(new String[0]));
            entry.clear();
        }

    }


    public static void addEntry(InMemoryDirectoryServer ds, String... args)
            throws LDIFException, LDAPException
    {
        LDAPResult result = ds.add(args);
        assertEquals(0, result.getResultCode().intValue());
    }

    static void verifyCert(X509Certificate cert)
            throws Exception
    {
        // Create the selector that specifies the starting certificate
        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(cert);

        // Load the JDK's trusted certs
        String filename = "C:\\Program Files\\jdk-22.0.1\\lib\\security\\cacerts".replace('/', File.separatorChar);
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(new FileInputStream(filename), "changeit".toCharArray());

        PKIXBuilderParameters pkixParams = new PKIXBuilderParameters(keystore, selector);

        //setup additional LDAP store
        X509LDAPCertStoreParameters CertStoreParameters = new X509LDAPCertStoreParameters.Builder("ldap://127.0.0.1:1389", "CN=certificates").build();
        CertStore certStore = CertStore.getInstance("LDAP", CertStoreParameters, "BC");
        pkixParams.addCertStore(certStore);

        // Build and verify the certification chain
        try
        {
            CertPathBuilder builder = CertPathBuilder.getInstance("PKIX", "BC");
            PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult)builder.build(pkixParams);

        }
        catch (ExtCertPathBuilderException exception)
        {
            //expected to fail with ExtCertPathBuilderException: Error finding target certificate.
        }
    }
}

class BcFilterCheck
        extends InMemoryOperationInterceptor
{
    private volatile boolean used = false;

    public void processSearchResult(InMemoryInterceptedSearchResult result)
    {
        String filter = result.getRequest().getFilter().toString();
        if (filter != null && !filter.isEmpty()) {
            filter = filter.toString();
        assertEquals("(&(cn=*chars[\\28\\29\\00]*)(userCertificate=*))", filter);

        used = true;

        result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
    }else{
        System.out.println("StringOutOfBoundsException");
    }
    }

    boolean isUsed()
    {
        return used;
    }
}
class TestResourceFinder
{
    private static final String dataDirName = "bc-test-data";

    /**
     * We search starting at the working directory looking for the bc-test-data directory.
     *
     * @throws FileNotFoundException
     */
    public static InputStream findTestResource(String homeDir, String fileName)
            throws FileNotFoundException
    {
        String wrkDirName = System.getProperty("user.dir");
        String separator = System.getProperty("file.separator");
        int lastIndex = wrkDirName.lastIndexOf(separator);
        File wrkDir = new File(wrkDirName);
        File dataDir = new File(wrkDir, dataDirName);
        while (!dataDir.exists() && wrkDirName.length() > 1)
        {
            wrkDirName = wrkDirName.substring(0, lastIndex);
            wrkDir = new File(wrkDirName);
            dataDir = new File(wrkDir, dataDirName);
        }

        if (!dataDir.exists())
        {
            String ln = System.getProperty("line.separator");
            throw new FileNotFoundException("Test data directory " + dataDirName + " not found." + ln + "Test data available from: https://github.com/bcgit/bc-test-data.git");
        }

        return new FileInputStream(new File(dataDir, homeDir + separator + fileName));
    }
}
