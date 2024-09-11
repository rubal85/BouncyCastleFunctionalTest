import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tls.*;
import org.bouncycastle.tls.test.TlsTestUtils;

import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.TlsDHConfig;
import org.bouncycastle.tls.crypto.TlsECConfig;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.io.PrintStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Hashtable;
import java.util.Vector;

public class TlsRSAKeyExchangeTest {

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        // Create a server socket
        ServerSocket serverSocket = new ServerSocket(4433);

        // Create a client socket
        Socket clientSocket = new Socket("localhost", 4433);

        // Accept a connection from the client and get input/output streams
        Socket serverSocketConnection = serverSocket.accept();
        TlsServerProtocol tlsServer = new TlsServerProtocol(serverSocketConnection.getInputStream(), serverSocketConnection.getOutputStream());

        // Create a TLS client using the client socket's streams
        TlsClientProtocol tlsClient = new TlsClientProtocol(clientSocket.getInputStream(), clientSocket.getOutputStream());

        // Perform the TLS handshake
        tlsServer.accept(new MockTlsServer()); // Pass the TLS client to the server

        // Inspect handshake messages and verify RSA key exchange

        // Test encryption and decryption

        // Close sockets and connections
        tlsServer.close();
        tlsClient.close();
        clientSocket.close();
        serverSocket.close();
    }
    static class MockTlsServer
            extends DefaultTlsServer
    {
        MockTlsServer()
        {
            super(new BcTlsCrypto(new SecureRandom()));
        }

        protected Vector getProtocolNames()
        {
            Vector protocolNames = new Vector();
            protocolNames.addElement(ProtocolName.HTTP_2_TLS);
            protocolNames.addElement(ProtocolName.HTTP_1_1);
            return protocolNames;
        }

        public void notifyAlertRaised(short alertLevel, short alertDescription, String message, Throwable cause)
        {
            PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
            out.println("TLS server raised alert: " + AlertLevel.getText(alertLevel)
                    + ", " + AlertDescription.getText(alertDescription));
            if (message != null)
            {
                out.println("> " + message);
            }
            if (cause != null)
            {
                cause.printStackTrace(out);
            }
        }

        public void notifyAlertReceived(short alertLevel, short alertDescription)
        {
            PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
            out.println("TLS server received alert: " + AlertLevel.getText(alertLevel)
                    + ", " + AlertDescription.getText(alertDescription));
        }

        public ProtocolVersion getServerVersion() throws IOException
        {
            ProtocolVersion serverVersion = super.getServerVersion();

            System.out.println("TLS server negotiated " + serverVersion);

            return serverVersion;
        }

        public CertificateRequest getCertificateRequest() throws IOException
        {
            short[] certificateTypes = new short[]{ ClientCertificateType.rsa_sign,
                    ClientCertificateType.dss_sign, ClientCertificateType.ecdsa_sign };

            Vector serverSigAlgs = null;
            if (TlsUtils.isSignatureAlgorithmsExtensionAllowed(context.getServerVersion()))
            {
                serverSigAlgs = TlsUtils.getDefaultSupportedSignatureAlgorithms(context);
            }

            Vector certificateAuthorities = new Vector();
//      certificateAuthorities.addElement(TlsTestUtils.loadBcCertificateResource("x509-ca-dsa.pem").getSubject());
//      certificateAuthorities.addElement(TlsTestUtils.loadBcCertificateResource("x509-ca-ecdsa.pem").getSubject());
//      certificateAuthorities.addElement(TlsTestUtils.loadBcCertificateResource("x509-ca-rsa.pem").getSubject());

            // All the CA certificates are currently configured with this subject
            certificateAuthorities.addElement(new X500Name("CN=BouncyCastle TLS Test CA"));

            return new CertificateRequest(certificateTypes, serverSigAlgs, certificateAuthorities);
        }

        public void notifyClientCertificate(org.bouncycastle.tls.Certificate clientCertificate) throws IOException {

            if (clientCertificate == null || clientCertificate.isEmpty()) {
                System.out.println("Client did not present a certificate.");
                return;
            }
            TlsCertificate[] chain = clientCertificate.getCertificateList();

            System.out.println("TLS server received client certificate chain of length " + chain.length);
            for (int i = 0; i != chain.length; i++) {
                org.bouncycastle.asn1.x509.Certificate entry = org.bouncycastle.asn1.x509.Certificate.getInstance(chain[i].getEncoded());
                // TODO Create fingerprint based on certificate signature algorithm digest
                System.out.println("    fingerprint:SHA-256 " + " ("
                        + entry.getSubject() + ")");
            }

            boolean isEmpty = (clientCertificate == null || clientCertificate.isEmpty());

            if (isEmpty) {
                return;
            }

            String[] trustedCertResources = new String[]{ "x509-client-dsa.pem", "x509-client-ecdh.pem",
                    "x509-client-ecdsa.pem", "x509-client-ed25519.pem", "x509-client-ed448.pem", "x509-client-rsa_pss_256.pem",
                    "x509-client-rsa_pss_384.pem", "x509-client-rsa_pss_512.pem", "x509-client-rsa.pem" };

            // Prefer public methods or upgrade BouncyCastle if possible
            TlsCertificate[] certPath = getTrustedCertPathUsingPublicMethods(context.getCrypto(), chain[0], trustedCertResources);

            if (certPath == null) {
                throw new TlsFatalAlert(AlertDescription.bad_certificate);
            }

            TlsUtils.checkPeerSigAlgs(context, certPath);
        }

        private static TlsCertificate[] getTrustedCertPathUsingPublicMethods(TlsCrypto crypto, TlsCertificate certificate, String[] trustedCertResources) {
            // Implement using public methods or alternative libraries, if available
            // For example:
            // TlsCertificate[] certPath = TlsUtils.getTrustedCertPath(crypto, certificate, trustedCertResources);
            // return certPath;

            // If no public alternatives are found, you can use reflection as a last resort:
            try {
                Method method = TlsTestUtils.class.getDeclaredMethod("getTrustedCertPath", TlsCrypto.class, TlsCertificate.class, String[].class);
                method.setAccessible(true);
                return (TlsCertificate[]) method.invoke(null, crypto, certificate, trustedCertResources);
            } catch (NoSuchMethodException | IllegalAccessException | InvocationTargetException e) {
                try {
                    throw new IOException("Error getting trusted certificate path", e);
                } catch (IOException ex) {
                    throw new RuntimeException(ex);
                }
            }
        }

        public void notifyHandshakeComplete() throws IOException
        {
            super.notifyHandshakeComplete();

            ProtocolName protocolName = context.getSecurityParametersConnection().getApplicationProtocol();
            if (protocolName != null)
            {
                System.out.println("Server ALPN: " + protocolName.getUtf8Decoding());
            }

            byte[] tlsServerEndPoint = context.exportChannelBinding(ChannelBinding.tls_server_end_point);
            System.out.println("Server 'tls-server-end-point': " + hex(tlsServerEndPoint));

            byte[] tlsUnique = context.exportChannelBinding(ChannelBinding.tls_unique);
            System.out.println("Server 'tls-unique': " + hex(tlsUnique));
        }

        private static TlsCredentialedDecryptor getEncryptionCredentials(TlsContext context, String[] certificateResources, String keyResource) throws IOException {
            try {
                Method method = TlsTestUtils.class.getDeclaredMethod("loadEncryptionCredentials", TlsContext.class, String[].class, String.class);
                method.setAccessible(true);
                return (TlsCredentialedDecryptor) method.invoke(null, context, certificateResources, keyResource);
            } catch (NoSuchMethodException | IllegalAccessException | InvocationTargetException e) {
                throw new IOException("Error loading encryption credentials", e);
            }
        }

        private static TlsCredentialedSigner loadSignerCredentialsServer(TlsContext context, Vector clientSigAlgs, short signatureAlgorithm) throws IOException {
            try {
                Method method = TlsTestUtils.class.getDeclaredMethod("loadSignerCredentialsServer", TlsContext.class, Vector.class, short.class);
                method.setAccessible(true);
                return (TlsCredentialedSigner) method.invoke(null, context, clientSigAlgs, signatureAlgorithm);
            } catch (NoSuchMethodException | IllegalAccessException | InvocationTargetException e) {
                throw new IOException("Error loading signer credentials", e);
            }
        }

        protected String hex(byte[] data)
        {
            return data == null ? "(null)" : Hex.toHexString(data);
        }
    }


}

