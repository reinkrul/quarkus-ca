package nl.reinkrul.quarkusca;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.operator.OperatorCreationException;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.event.Observes;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.net.InetAddress;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;

import io.quarkus.runtime.StartupEvent;

@ApplicationScoped
public class CertificateAuthority {

    private static final Logger LOG = LoggerFactory.getLogger(CertificateAuthority.class);

    @ConfigProperty(name = "ca.commonName")
    private String commonName;

    @ConfigProperty(name = "ca.certificate.validity")
    private int validity;

    @ConfigProperty(name = "ca.key.size")
    private int keySize;

    private KeyContainer key;
    private CertificateSigner signer;

    void onStart(@Observes final StartupEvent event) throws GeneralSecurityException, OperatorCreationException, IOException {
        final File caKeyStoreFile = new File("ca" + KeyContainer.KEYSTORE_FILE_EXTENSION);
        final File httpsKeyStoreFile = new File("ca-web" + KeyContainer.KEYSTORE_FILE_EXTENSION);

        key = new KeyContainer("changeit", "ca", caKeyStoreFile.exists() ? caKeyStoreFile : null);
        final X500Name caName = new X500Name("CN=" + commonName);
        if (!caKeyStoreFile.exists()) {
            LOG.info("No CA key material found, a new CA key pair and certificate will be created.");
            generateCaCertificate(caKeyStoreFile, caName);
        }
        signer = new CertificateSigner(caName, key.getPrivateKey());
        if (!httpsKeyStoreFile.exists()) {
            LOG.info("No HTTPS key store found ({}), a new server certificate certificate will be created.", httpsKeyStoreFile);
            generateHttpsCertificate(httpsKeyStoreFile);
        }
    }

    public KeyContainer issueServerCertificate(final CertificateRequest request) {
        LOG.info("Issuing server certificate: {}", request);
        try {
            final KeyPair keyPair = generateKeyPair(keySize);
            final X509Certificate certificate = signer.signServerCertificate(request.toX500Name(), keyPair, validity, generateCertificateSerial());
            final KeyContainer container = new KeyContainer("changeit", "certificate");
            container.set(new X509Certificate[]{ key.getCertificate(), certificate }, keyPair);
            return container;
        } catch (GeneralSecurityException | OperatorCreationException | IOException e) {
            throw new RuntimeException("Unable to issue server certificate.", e);
        }
    }

    public X509Certificate getCertificate() {
        return key.getCertificate();
    }

    private void generateCaCertificate(final File keyStoreFile, final X500Name caName) throws GeneralSecurityException, OperatorCreationException, IOException {
        final KeyPair keyPair = generateKeyPair(keySize);
        final X509Certificate certificate = new CertificateSigner(caName, keyPair.getPrivate()).signCaCertificate(caName, keyPair, validity, generateCertificateSerial());
        key.set(certificate, keyPair);
        key.store(keyStoreFile);
    }

    private void generateHttpsCertificate(final File keyStoreFile) throws IOException {
        final String hostName = InetAddress.getLocalHost().getHostName();
        LOG.info("Generating CA HTTPS certificate for host: {}", hostName);
        issueServerCertificate(new CertificateRequest(hostName, null, null)).store(keyStoreFile);
    }

    private KeyPair generateKeyPair(final int keySize) throws GeneralSecurityException {
        LOG.info("Generating RSA {} bits key pair.", keySize);
        final KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(keySize);
        final long startTime = System.currentTimeMillis();
        try {
            return generator.generateKeyPair();
        } finally {
            LOG.info("Generated RSA key pair in {}ms", System.currentTimeMillis() - startTime);
        }
    }

    private static BigInteger generateCertificateSerial() {
        return BigInteger.valueOf(System.currentTimeMillis());  // Not very safe and quite naive
    }
}
