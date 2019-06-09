package nl.reinkrul.quarkusca;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

public class CertificateSigner {

    private static final String ALGORITHM = "SHA256withRSA";
    private static final long MILLIS_PER_DAY = 1000 * 60 * 60 * 24;

    private final X500Name caName;
    private final PrivateKey caKey;

    public CertificateSigner(final X500Name caName, final PrivateKey caKey) {
        this.caName = caName;
        this.caKey = caKey;
    }

    public X509Certificate signCaCertificate(final X500Name endEntity, final KeyPair endEntityKey, final int validityInDays, final BigInteger serial) throws IOException,
            CertificateException, OperatorCreationException {
        final List<Extension> extensions = Arrays.asList(
                new Extension(Extension.basicConstraints, true, new BasicConstraints(true).getEncoded()),
                new Extension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign).getEncoded())
        );
        return sign(endEntity, endEntityKey, validityInDays, serial, extensions);
    }

    public X509Certificate signServerCertificate(final X500Name endEntity, final KeyPair endEntityKey, final int validityInDays, final BigInteger serial)
            throws CertificateException, OperatorCreationException, IOException {
        final List<Extension> extensions = Arrays.asList(
                new Extension(Extension.basicConstraints, true, new BasicConstraints(false).getEncoded()),
                new Extension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment).getEncoded()),
                new Extension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth).getEncoded())
        );
        return sign(endEntity, endEntityKey, validityInDays, serial, extensions);
    }

    private X509Certificate sign(final X500Name endEntity, final KeyPair endEntityKey, final int validityInDays, final BigInteger serial, final Iterable<Extension> extensions)
            throws CertificateException, OperatorCreationException, CertIOException {
        final Date validFrom = new Date(System.currentTimeMillis());
        final Date validUntil = new Date(validFrom.getTime() + (validityInDays * MILLIS_PER_DAY));
        final ContentSigner signer = new JcaContentSignerBuilder(ALGORITHM).build(caKey);
        final X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(caName, serial, validFrom, validUntil, endEntity, endEntityKey.getPublic());

        for (final Extension extension : extensions) {
            certificateBuilder.addExtension(extension);
        }

        return new JcaX509CertificateConverter().getCertificate(certificateBuilder.build(signer));
    }
}
