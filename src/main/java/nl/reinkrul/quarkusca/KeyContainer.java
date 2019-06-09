package nl.reinkrul.quarkusca;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class KeyContainer {

    private static final Logger LOG = LoggerFactory.getLogger(KeyContainer.class);
    public static final String KEYSTORE_TYPE = "JCEKS";
    public static final String KEYSTORE_FILE_EXTENSION = ".jceks";

    private final String password;
    private final String alias;

    private PrivateKey privateKey;
    private X509Certificate[] chain;

    public KeyContainer(final String password, final String alias) throws IOException {
        this(password, alias, null);
    }

    public KeyContainer(final String password, final String alias, final File file) throws IOException {
        this.password = password;
        this.alias = alias;
        if (file != null) {
            load(file);
        }
    }

    private void load(final File file) throws IOException {
        LOG.info("Loading key material from {}", file);
        try {
            final KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
            keyStore.load(new FileInputStream(file), password.toCharArray());
            privateKey = (PrivateKey) keyStore.getKey(alias, password.toCharArray());
            chain = new X509Certificate[]{ (X509Certificate) keyStore.getCertificate(alias) };
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException | CertificateException e) {
            throw new IOException("Unable to load key store.", e);
        }
    }

    public void set(final X509Certificate certificate, final KeyPair key) {
        set(new X509Certificate[]{ certificate }, key);
    }

    public void set(final X509Certificate[] chain, final KeyPair key) {
        this.chain = chain;
        this.privateKey = key.getPrivate();
    }

    public void store(final File file) throws IOException {
        try (final FileOutputStream outputStream = new FileOutputStream(file)) {
            store(outputStream);
        }
    }

    public void store(final OutputStream outputStream) throws IOException {
        try {
            final KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
            keyStore.load(null, password.toCharArray());
            keyStore.setKeyEntry(alias, privateKey, password.toCharArray(), chain);
            keyStore.store(outputStream, password.toCharArray());
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            throw new IOException("Unable to store key material.", e);
        }
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public X509Certificate getCertificate() {
        return chain[chain.length - 1];
    }
}
