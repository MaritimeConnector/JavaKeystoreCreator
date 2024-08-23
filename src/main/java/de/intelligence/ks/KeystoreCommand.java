package de.intelligence.ks;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;

import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import picocli.CommandLine;

@CommandLine.Command(name = "CreateKeystore", mixinStandardHelpOptions = true, version = "1.0",
        description = "Create a PKCS#12 keystore from a public certificate and private key files.")
public final class KeystoreCommand implements Runnable {

    @CommandLine.Option(names = {"-c", "--cert"}, required = true, description = "Public certificate file (PEM format)")
    private Path certFile;

    @CommandLine.Option(names = {"-k", "--key"}, required = true, description = "Private key file (PEM format)")
    private Path keyFile;

    @CommandLine.Option(names = {"-o", "--output"}, required = true, description = "Output PKCS#12 keystore file")
    private Path outputFile;

    @CommandLine.Option(names = {"-a", "--alias"}, description = "Key alias")
    private String alias = "1";

    @CommandLine.Option(names = {"-p", "--password"}, required = true, description = "Keystore password")
    private String password;

    @Override
    public void run() {
        try {
            this.execute();
        } catch (GeneralSecurityException | IOException ex) {
            throw new RuntimeException("Failed to create keystore", ex);
        }
    }

    private void execute() throws GeneralSecurityException, IOException {
        // Register Bouncy Castle as security provider
        Provider provider = new BouncyCastleProvider();
        Security.addProvider(provider);

        // Read certificate
        final X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new FileInputStream(this.certFile.toFile()));

        // Read private key
        final PemObject pemObject;
        try (PemReader reader = new PemReader(new InputStreamReader(new FileInputStream(this.keyFile.toFile())))) {
            pemObject = reader.readPemObject();
        }
        final ECPrivateKey ecPrivateKey = (ECPrivateKey) KeyFactory.getInstance("EC", "BC")
                .generatePrivate(new PKCS8EncodedKeySpec(pemObject.getContent()));

        // Create key store
        final KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        keyStore.setKeyEntry(this.alias, ecPrivateKey, this.password.toCharArray(), new Certificate[]{cert});

        // Write key store
        final FileOutputStream keyOut = new FileOutputStream(this.outputFile.toFile());
        keyStore.store(keyOut, this.password.toCharArray());
        keyOut.close();

        System.out.println("Stored keystore at " + this.outputFile.toAbsolutePath());
    }

}
