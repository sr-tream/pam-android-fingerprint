package com.randiny_games.fingerprintauthenticator;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import java.math.BigInteger;
import java.net.Socket;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;

/** Channel identity only. This key can NEVER replace the biometric signing key. */
final class NetworkKeys {
    private static final String ALIAS = "pam-network-tls-v1";

    private static synchronized KeyStore store() throws Exception {
        KeyStore store = KeyStore.getInstance("AndroidKeyStore");
        store.load(null);
        if (!store.containsAlias(ALIAS)) {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", "AndroidKeyStore");
            generator.initialize(new KeyGenParameterSpec.Builder(ALIAS,
                    KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                    .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                    // Conscrypt signs precomputed TLS transcript hashes with NONEwithECDSA.
                    // This is ONLY the channel key; Keys.java keeps its strict biometric policy.
                    .setDigests(KeyProperties.DIGEST_NONE, KeyProperties.DIGEST_SHA256)
                    .setCertificateSubject(new X500Principal("CN=PAM phone TLS server"))
                    .setCertificateSerialNumber(BigInteger.ONE)
                    .setCertificateNotBefore(new Date(0))
                    .setCertificateNotAfter(new Date(4102444800000L))
                    .setUserAuthenticationRequired(false)
                    .build());
            generator.generateKeyPair();
        }
        return store;
    }

    static String certificateFingerprint() throws Exception {
        return digest(store().getCertificate(ALIAS).getEncoded());
    }

    static synchronized void resetCertificate() throws Exception {
        KeyStore store = KeyStore.getInstance("AndroidKeyStore");
        store.load(null);
        if (store.containsAlias(ALIAS)) store.deleteEntry(ALIAS);
    }

    static String digest(byte[] bytes) throws Exception {
        byte[] hash = MessageDigest.getInstance("SHA-256").digest(bytes);
        StringBuilder out = new StringBuilder(64);
        for (byte b : hash) out.append(String.format("%02x", b & 255));
        return out.toString();
    }

    static SSLContext serverContext(String clientPin) throws Exception {
        final String expected = NetworkConfig.fingerprint(clientPin);
        final KeyStore store = store();
        final X509Certificate certificate = (X509Certificate) store.getCertificate(ALIAS);
        final PrivateKey key = (PrivateKey) store.getKey(ALIAS, null);
        X509ExtendedKeyManager manager = new X509ExtendedKeyManager() {
            private String alias(String type) { return type != null && type.startsWith("EC") ? ALIAS : null; }
            @Override public String[] getClientAliases(String type, Principal[] issuers) { return null; }
            @Override public String chooseClientAlias(String[] types, Principal[] issuers, Socket socket) { return null; }
            @Override public String[] getServerAliases(String type, Principal[] issuers) {
                return alias(type) == null ? null : new String[] {ALIAS};
            }
            @Override public String chooseServerAlias(String type, Principal[] issuers, Socket socket) {
                return alias(type);
            }
            @Override public String chooseEngineServerAlias(String type, Principal[] issuers, SSLEngine engine) {
                return alias(type);
            }
            @Override public X509Certificate[] getCertificateChain(String alias) {
                return ALIAS.equals(alias) ? new X509Certificate[] {certificate} : null;
            }
            @Override public PrivateKey getPrivateKey(String alias) { return ALIAS.equals(alias) ? key : null; }
        };
        X509TrustManager trust = new X509TrustManager() {
            @Override public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
            @Override public void checkServerTrusted(X509Certificate[] chain, String type) throws CertificateException {
                throw new CertificateException("Client certificates only");
            }
            @Override public void checkClientTrusted(X509Certificate[] chain, String type) throws CertificateException {
                try {
                    if (chain == null || chain.length == 0 || chain.length > 4)
                        throw new CertificateException("Missing client certificate");
                    NetworkTrust.check(chain[0], expected);
                } catch (CertificateException error) { throw error; }
                catch (Exception error) { throw new CertificateException("Invalid client certificate", error); }
            }
        };
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(new javax.net.ssl.KeyManager[] {manager}, new javax.net.ssl.TrustManager[] {trust}, null);
        return context;
    }
    private NetworkKeys() {}
}
