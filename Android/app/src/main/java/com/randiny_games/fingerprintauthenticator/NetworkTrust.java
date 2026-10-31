package com.randiny_games.fingerprintauthenticator;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

/** Re-run for EVERY connection, including resumed sessions that skip TrustManager. */
final class NetworkTrust {
    static void check(Certificate certificate, String pin) throws CertificateException {
        check(certificate, pin, new Date());
    }
    static void check(Certificate certificate, String pin, Date now) throws CertificateException {
        try {
            if (!(certificate instanceof X509Certificate) || pin == null || !pin.matches("[0-9a-f]{64}"))
                throw new CertificateException("Invalid pinned client certificate");
            ((X509Certificate) certificate).checkValidity(now);
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded());
            StringBuilder digest = new StringBuilder(64);
            for (byte b : hash) digest.append(String.format("%02x", b & 255));
            if (!MessageDigest.isEqual(pin.getBytes(StandardCharsets.US_ASCII),
                    digest.toString().getBytes(StandardCharsets.US_ASCII)))
                throw new CertificateException("Unpaired desktop certificate");
        } catch (CertificateException error) { throw error; }
        catch (Exception error) { throw new CertificateException("Invalid client certificate", error); }
    }
    private NetworkTrust() {}
}
