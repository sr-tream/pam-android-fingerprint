package com.randiny_games.fingerprintauthenticator;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/** Shareable pairing data: only a public-key digest, never key material. */
final class PairingInfo {
    private final String fingerprint;

    PairingInfo(byte[] publicKey) throws NoSuchAlgorithmException {
        if (publicKey == null || publicKey.length == 0) {
            throw new IllegalArgumentException("Missing public key");
        }
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(publicKey);
        char[] hex = new char[digest.length * 2];
        String digits = "0123456789abcdef";
        for (int i = 0; i < digest.length; i++) {
            hex[2 * i] = digits.charAt((digest[i] & 255) >>> 4);
            hex[2 * i + 1] = digits.charAt(digest[i] & 15);
        }
        fingerprint = new String(hex);
    }

    String fingerprint() {
        return fingerprint;
    }

    String groupedFingerprint() {
        StringBuilder grouped = new StringBuilder(71);
        for (int i = 0; i < fingerprint.length(); i += 8) {
            if (i != 0) grouped.append('-');
            grouped.append(fingerprint, i, i + 8);
        }
        return grouped.toString();
    }
}
