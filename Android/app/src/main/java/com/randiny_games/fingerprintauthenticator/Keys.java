package com.randiny_games.fingerprintauthenticator;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.security.keystore.KeyInfo;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.spec.ECGenParameterSpec;

final class Keys {
    private static final String ALIAS = "pam-fingerprint-v2";

    static synchronized PrivateKey privateKey() throws Exception {
        KeyStore store = KeyStore.getInstance("AndroidKeyStore");
        store.load(null);
        if (!store.containsAlias(ALIAS)) {
            KeyPairGenerator generator = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
            generator.initialize(new KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setUserAuthenticationRequired(true)
                    .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                    .setInvalidatedByBiometricEnrollment(true)
                    .build());
            generator.generateKeyPair();
        }
        // An invalidated key is deliberately NOT regenerated automatically.
        PrivateKey key = (PrivateKey) store.getKey(ALIAS, null);
        KeyInfo info = KeyFactory.getInstance(key.getAlgorithm(), "AndroidKeyStore")
                .getKeySpec(key, KeyInfo.class);
        if (!info.isInsideSecureHardware() ||
                !info.isUserAuthenticationRequirementEnforcedBySecureHardware() ||
                !info.isUserAuthenticationRequired() ||
                info.getUserAuthenticationType() != KeyProperties.AUTH_BIOMETRIC_STRONG ||
                info.getUserAuthenticationValidityDurationSeconds() > 0 ||
                !info.isInvalidatedByBiometricEnrollment()) {
            throw new SecurityException("Key is not hardware-backed, biometric-only and auth-per-use");
        }
        return key;
    }

    static byte[] publicKey() throws Exception {
        KeyStore store = KeyStore.getInstance("AndroidKeyStore");
        store.load(null);
        return store.getCertificate(ALIAS).getPublicKey().getEncoded();
    }
}
