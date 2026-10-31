package com.randiny_games.fingerprintauthenticator;

import android.app.Activity;
import android.graphics.Color;
import android.hardware.biometrics.BiometricManager;
import android.hardware.biometrics.BiometricPrompt;
import android.os.Bundle;
import android.os.CancellationSignal;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.util.Base64;
import java.nio.charset.StandardCharsets;
import java.security.Signature;
import org.json.JSONObject;

/** Authorizes exactly one fresh challenge, never a reusable authentication token. */
public final class AuthActivity extends Activity {
    private final Handler handler = new Handler(Looper.getMainLooper());
    private CancellationSignal cancellation = new CancellationSignal();
    private String nonce;
    private boolean completed;
    private boolean persistent;
    private int attempt;
    private byte[] payload;
    private BiometricPrompt prompt;
    private Results.Pending pending;
    private AuthScreen screen;

    private static String field(String value) {
        if (value == null || !value.matches("[A-Za-z0-9_.@-]{1,64}"))
            throw new IllegalArgumentException("Invalid request context");
        return value;
    }

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        if (state != null) {
            // The destroyed instance has already failed or completed this
            // operation. Never resurrect its nonce after a configuration change.
            completed = true;
            finish();
            return;
        }
        setShowWhenLocked(true);
        setTurnScreenOn(true);
        getWindow().addFlags(android.view.WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON |
                             android.view.WindowManager.LayoutParams.FLAG_SECURE);
        screen = new AuthScreen(this);
        nonce = getIntent().getStringExtra("nonce");
        if (nonce == null || !nonce.matches("[0-9a-f]{64}")) {
            completed = true;
            finish();
            return;
        }
        try {
            String host = field(getIntent().getStringExtra("host"));
            String user = field(getIntent().getStringExtra("user"));
            String service = field(getIntent().getStringExtra("service"));
            // Old desktop clients keep their bounded behavior during upgrades.
            persistent = service.equals("kde-fingerprint") &&
                    "leased-v1".equals(getIntent().getStringExtra("control"));
            pending = Results.start(nonce, persistent,
                    () -> runOnUiThread(this::clientClosed), SystemClock.elapsedRealtime());
            screen.context(host, user, service);
            payload = ("pam-android-fingerprint:v2\n" + nonce + "\n" +
                    host + "\n" + user + "\n" + service + "\n").getBytes(StandardCharsets.US_ASCII);
            prompt = new BiometricPrompt.Builder(this)
                    .setTitle(service.equals("pair") ? "Pair this phone with a PC?" : "Computer sign-in")
                    .setSubtitle(user + " @ " + host)
                    .setDescription("Service: " + service + ". Confirm with a strong biometric.")
                    .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                    .setNegativeButton("Cancel / use PC password", getMainExecutor(),
                            (dialog, which) -> fail("cancelled"))
                    .build();
            if (persistent) {
                screen.waitingForPc();
                handler.post(new Runnable() {
                    @Override public void run() {
                        if (completed) return;
                        if (!Results.active(pending, SystemClock.elapsedRealtime())) {
                            clientClosed();
                            return;
                        }
                        handler.postDelayed(this, 500);
                    }
                });
            } else {
                final long deadline = SystemClock.elapsedRealtime() + 25000;
                handler.post(new Runnable() {
                    @Override public void run() {
                        if (completed) return;
                        screen.remaining((int) Math.max(0, (deadline - SystemClock.elapsedRealtime() + 999) / 1000));
                        handler.postDelayed(this, 1000);
                    }
                });
                handler.postDelayed(() -> fail("timeout"), 25000);
            }
            startBiometric();
        } catch (Exception error) { fail(error.getClass().getSimpleName() + ": " + error.getMessage()); }
    }

    private void startBiometric() {
        if (completed) return;
        if (!Results.active(pending, SystemClock.elapsedRealtime())) {
            clientClosed();
            return;
        }
        try {
            final int generation = ++attempt;
            cancellation.cancel();
            cancellation = new CancellationSignal();
            Signature signer = Signature.getInstance("SHA256withECDSA");
            signer.initSign(Keys.privateKey());
            screen.status("Touch sensor", Color.rgb(180, 255, 200));
            prompt.authenticate(new BiometricPrompt.CryptoObject(signer), cancellation,
                    getMainExecutor(), new BiometricPrompt.AuthenticationCallback() {
                        @Override public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
                            if (completed || generation != attempt) return;
                            if (!Results.active(pending, SystemClock.elapsedRealtime())) {
                                clientClosed();
                                return;
                            }
                            try {
                                Signature signature = result.getCryptoObject().getSignature();
                                signature.update(payload);
                                JSONObject response = new JSONObject();
                                response.put("nonce", nonce);
                                response.put("public_key", Base64.encodeToString(Keys.publicKey(), Base64.NO_WRAP));
                                response.put("signature", Base64.encodeToString(signature.sign(), Base64.NO_WRAP));
                                complete(response);
                            } catch (Exception error) { fail(error.getClass().getSimpleName()); }
                        }
                        @Override public void onAuthenticationError(int code, CharSequence error) {
                            if (completed || generation != attempt) return;
                            if (persistent && code == BiometricPrompt.BIOMETRIC_ERROR_TIMEOUT &&
                                    Results.active(pending, SystemClock.elapsedRealtime())) {
                                // Hardware operations may time out even though the
                                // PC request is still alive. Re-arm a NEW per-use
                                // signing operation, never a cached authorization.
                                handler.postDelayed(AuthActivity.this::startBiometric, 100);
                                return;
                            }
                            fail("biometric_" + code + ": " + error);
                        }
                        @Override public void onAuthenticationFailed() {
                            if (!completed && generation == attempt)
                                screen.status("Try again", Color.rgb(255, 210, 100));
                        }
                    });
        } catch (Exception error) { fail(error.getClass().getSimpleName() + ": " + error.getMessage()); }
    }

    private void clientClosed() {
        if (!completed) fail("request_closed");
        cancellation.cancel();
        finish();
    }

    private void fail(String error) {
        try {
            JSONObject response = new JSONObject();
            response.put("nonce", nonce);
            response.put("error", error);
            complete(response);
        } catch (Exception ignored) { finish(); }
    }

    private void complete(JSONObject response) {
        if (completed) return;
        completed = true;
        handler.removeCallbacksAndMessages(null);
        cancellation.cancel();
        boolean published = Results.complete(pending, response.toString());
        screen.result(published && !response.has("error"));
        // Publish the result immediately, but keep the small physical display
        // confirmation visible briefly. No signature can be reused afterward.
        handler.postDelayed(this::finish, 1400);
    }

    @Override protected void onDestroy() {
        if (nonce != null && !completed) fail("activity_closed");
        cancellation.cancel();
        handler.removeCallbacksAndMessages(null);
        super.onDestroy();
    }
}
