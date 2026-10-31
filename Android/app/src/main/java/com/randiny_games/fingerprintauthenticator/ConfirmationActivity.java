package com.randiny_games.fingerprintauthenticator;

import android.app.Activity;
import android.graphics.Color;
import android.hardware.biometrics.BiometricManager;
import android.hardware.biometrics.BiometricPrompt;
import android.os.Bundle;
import android.os.CancellationSignal;
import android.content.Intent;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.util.Base64;
import java.nio.charset.StandardCharsets;
import java.security.Signature;
import org.json.JSONObject;

/** Authorizes exactly one fresh challenge, never a reusable authentication token. */
public final class ConfirmationActivity extends Activity {
    private final Handler handler = new Handler(Looper.getMainLooper());
    private CancellationSignal cancellation = new CancellationSignal();
    private String nonce;
    private boolean completed;
    private boolean persistent;
    private byte[] payload;
    private BiometricPrompt prompt;
    private Results.Pending pending;
    private RequestOwner owner;
    private AuthScreen screen;
    private SuccessFeedback feedback;
    private final AttemptState state = new AttemptState();
    private RequestUi ui;
    private boolean resumed;

    @Override public void onCreate(Bundle saved) {
        super.onCreate(saved);
        setShowWhenLocked(true);
        setTurnScreenOn(true);
        getWindow().addFlags(android.view.WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON |
                             android.view.WindowManager.LayoutParams.FLAG_SECURE);
        screen = new AuthScreen(this);
        feedback = new SuccessFeedback(this);
        nonce = getIntent().getStringExtra("nonce");
        if (nonce == null || !nonce.matches("[0-9a-f]{64}")) {
            completed = true;
            closeWindow();
            return;
        }
        try {
            owner = RequestOwner.lookup(nonce, getIntent().getStringExtra("request_owner"),
                    SystemClock.elapsedRealtime());
            pending = owner.pending;
            ui = RequestUi.existing(owner);
            if (!ui.attach(this)) { completed = true; closeWindow(); return; }
            String host = owner.host, user = owner.user, service = owner.service;
            persistent = owner.unlimited;
            pending = owner.pending;
            screen.context(host, user, service);
            screen.controls(persistent, this::resumeExplicitly, () -> fail("cancelled"));
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
            } else {
                final long deadline = ui.deadline;
                handler.post(new Runnable() {
                    @Override public void run() {
                        if (completed) return;
                        screen.remaining((int) Math.max(0, (deadline - SystemClock.elapsedRealtime() + 999) / 1000));
                        handler.postDelayed(this, 1000);
                    }
                });
                handler.postDelayed(() -> fail("timeout"),
                        Math.max(0, deadline - SystemClock.elapsedRealtime()));
            }
        } catch (Exception error) {
            if (ui == null) { completed = true; closeWindow(); }
            else fail(error.getClass().getSimpleName() + ": " + error.getMessage());
        }
    }

    @Override protected void onResume() {
        super.onResume();
        resumed = true;
        state.foreground();
        if (!completed && owner != null) startBiometric();
    }

    @Override protected void onPause() {
        resumed = false;
        state.background(); // Invalidate callbacks BEFORE cancelling the operation.
        cancellation.cancel();
        if (!completed && owner != null) {
            if (persistent) paused();
            else fail("backgrounded");
        }
        super.onPause();
    }

    @Override protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        if (!completed && owner != null && owner.token.equals(intent.getStringExtra("request_owner")))
            resumeExplicitly();
    }

    @Override public void onBackPressed() { if (!completed) fail("cancelled"); else closeWindow(); }

    private void resumeExplicitly() { if (!completed) startBiometric(); }

    private void paused() {
        screen.status("Paused — resume to scan", Color.rgb(255, 210, 100));
        screen.scanning(false);
        if (ui != null) ui.paused();
    }

    private void startBiometric() {
        if (completed || !state.canStart()) return;
        if (!Results.active(pending, SystemClock.elapsedRealtime())) {
            requestEnded();
            return;
        }
        try {
            final int generation = state.begin();
            cancellation.cancel();
            cancellation = new CancellationSignal();
            Signature signer = Signature.getInstance("SHA256withECDSA");
            signer.initSign(Keys.privateKey());
            screen.status("Touch sensor", Color.rgb(180, 255, 200));
            screen.scanning(true);
            ui.resumed();
            prompt.authenticate(new BiometricPrompt.CryptoObject(signer), cancellation,
                    getMainExecutor(), new BiometricPrompt.AuthenticationCallback() {
                        @Override public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
                            if (completed || !state.accepts(generation)) return;
                            if (!Results.active(pending, SystemClock.elapsedRealtime())) {
                                requestEnded();
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
                            if (completed || !state.accepts(generation)) return;
                            if (persistent && code == BiometricPrompt.BIOMETRIC_ERROR_TIMEOUT &&
                                    Results.active(pending, SystemClock.elapsedRealtime())) {
                                // Hardware operations may time out even though the
                                // PC request is still alive. Re-arm a NEW per-use
                                // signing operation, never a cached authorization.
                                int epoch = state.pause();
                                handler.postDelayed(() -> {
                                    if (!completed && state.rearm(epoch)) startBiometric();
                                }, 100);
                                return;
                            }
                            if (persistent && (code == BiometricPrompt.BIOMETRIC_ERROR_USER_CANCELED ||
                                    code == BiometricPrompt.BIOMETRIC_ERROR_CANCELED)) {
                                state.pause();
                                cancellation.cancel();
                                paused();
                                return;
                            }
                            fail("biometric_" + code + ": " + error);
                        }
                        @Override public void onAuthenticationFailed() {
                            if (!completed && state.accepts(generation))
                                screen.status("Try again", Color.rgb(255, 210, 100));
                        }
                    });
        } catch (Exception error) { fail(error.getClass().getSimpleName() + ": " + error.getMessage()); }
    }

    void requestEnded() {
        if (completed) return; // Successful visible feedback owns its short closing delay.
        completed = true;
        state.end();
        handler.removeCallbacksAndMessages(null);
        cancellation.cancel();
        closeWindow();
    }

    boolean keepFeedbackVisible() { return completed && resumed && !isFinishing(); }

    private void closeWindow() {
        if (ui != null) ui.removeTask(this);
        else RequestUi.closeStale(this);
        finish();
    }

    private void fail(String error) {
        try {
            JSONObject response = new JSONObject();
            response.put("nonce", nonce);
            response.put("error", error);
            complete(response);
        } catch (Exception ignored) { closeWindow(); }
    }

    private void complete(JSONObject response) {
        if (completed) return;
        completed = true;
        state.end();
        handler.removeCallbacksAndMessages(null);
        cancellation.cancel();
        boolean published = Results.complete(pending, response.toString());
        screen.result(published && !response.has("error"));
        if (published && !response.has("error")) feedback.play();
        // Publish the result immediately, but keep the small physical display
        // confirmation visible briefly. No signature can be reused afterward.
        handler.postDelayed(this::closeWindow, 1400);
    }

    @Override protected void onDestroy() {
        state.end();
        if (ui != null) {
            if (!completed && (isFinishing() || !persistent)) fail("activity_closed");
            ui.detach(this);
        }
        cancellation.cancel();
        if (feedback != null) feedback.close();
        handler.removeCallbacksAndMessages(null);
        super.onDestroy();
    }
}
