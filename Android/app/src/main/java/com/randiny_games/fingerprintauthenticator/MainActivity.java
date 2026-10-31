package com.randiny_games.fingerprintauthenticator;

import android.app.Activity;
import android.content.Intent;
import android.hardware.biometrics.BiometricManager;
import android.os.Bundle;
import android.provider.Settings;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.ScrollView;
import java.security.MessageDigest;

public final class MainActivity extends Activity {
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(32, 64, 32, 32);
        TextView text = new TextView(this);
        text.setTextSize(18);
        int status = getSystemService(BiometricManager.class).canAuthenticate(
                BiometricManager.Authenticators.BIOMETRIC_STRONG);
        String description = "Android fingerprint → Linux\n\n" +
                "Uses an already authorized ADB connection. " +
                "Every request needs fresh strong-biometric authorization. No PIN fallback.\n\n" +
                "Biometrics: " + (status == 0 ? "ready" : "not ready (code " + status + ")") +
                "\n\nRun pair on your computer to enroll this phone.";
        try {
            Keys.privateKey();
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(Keys.publicKey());
            StringBuilder hex = new StringBuilder();
            for (byte b : hash) hex.append(String.format("%02x", b & 255));
            description += "\n\nKey SHA256:\n" + hex;
        } catch (Exception error) {
            description += "\n\nKey unavailable: " + error.getClass().getSimpleName() +
                    ". Enroll a fingerprint. Changed biometric enrollment may require re-pairing.";
        }
        text.setText(description);
        layout.addView(text);
        Button enroll = new Button(this);
        enroll.setText("Enroll fingerprints");
        enroll.setOnClickListener(v -> startActivity(new Intent(Settings.ACTION_BIOMETRIC_ENROLL)
                .putExtra(Settings.EXTRA_BIOMETRIC_AUTHENTICATORS_ALLOWED,
                        BiometricManager.Authenticators.BIOMETRIC_STRONG)));
        layout.addView(enroll);
        Button display = new Button(this);
        display.setText("Confirmation display settings");
        display.setOnClickListener(v -> startActivity(new Intent(this, DisplaySettingsActivity.class)));
        layout.addView(display);
        ScrollView scroll = new ScrollView(this);
        scroll.addView(layout);
        setContentView(scroll);
    }
}
