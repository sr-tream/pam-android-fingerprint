package com.randiny_games.fingerprintauthenticator;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ActivityNotFoundException;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Intent;
import android.graphics.Typeface;
import android.hardware.biometrics.BiometricManager;
import android.os.Build;
import android.provider.Settings;
import android.text.SpannableString;
import android.text.Spanned;
import android.text.style.ForegroundColorSpan;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.ScrollView;
import android.widget.Toast;

public final class MainActivity extends Activity {
    private AlertDialog transferDialog;

    @Override public void onResume() {
        super.onResume();
        showReadiness();
    }

    @Override public void onPause() {
        if (transferDialog != null) {
            transferDialog.dismiss();
            transferDialog = null;
        }
        super.onPause();
    }

    private void showReadiness() {
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(32, 64, 32, 32);
        TextView text = new TextView(this);
        text.setTextSize(18);
        int status = getSystemService(BiometricManager.class).canAuthenticate(
                BiometricManager.Authenticators.BIOMETRIC_STRONG);
        String description = "Android fingerprint → Linux\n\n" +
                "Uses paired, encrypted LAN connections or optional authorized ADB. " +
                "Every request needs fresh strong-biometric authorization. No PIN fallback.\n\n" +
                "Biometrics: " + (status == 0 ? "ready" : "not ready (code " + status + ")") +
                "\n\nRun pair on your computer to enroll this phone.";
        PairingInfo info = null;
        try {
            Keys.privateKey();
            info = new PairingInfo(Keys.publicKey());
        } catch (Exception error) {
            description += "\n\nKey unavailable: " + error.getClass().getSimpleName() +
                    ". Enroll a fingerprint. Changed biometric enrollment may require re-pairing.";
        }
        text.setText(description);
        layout.addView(text);
        if (info != null) {
            LinearLayout keyPanel = new LinearLayout(this);
            keyPanel.setOrientation(LinearLayout.VERTICAL);
            keyPanel.setBackgroundColor(FingerprintColors.BACKGROUND);
            keyPanel.setForceDarkAllowed(false);
            int padding = Math.round(12 * getResources().getDisplayMetrics().density);
            keyPanel.setPadding(padding, padding, padding, padding);
            TextView title = new TextView(this);
            title.setText("Key SHA256 (read across, then down):");
            title.setTextColor(FingerprintColors.TEXT);
            keyPanel.addView(title);
            String code = info.groupedFingerprint();
            TextView sample = new TextView(this);
            sample.setTypeface(Typeface.MONOSPACE, Typeface.BOLD);
            sample.setTextSize(16);
            int groupWidth = (int) Math.ceil(sample.getPaint().measureText("00000000-"));
            int available = getResources().getDisplayMetrics().widthPixels -
                    layout.getPaddingLeft() - layout.getPaddingRight() - 2 * padding;
            int groupsPerRow = Math.max(1, Math.min(8, available / groupWidth));
            for (int group = 0; group < 8; group += groupsPerRow) {
                String block = code.substring(group * 9,
                        Math.min((group + groupsPerRow) * 9, code.length()));
                SpannableString colored = new SpannableString(block);
                for (int i = 0; i < block.length(); i++) {
                    colored.setSpan(new ForegroundColorSpan(FingerprintColors.color(block.charAt(i))),
                            i, i + 1, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
                }
                TextView fingerprint = new TextView(this);
                fingerprint.setText(colored);
                fingerprint.setTypeface(Typeface.MONOSPACE, Typeface.BOLD);
                fingerprint.setTextSize(16);
                fingerprint.setTextDirection(View.TEXT_DIRECTION_LTR);
                fingerprint.setSingleLine(true);
                keyPanel.addView(fingerprint);
            }
            layout.addView(keyPanel);
        }
        final PairingInfo pairing = info;
        Button copy = new Button(this);
        copy.setText("Copy SHA256");
        copy.setEnabled(pairing != null);
        copy.setOnClickListener(v -> confirmTransfer(pairing, false));
        layout.addView(copy);
        Button share = new Button(this);
        share.setText("Share SHA256");
        share.setEnabled(pairing != null);
        share.setOnClickListener(v -> confirmTransfer(pairing, true));
        layout.addView(share);
        Button network = new Button(this);
        network.setText("Direct network settings (no ADB)");
        network.setOnClickListener(v -> startActivity(new Intent(this, NetworkSettingsActivity.class)));
        layout.addView(network);
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

    private void confirmTransfer(PairingInfo pairing, boolean share) {
        if (pairing == null) return;
        if (transferDialog != null) transferDialog.dismiss();
        transferDialog = new AlertDialog.Builder(this)
                .setTitle(share ? "Share public-key fingerprint?" : "Copy public-key fingerprint?")
                .setMessage("Only the SHA-256 fingerprint of your public key is transferred. " +
                        "Your private key, biometric data, PIN and PC password are not included.\n\n" +
                        "This code is public and is not a login credential. Use a trusted transfer " +
                        "channel: substituted pairing data can enroll an attacker's key. " +
                        "Sharing does not prove hardware backing.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton(share ? "Share SHA256" : "Copy SHA256", (dialog, which) -> {
                    if (share) shareFingerprint(pairing);
                    else copyFingerprint(pairing);
                })
                .create();
        transferDialog.setOnDismissListener(dialog -> {
            if (transferDialog == dialog) transferDialog = null;
        });
        transferDialog.show();
    }

    private void copyFingerprint(PairingInfo pairing) {
        ClipboardManager clipboard = getSystemService(ClipboardManager.class);
        if (clipboard == null) {
            Toast.makeText(this, "Clipboard unavailable.", Toast.LENGTH_LONG).show();
            return;
        }
        try {
            clipboard.setPrimaryClip(ClipData.newPlainText("PAM public-key SHA256", pairing.groupedFingerprint()));
            // Android 13+ provides its own clipboard confirmation.
            if (Build.VERSION.SDK_INT < 33) {
                Toast.makeText(this, "Key SHA256 copied.", Toast.LENGTH_SHORT).show();
            }
        } catch (SecurityException | IllegalStateException error) {
            Toast.makeText(this, "Could not copy the key fingerprint.", Toast.LENGTH_LONG).show();
        }
    }

    private void shareFingerprint(PairingInfo pairing) {
        Intent send = new Intent(Intent.ACTION_SEND)
                .setType("text/plain")
                .putExtra(Intent.EXTRA_SUBJECT, "PAM Fingerprint public-key SHA256")
                .putExtra(Intent.EXTRA_TEXT, pairing.groupedFingerprint());
        try {
            startActivity(Intent.createChooser(send, "Share public-key fingerprint"));
        } catch (ActivityNotFoundException | SecurityException error) {
            Toast.makeText(this, "No available app could share the key fingerprint.", Toast.LENGTH_LONG).show();
        }
    }
}
