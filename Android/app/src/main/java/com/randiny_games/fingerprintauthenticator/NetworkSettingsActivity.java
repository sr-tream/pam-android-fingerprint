package com.randiny_games.fingerprintauthenticator;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.NotificationManager;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Intent;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.provider.Settings;
import android.text.InputType;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.Collections;

public final class NetworkSettingsActivity extends Activity {
    private CheckBox enabled;
    private EditText clientPin, port;
    private TextView info;
    private String phonePin;
    private AlertDialog confirmation;

    private void confirm(AlertDialog.Builder builder) {
        if (confirmation != null) confirmation.dismiss();
        confirmation = builder.create();
        confirmation.setOnDismissListener(dialog -> {
            if (confirmation == dialog) confirmation = null;
        });
        confirmation.show();
    }

    @Override public void onPause() {
        if (confirmation != null) {
            confirmation.dismiss();
            confirmation = null;
        }
        super.onPause();
    }

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(32, 48, 32, 32);
        TextView title = new TextView(this);
        title.setText("Direct network authentication (no ADB)\n\n" +
                "First create a desktop TLS identity on your PC. Enter only its PUBLIC " +
                "certificate SHA256 below. Never copy the private PEM file to a phone.");
        title.setTextSize(18);
        layout.addView(title);
        enabled = new CheckBox(this);
        enabled.setText("Enable authenticated LAN listener; restart after phone unlock/boot");
        enabled.setChecked(NetworkConfig.preferences(this).getBoolean("enabled", false));
        layout.addView(enabled);
        TextView clientLabel = new TextView(this);
        clientLabel.setText("Trusted desktop TLS certificate SHA256:");
        layout.addView(clientLabel);
        clientPin = new EditText(this);
        clientPin.setSingleLine(false);
        clientPin.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        clientPin.setText(NetworkConfig.preferences(this).getString("client_pin", ""));
        layout.addView(clientPin);
        TextView portLabel = new TextView(this);
        portLabel.setText("LAN port:");
        layout.addView(portLabel);
        port = new EditText(this);
        port.setInputType(InputType.TYPE_CLASS_NUMBER);
        port.setText(String.valueOf(NetworkConfig.preferences(this).getInt("port", NetworkConfig.DEFAULT_PORT)));
        layout.addView(port);
        Button save = new Button(this);
        save.setText("Save network settings");
        save.setOnClickListener(v -> save());
        layout.addView(save);
        info = new TextView(this);
        info.setTextSize(16);
        layout.addView(info);
        Button copy = new Button(this);
        copy.setText("Copy phone TLS certificate SHA256");
        copy.setOnClickListener(v -> {
            if (phonePin == null) return;
            confirm(new AlertDialog.Builder(this).setTitle("Copy public TLS certificate fingerprint?")
                    .setMessage("This is the phone's public CHANNEL certificate fingerprint, not its " +
                            "biometric key fingerprint. Verify it through a trusted channel when " +
                            "adding the network endpoint on your PC. No private key is copied.")
                    .setNegativeButton("Cancel", null).setPositiveButton("Copy", (d, which) -> {
                        ClipboardManager clipboard = getSystemService(ClipboardManager.class);
                        try {
                            if (clipboard == null) throw new IllegalStateException();
                            clipboard.setPrimaryClip(ClipData.newPlainText(
                                    "Phone TLS certificate SHA256", NetworkConfig.grouped(phonePin)));
                        } catch (RuntimeException unavailable) {
                            Toast.makeText(this, "Could not copy the certificate fingerprint.", Toast.LENGTH_LONG).show();
                        }
                    }));
        });
        layout.addView(copy);
        Button reset = new Button(this);
        reset.setText("Reset phone TLS certificate");
        reset.setOnClickListener(v -> confirm(new AlertDialog.Builder(this)
                .setTitle("Replace ONLY the phone TLS identity?")
                .setMessage("This stops network authentication and deletes only the channel key. " +
                        "Your biometric signing key and its PC pairing are NOT changed.\n\n" +
                        "The phone TLS certificate fingerprint will change. You must explicitly " +
                        "update its pin on each PC and enable the listener again.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Reset TLS only", (dialog, which) -> {
                    if (!NetworkConfig.preferences(this).edit().putBoolean("enabled", false).commit()) {
                        Toast.makeText(this, "Could not disable the listener.", Toast.LENGTH_LONG).show();
                        return;
                    }
                    NetworkService.revokeConnections();
                    stopService(new Intent(this, NetworkService.class));
                    enabled.setChecked(false);
                    try {
                        NetworkKeys.resetCertificate();
                        refresh();
                    } catch (Exception error) {
                        Toast.makeText(this, "TLS reset failed; network remains disabled.", Toast.LENGTH_LONG).show();
                    }
                })));
        layout.addView(reset);
        if (Build.VERSION.SDK_INT < 35) {
            Button background = new Button(this);
            background.setText("Allow automatic prompts (display over other apps)");
            background.setOnClickListener(v -> startActivity(new Intent(
                    Settings.ACTION_MANAGE_OVERLAY_PERMISSION, Uri.parse("package:" + getPackageName()))));
            layout.addView(background);
        }
        Button battery = new Button(this);
        battery.setText("App notification / battery settings");
        battery.setOnClickListener(v -> startActivity(new Intent(
                Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:" + getPackageName()))));
        layout.addView(battery);
        TextView limits = new TextView(this);
        limits.setText("Keep the phone and PC on a reachable trusted network. Use a stable IP/DHCP " +
                "reservation. Allow notifications and unrestricted background/battery use.\n\n" +
                "Without automatic-prompt permission, tap the authentication notification. " +
                "Android 15+ uses notification-tap fallback when the app is not visible.\n\n" +
                "After a phone reboot, unlock it once with its PIN/password. This service does not " +
                "bypass the lock screen, biometric lockout, force-stop or Android background policy.");
        layout.addView(limits);
        ScrollView scroll = new ScrollView(this);
        scroll.addView(layout);
        setContentView(scroll);
    }

    @Override public void onResume() {
        super.onResume();
        refresh();
    }

    private void refresh() {
        try {
            phonePin = NetworkKeys.certificateFingerprint();
            StringBuilder addresses = new StringBuilder();
            for (NetworkInterface network : Collections.list(NetworkInterface.getNetworkInterfaces())) {
                if (!network.isUp() || network.isLoopback()) continue;
                for (InetAddress address : Collections.list(network.getInetAddresses())) {
                    if (address.isLoopbackAddress() || address.isLinkLocalAddress() ||
                            address.isMulticastAddress() || !NetworkAddresses.local(address)) continue;
                    String host = address.getHostAddress();
                    if (host == null || host.contains("%")) continue;
                    addresses.append(host.contains(":") ? "[" + host + "]" : host)
                            .append(':').append(port.getText()).append('\n');
                }
            }
            info.setText("\n" + NetworkService.status + "\n\nPhone TLS certificate SHA256 " +
                    "(NOT the biometric key):\n" + NetworkConfig.grouped(phonePin) +
                    "\n\nNetwork endpoints:\n" + addresses);
        } catch (Exception error) {
            phonePin = null;
            info.setText("Network identity unavailable: " + error.getClass().getSimpleName());
        }
    }

    private void save() {
        try {
            final boolean allow = enabled.isChecked();
            final String pin = allow ? NetworkConfig.fingerprint(clientPin.getText().toString()) :
                    NetworkConfig.preferences(this).getString("client_pin", "");
            final int number = allow ? Integer.parseInt(port.getText().toString()) :
                    NetworkConfig.preferences(this).getInt("port", NetworkConfig.DEFAULT_PORT);
            if (number < 1 || number > 65535) throw new IllegalArgumentException("Invalid port");
            if (allow && !getSystemService(NotificationManager.class).areNotificationsEnabled()) {
                if (Build.VERSION.SDK_INT >= 33) requestPermissions(
                        new String[] {"android.permission.POST_NOTIFICATIONS"}, 5);
                Toast.makeText(this, "Allow notifications, then save again.", Toast.LENGTH_LONG).show();
                return;
            }
            confirm(new AlertDialog.Builder(this).setTitle(allow ? "Trust this desktop for LAN requests?" : "Stop LAN requests?")
                    .setMessage(allow ? "The holder of this desktop certificate's PRIVATE key can request " +
                            "biometric prompts. Only trust your own PC. Each successful computer " +
                            "authentication still needs your fresh strong biometric.\n\n" +
                            "Desktop TLS certificate SHA256:\n" + NetworkConfig.grouped(pin) :
                            "Existing network requests will be cancelled. ADB remains a separate optional transport.")
                    .setNegativeButton("Cancel", null).setPositiveButton("Save", (dialog, which) -> {
                        boolean saved = NetworkConfig.preferences(this).edit().putBoolean("enabled", allow)
                                .putString("client_pin", pin).putInt("port", number).commit();
                        if (!saved) {
                            Toast.makeText(this, "Could not save network settings.", Toast.LENGTH_LONG).show();
                            return;
                        }
                        NetworkService.revokeConnections();
                        stopService(new Intent(this, NetworkService.class));
                        if (allow) {
                            try { startForegroundService(new Intent(this, NetworkService.class)); }
                            catch (RuntimeException error) { NetworkService.status = "Could not start network service."; }
                        }
                        refresh();
                    }));
        } catch (Exception error) {
            Toast.makeText(this, "Check the certificate SHA256 and port.", Toast.LENGTH_LONG).show();
        }
    }
}
