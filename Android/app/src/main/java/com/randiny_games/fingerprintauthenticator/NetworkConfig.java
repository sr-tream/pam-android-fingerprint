package com.randiny_games.fingerprintauthenticator;

import android.content.Context;
import android.content.SharedPreferences;

final class NetworkConfig {
    static final int DEFAULT_PORT = 48751;
    static SharedPreferences preferences(Context context) {
        return context.getSharedPreferences("network", Context.MODE_PRIVATE);
    }
    static String fingerprint(String input) {
        if (input == null || !input.matches(
                "(?:[0-9a-fA-F]{64}|[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{8}){7})"))
            throw new IllegalArgumentException("Use 64 hex digits or eight 8-digit groups joined by '-'.");
        return input.replace("-", "").toLowerCase(java.util.Locale.ROOT);
    }
    static String grouped(String compact) {
        String value = fingerprint(compact);
        StringBuilder out = new StringBuilder(71);
        for (int i = 0; i < 64; i += 8) {
            if (i != 0) out.append('-');
            out.append(value, i, i + 8);
        }
        return out.toString();
    }
    private NetworkConfig() {}
}
