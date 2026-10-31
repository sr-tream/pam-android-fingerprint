package com.randiny_games.fingerprintauthenticator;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.ActivityInfo;

/** Local presentation preferences only; never changes biometric/key policy. */
final class DisplaySettings {
    private static final String FILE = "display";
    static final int[] ORIENTATIONS = {
            ActivityInfo.SCREEN_ORIENTATION_UNSPECIFIED,
            ActivityInfo.SCREEN_ORIENTATION_PORTRAIT,
            ActivityInfo.SCREEN_ORIENTATION_LANDSCAPE,
            ActivityInfo.SCREEN_ORIENTATION_REVERSE_PORTRAIT,
            ActivityInfo.SCREEN_ORIENTATION_REVERSE_LANDSCAPE
    };
    final boolean custom;
    final DisplayArea area;
    final int orientation;

    DisplaySettings(boolean custom, DisplayArea area, int orientation) {
        if (orientation < 0 || orientation >= ORIENTATIONS.length)
            throw new IllegalArgumentException("Invalid orientation.");
        this.custom = custom;
        this.area = area;
        this.orientation = orientation;
    }

    static DisplaySettings load(Context context) {
        SharedPreferences prefs = context.getSharedPreferences(FILE, Context.MODE_PRIVATE);
        try {
            return new DisplaySettings(prefs.getBoolean("custom", false),
                    new DisplayArea(prefs.getInt("left", 0), prefs.getInt("top", 0),
                            prefs.getInt("width", 100), prefs.getInt("height", 100)),
                    prefs.getInt("orientation", 0));
        } catch (IllegalArgumentException | ClassCastException error) {
            return new DisplaySettings(false, new DisplayArea(0, 0, 100, 100), 0);
        }
    }

    void save(Context context) {
        if (!context.getSharedPreferences(FILE, Context.MODE_PRIVATE).edit()
                .putBoolean("custom", custom).putInt("left", area.left)
                .putInt("top", area.top).putInt("width", area.width)
                .putInt("height", area.height).putInt("orientation", orientation).commit())
            throw new IllegalStateException("Could not save display preferences.");
    }
}
