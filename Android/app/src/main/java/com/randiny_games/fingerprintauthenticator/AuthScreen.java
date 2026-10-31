package com.randiny_games.fingerprintauthenticator;

import android.app.Activity;
import android.graphics.Color;
import android.graphics.Typeface;
import android.text.TextUtils;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.TextView;

/** Request context within an optional user-selected usable screen rectangle. */
final class AuthScreen {
    private final Activity activity;
    private final boolean compact;
    private final TextView title;
    private final TextView identity;
    private final TextView status;
    private final TextView remaining;

    AuthScreen(Activity activity) {
        this.activity = activity;
        DisplaySettings settings = DisplaySettings.load(activity);
        compact = settings.custom;
        activity.setRequestedOrientation(DisplaySettings.ORIENTATIONS[settings.orientation]);
        if (compact) {
            // AuthActivity handles orientation/screenSize changes without
            // recreation, so rotating cannot cancel or duplicate a challenge.
            activity.getWindow().getDecorView().setSystemUiVisibility(
                    View.SYSTEM_UI_FLAG_LAYOUT_STABLE |
                    View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN |
                    View.SYSTEM_UI_FLAG_FULLSCREEN |
                    View.SYSTEM_UI_FLAG_LAYOUT_HIDE_NAVIGATION |
                    View.SYSTEM_UI_FLAG_HIDE_NAVIGATION |
                    View.SYSTEM_UI_FLAG_IMMERSIVE_STICKY);
            android.view.WindowManager.LayoutParams window = activity.getWindow().getAttributes();
            window.layoutInDisplayCutoutMode =
                    android.view.WindowManager.LayoutParams.LAYOUT_IN_DISPLAY_CUTOUT_MODE_SHORT_EDGES;
            activity.getWindow().setAttributes(window);
        }
        FrameLayout root = new FrameLayout(activity);
        root.setBackgroundColor(Color.BLACK);
        LinearLayout card = new LinearLayout(activity);
        card.setOrientation(LinearLayout.VERTICAL);
        int pad = dp(compact ? 5 : 24);
        card.setPadding(pad, pad, pad, pad);
        card.setBackgroundColor(Color.rgb(15, 27, 23));
        FrameLayout.LayoutParams params = new FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT,
                compact ? FrameLayout.LayoutParams.MATCH_PARENT : FrameLayout.LayoutParams.WRAP_CONTENT,
                compact ? Gravity.TOP | Gravity.LEFT : Gravity.CENTER);
        if (compact) {
            root.addOnLayoutChangeListener((view, l, t, r, b, ol, ot, or, ob) -> {
                if (r <= l || b <= t) return;
                int[] bounds = settings.area.pixels(r - l, b - t);
                FrameLayout.LayoutParams region = (FrameLayout.LayoutParams) card.getLayoutParams();
                if (region.leftMargin != bounds[0] || region.topMargin != bounds[1] ||
                        region.width != bounds[2] || region.height != bounds[3]) {
                    region.leftMargin = bounds[0];
                    region.topMargin = bounds[1];
                    region.width = bounds[2];
                    region.height = bounds[3];
                    card.setLayoutParams(region);
                }
            });
        } else {
            params.leftMargin = params.rightMargin = dp(24);
        }
        title = row(card, compact ? 11 : 22, true);
        identity = row(card, compact ? 10 : 18, false);
        status = row(card, compact ? 11 : 20, true);
        remaining = row(card, compact ? 9 : 16, false);
        title.setText("PAM");
        status.setText("Preparing…");
        root.addView(card, params);
        activity.setContentView(root);
    }

    private int dp(int value) {
        return Math.round(value * activity.getResources().getDisplayMetrics().density);
    }

    private TextView row(LinearLayout card, int size, boolean bold) {
        TextView view = new TextView(activity);
        view.setTextColor(Color.WHITE);
        // Fixed physical size in this accessibility profile; system font scale
        // must not push the request context into a damaged part of the OLED.
        view.setTextSize(TypedValue.COMPLEX_UNIT_DIP, size);
        view.setSingleLine(true);
        view.setEllipsize(TextUtils.TruncateAt.END);
        view.setIncludeFontPadding(false);
        view.setPadding(0, dp(1), 0, dp(1));
        if (bold) view.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        if (compact) {
            view.setGravity(Gravity.CENTER_VERTICAL);
            view.setAutoSizeTextTypeUniformWithConfiguration(5, size, 1, TypedValue.COMPLEX_UNIT_DIP);
            card.addView(view, new LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT, 0, 1));
        } else {
            card.addView(view);
        }
        return view;
    }

    void context(String host, String user, String service) {
        title.setText(service.equals("pair") ? "PAIR PHONE" : "PAM: " + service);
        identity.setText(user + "@" + host);
    }

    void status(String text, int color) {
        status.setText(text);
        status.setTextColor(color);
    }

    void remaining(int seconds) {
        remaining.setText(seconds + " s");
    }

    void result(boolean success) {
        status(success ? "Confirmed" : "Cancelled",
                success ? Color.rgb(130, 255, 170) : Color.rgb(255, 190, 110));
        remaining.setText(success ? "PC sign-in" : "Use PC password");
    }
}
