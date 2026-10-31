package com.randiny_games.fingerprintauthenticator;

import android.app.Activity;
import android.graphics.Color;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;

/** A presentation-only sample: never accesses keys or starts authentication. */
public final class DisplayPreviewActivity extends Activity {
    private final Handler handler = new Handler(Looper.getMainLooper());

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        AuthScreen screen = new AuthScreen(this);
        screen.context("workstation", "alice", "sudo");
        screen.status("PREVIEW ONLY", Color.YELLOW);
        screen.remaining(10);
        handler.postDelayed(this::finish, 10000);
    }

    @Override protected void onDestroy() {
        handler.removeCallbacksAndMessages(null);
        super.onDestroy();
    }
}
