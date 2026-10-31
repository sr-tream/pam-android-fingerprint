package com.randiny_games.fingerprintauthenticator;

import android.app.Activity;
import android.os.Bundle;

/** Legacy ADB entry point. Never owns a biometric operation or a resumable task. */
public final class AuthActivity extends Activity {
    @Override public void onCreate(Bundle saved) {
        super.onCreate(saved);
        RequestOwner owner = null;
        try {
            if (saved != null) return;
            String service = getIntent().getStringExtra("service");
            boolean unlimited = "kde-fingerprint".equals(service) &&
                    "leased-v1".equals(getIntent().getStringExtra("control"));
            owner = RequestOwner.start(getIntent().getStringExtra("nonce"),
                    getIntent().getStringExtra("host"), getIntent().getStringExtra("user"),
                    service, false, unlimited, android.os.SystemClock.elapsedRealtime());
            RequestUi.open(this, owner, true);
        } catch (Exception rejected) {
            if (owner != null) Results.cancel(owner.pending);
        } finally { finish(); }
    }
}
