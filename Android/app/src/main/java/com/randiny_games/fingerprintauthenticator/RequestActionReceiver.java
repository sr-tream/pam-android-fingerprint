package com.randiny_games.fingerprintauthenticator;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;

/** Non-exported receiver for owner-bound notification actions. */
public final class RequestActionReceiver extends BroadcastReceiver {
    @Override public void onReceive(Context context, Intent intent) {
        String token = intent.getStringExtra("request_owner");
        if (token != null && Uri.parse("pam-cancel:" + token).equals(intent.getData()))
            RequestUi.cancel(intent.getStringExtra("nonce"), token);
        else if (token != null && Uri.parse("pam-dismiss:" + token).equals(intent.getData()))
            RequestUi.dismissed(intent.getStringExtra("nonce"), token);
    }
}
