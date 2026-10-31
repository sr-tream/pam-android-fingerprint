package com.randiny_games.fingerprintauthenticator;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

/** Normal BOOT_COMPLETED runs after first unlock; no direct-boot credential bypass. */
public final class NetworkBootReceiver extends BroadcastReceiver {
    @Override public void onReceive(Context context, Intent intent) {
        if (!Intent.ACTION_BOOT_COMPLETED.equals(intent.getAction()) ||
                !NetworkConfig.preferences(context).getBoolean("enabled", false)) return;
        try { context.startForegroundService(new Intent(context, NetworkService.class)); }
        catch (RuntimeException denied) { NetworkService.status = "Open the app to restart network authentication."; }
    }
}
