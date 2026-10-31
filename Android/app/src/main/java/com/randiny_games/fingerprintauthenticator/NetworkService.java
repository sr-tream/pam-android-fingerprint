package com.randiny_games.fingerprintauthenticator;

import android.app.ActivityManager;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.os.Build;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.SystemClock;
import android.provider.Settings;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import org.json.JSONObject;

/** Opt-in authenticated LAN listener. TLS authentication alone never authorizes PAM. */
public final class NetworkService extends Service {
    private static volatile NetworkService instance;
    private static final int LISTENER_NOTIFICATION = 40, REQUEST_NOTIFICATION = 41;
    private static final String LISTENER_CHANNEL = "network-listener", REQUEST_CHANNEL = "network-auth";
    static volatile String status = "Network service is stopped.";
    private final Handler handler = new Handler(Looper.getMainLooper());
    private final NetworkLifecycle lifecycle = new NetworkLifecycle();
    private final ScheduledExecutorService deadlines = Executors.newSingleThreadScheduledExecutor();
    private final ThreadPoolExecutor workers = new ThreadPoolExecutor(2, 2, 0, TimeUnit.SECONDS,
            new ArrayBlockingQueue<>(2), new ThreadPoolExecutor.AbortPolicy());

    @Override public IBinder onBind(Intent intent) { return null; }

    @Override public void onCreate() {
        super.onCreate();
        instance = this;
    }

    static void revokeConnections() {
        NetworkService service = instance;
        if (service != null) service.stopConnections();
    }

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        stopConnections();
        if (!NetworkConfig.preferences(this).getBoolean("enabled", false)) {
            stopSelf();
            return START_NOT_STICKY;
        }
        NotificationManager notifications = getSystemService(NotificationManager.class);
        if (!notifications.areNotificationsEnabled()) {
            status = "Allow notifications before starting the network service.";
            stopSelf();
            return START_NOT_STICKY;
        }
        notifications.createNotificationChannel(new NotificationChannel(
                LISTENER_CHANNEL, "Network fingerprint listener", NotificationManager.IMPORTANCE_LOW));
        notifications.createNotificationChannel(new NotificationChannel(
                REQUEST_CHANNEL, "Computer authentication requests", NotificationManager.IMPORTANCE_HIGH));
        if (notifications.getNotificationChannel(REQUEST_CHANNEL).getImportance() == NotificationManager.IMPORTANCE_NONE) {
            status = "Enable the computer-authentication notification channel.";
            stopSelf();
            return START_NOT_STICKY;
        }
        Intent settings = new Intent(this, NetworkSettingsActivity.class);
        PendingIntent open = PendingIntent.getActivity(this, 0, settings,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        Notification notification = new Notification.Builder(this, LISTENER_CHANNEL)
                .setSmallIcon(android.R.drawable.ic_lock_lock)
                .setContentTitle("PAM network authentication")
                .setContentText("Only your paired desktop can request a fingerprint.")
                .setContentIntent(open).setOngoing(true).build();
        startForeground(LISTENER_NOTIFICATION, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE);
        final long current = lifecycle.generation();
        final int port = NetworkConfig.preferences(this).getInt("port", NetworkConfig.DEFAULT_PORT);
        final String pin = NetworkConfig.preferences(this).getString("client_pin", "");
        new Thread(() -> listen(current, port, pin), "pam-network-listener").start();
        return START_STICKY;
    }

    private void listen(long current, int port, String clientPin) {
        SSLServerSocket server = null;
        try {
            server = (SSLServerSocket) NetworkKeys.serverContext(clientPin).getServerSocketFactory()
                    .createServerSocket();
            server.setReuseAddress(true);
            server.setNeedClientAuth(true);
            server.setEnabledProtocols(new String[] {"TLSv1.3", "TLSv1.2"});
            server.bind(new InetSocketAddress(port), 4);
            if (!lifecycle.publish(current, server)) return;
            status = "Listening on port " + port + " (paired desktop certificate required).";
            while (lifecycle.current(current)) {
                SSLSocket peer = (SSLSocket) server.accept();
                if (!NetworkAddresses.local(peer.getInetAddress())) { close(peer); continue; }
                if (!lifecycle.admit(current, peer)) { close(peer); return; }
                try { workers.execute(() -> serve(peer, current, clientPin)); }
                catch (RuntimeException busy) { lifecycle.finished(null, peer); }
            }
        } catch (Exception error) {
            if (lifecycle.current(current)) {
                status = "Network listener unavailable: " + error.getClass().getSimpleName();
                handler.post(() -> { if (lifecycle.current(current)) stopSelf(); });
            }
        } finally {
            lifecycle.listenerFinished(server);
            if (server != null) try { server.close(); } catch (Exception ignored) {}
        }
    }

    private static boolean version(JSONObject value) throws Exception {
        return value.get("v") instanceof Integer && value.getInt("v") == 1;
    }

    private void serve(SSLSocket peer, long current, String clientPin) {
        RequestOwner owner = null;
        try {
            peer.setSoTimeout(3000);
            ScheduledFuture<?> handshake = deadlines.schedule(() -> close(peer), 3, TimeUnit.SECONDS);
            try { peer.startHandshake(); } // Pinned mTLS completes before any request dispatch.
            finally { handshake.cancel(false); }
            if (!lifecycle.current(current)) return;
            NetworkTrust.check(peer.getSession().getPeerCertificates()[0], NetworkConfig.fingerprint(clientPin));
            peer.setSoTimeout(200);
            InputStream input = peer.getInputStream();
            NetworkFrames frames = new NetworkFrames();
            long start = SystemClock.elapsedRealtime();
            String line = null;
            ScheduledFuture<?> initialFrame = deadlines.schedule(() -> close(peer), 5, TimeUnit.SECONDS);
            try {
                while (line == null && SystemClock.elapsedRealtime() - start < 5000 && lifecycle.current(current))
                    line = frames.poll(input);
            } finally { initialFrame.cancel(false); }
            if (line == null || !lifecycle.current(current) || SystemClock.elapsedRealtime() - start >= 5000) return;
            JSONObject request = new JSONObject(line);
            if (!version(request) || !"authenticate".equals(request.getString("op")) ||
                    request.length() != 6) return;
            String service = request.getString("service");
            owner = lifecycle.start(current, peer, request.getString("nonce"), request.getString("host"),
                    request.getString("user"), service,
                    SystemClock.elapsedRealtime());
            final RequestOwner launch = owner;
            handler.post(() -> { if (lifecycle.current(current)) launch(launch); });
            long heartbeat = SystemClock.elapsedRealtime();
            while (lifecycle.current(current)) {
                long now = SystemClock.elapsedRealtime();
                if (now - heartbeat >= Results.LEASE_MILLIS || !Results.active(owner.pending, now)) {
                    // A completed result also makes active() false.
                    if (!owner.pending.future.isDone()) return;
                }
                if (owner.pending.future.isDone()) {
                    JSONObject reply = new JSONObject();
                    reply.put("v", 1).put("op", "result").put("nonce", owner.nonce)
                            .put("response", new JSONObject(owner.pending.future.getNow("")));
                    byte[] bytes = (reply.toString() + "\n").getBytes(StandardCharsets.UTF_8);
                    if (bytes.length > 4096) return;
                    ScheduledFuture<?> write = deadlines.schedule(() -> close(peer), 2, TimeUnit.SECONDS);
                    try {
                        peer.getOutputStream().write(bytes);
                        peer.getOutputStream().flush();
                    } finally { write.cancel(false); }
                    return;
                }
                line = frames.poll(input);
                if (line == null) continue;
                JSONObject control = new JSONObject(line);
                if (!version(control) || control.length() != 3 ||
                        !owner.nonce.equals(control.getString("nonce"))) return;
                String op = control.getString("op");
                if (op.equals("cancel")) return;
                if (!op.equals("keepalive")) return;
                heartbeat = SystemClock.elapsedRealtime();
                if (!Results.touch(owner.pending, heartbeat)) return;
            }
        } catch (Exception rejected) {
            // Never log peer-supplied data, signatures or private identity material.
        } finally {
            lifecycle.finished(owner, peer);
        }
    }

    private void launch(RequestOwner owner) {
        if (!Results.active(owner.pending, SystemClock.elapsedRealtime())) return;
        ActivityManager.RunningAppProcessInfo process = new ActivityManager.RunningAppProcessInfo();
        ActivityManager.getMyMemoryState(process);
        // Permission is an explicit opt-in on the tested Android 11/14 devices.
        // Android 15+ requires a visible overlay: use the notification instead,
        // never create a hidden overlay to evade background-start restrictions.
        boolean automatic = process.importance == ActivityManager.RunningAppProcessInfo.IMPORTANCE_FOREGROUND ||
                Build.VERSION.SDK_INT < 35 && Settings.canDrawOverlays(this);
        RequestUi.open(this, owner, automatic);
    }

    private static void close(SSLSocket peer) { try { peer.close(); } catch (Exception ignored) {} }

    private void stopConnections() {
        lifecycle.revoke();
    }

    @Override public void onTaskRemoved(Intent rootIntent) { RequestUi.taskRemoved(rootIntent); }

    @Override public void onDestroy() {
        stopConnections();
        workers.shutdownNow();
        deadlines.shutdownNow();
        if (instance == this) instance = null;
        status = "Network service is stopped.";
        super.onDestroy();
    }
}
