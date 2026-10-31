package com.randiny_games.fingerprintauthenticator;

import android.app.ActivityManager;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.service.notification.StatusBarNotification;
import java.lang.ref.WeakReference;
import java.util.HashMap;
import java.util.Map;

/** Main-thread, per-owner UI. Transport results are never consumed by UI cleanup. */
final class RequestUi {
    private static final Map<String, RequestUi> requests = new HashMap<>();
    private static final String CHANNEL = "network-auth";
    private static final int NOTIFICATION = 41;
    private final Handler handler = new Handler(Looper.getMainLooper());
    private final Context context;
    final RequestOwner owner;
    final long deadline;
    private final long attachDeadline;
    private final Uri identity;
    private final UiTaskBinding binding;
    private ActivityManager.AppTask task;
    private WeakReference<ConfirmationActivity> window = new WeakReference<>(null);
    private boolean terminal, cleaned, paused, inRecents, awaitingAttachment;

    private RequestUi(Context context, RequestOwner owner) {
        this.context = context.getApplicationContext();
        this.owner = owner;
        deadline = SystemClock.elapsedRealtime() + 25000;
        attachDeadline = SystemClock.elapsedRealtime() + 5000;
        identity = Uri.parse("pam-confirm:" + owner.token);
        binding = new UiTaskBinding(owner.token);
        requests.put(owner.token, this);
        // CompletableFuture callbacks may run under Results' registry lock.
        // ALWAYS enqueue, even if already on the main thread.
        owner.pending.future.whenComplete((value, error) -> handler.post(this::ended));
        handler.post(this::monitor);
    }

    static void open(Context context, RequestOwner owner, boolean launch) {
        RequestUi ui = requests.get(owner.token);
        if (ui == null) ui = new RequestUi(context, owner);
        if (!ui.live()) return;
        boolean notified = ui.notification();
        if (launch) {
            ui.awaitingAttachment = true;
            try { context.startActivity(ui.intent()); }
            catch (RuntimeException denied) {
                ui.awaitingAttachment = false;
                if (!ui.notification()) ui.cancel();
            }
        }
        else if (!notified) ui.cancel();
    }

    static RequestUi existing(RequestOwner owner) {
        RequestUi ui = requests.get(owner.token);
        if (ui == null || ui.owner != owner || !ui.live())
            throw new IllegalStateException("No live UI owner");
        return ui;
    }

    private Intent intent() {
        // Document identity is component + unique data URI. A notification tap
        // reuses only this document; a different owner can never share its task.
        return new Intent(context, ConfirmationActivity.class)
                .setData(identity)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_NEW_DOCUMENT)
                .putExtra("nonce", owner.nonce).putExtra("request_owner", owner.token);
    }

    private boolean live() {
        return !terminal && Results.active(owner.pending, SystemClock.elapsedRealtime());
    }

    boolean attach(ConfirmationActivity activity) {
        if (!live() || !identity.equals(activity.getIntent().getData())) return false;
        if (binding.bound() && !matchesTask(activity.getTaskId())) {
            cancel(); // A swiped document may not be recreated by a stale notification.
            return false;
        }
        ConfirmationActivity previous = window.get();
        if (previous != null && previous != activity && !previous.isDestroyed()) return false;
        window = new WeakReference<>(activity);
        awaitingAttachment = false;
        if (!binding.bound()) {
            try {
                for (ActivityManager.AppTask candidate : context.getSystemService(ActivityManager.class).getAppTasks()) {
                    ActivityManager.RecentTaskInfo info = candidate.getTaskInfo();
                    if (info.taskId == activity.getTaskId() && valid(info) && activity.isTaskRoot() &&
                            binding.bind(info.taskId, owner.token, info.numActivities == 1)) {
                        task = candidate;
                        candidate.setExcludeFromRecents(!owner.unlimited);
                        inRecents = owner.unlimited;
                        break;
                    }
                }
            } catch (RuntimeException unavailable) { /* Default manifest exclusion stays safe. */ }
        }
        if (owner.unlimited && !inRecents && !notification()) { cancel(); return false; }
        return true;
    }

    private boolean valid(ActivityManager.RecentTaskInfo info) {
        return confirmationTask(info, identity);
    }

    private static boolean confirmationTask(ActivityManager.RecentTaskInfo info, Uri identity) {
        return info.baseIntent != null && identity.equals(info.baseIntent.getData()) &&
                info.baseIntent.getComponent() != null &&
                ConfirmationActivity.class.getName().equals(info.baseIntent.getComponent().getClassName()) &&
                info.numActivities == 1;
    }

    static void closeStale(ConfirmationActivity activity) {
        String token = activity.getIntent().getStringExtra("request_owner");
        if (token == null || !token.matches("[0-9a-f]{64}") || requests.containsKey(token) ||
                !activity.isTaskRoot()) return;
        Uri expected = Uri.parse("pam-confirm:" + token);
        if (!expected.equals(activity.getIntent().getData())) return;
        try {
            for (ActivityManager.AppTask candidate : activity.getSystemService(ActivityManager.class).getAppTasks()) {
                ActivityManager.RecentTaskInfo info = candidate.getTaskInfo();
                if (info.taskId == activity.getTaskId() && confirmationTask(info, expected)) {
                    candidate.setExcludeFromRecents(true);
                    candidate.finishAndRemoveTask();
                    return;
                }
            }
        } catch (RuntimeException removed) { /* Never infer ownership from an ID alone. */ }
    }

    private boolean matchesTask(int expected) {
        if (task == null) return false;
        try {
            ActivityManager.RecentTaskInfo info = task.getTaskInfo();
            return info.taskId == expected && valid(info) &&
                    binding.matches(info.taskId, owner.token, info.numActivities == 1);
        } catch (RuntimeException removed) { return false; }
    }

    void detach(ConfirmationActivity activity) {
        if (window.get() != activity) return;
        window.clear();
        if (terminal) cleanup();
    }

    void paused() {
        paused = true;
        if (owner.unlimited && !inRecents && !notification()) cancel();
        else notification();
    }

    void resumed() { paused = false; notification(); }

    private boolean notification() {
        try {
            NotificationManager manager = context.getSystemService(NotificationManager.class);
            if (manager == null || !manager.areNotificationsEnabled()) return false;
            manager.createNotificationChannel(new NotificationChannel(CHANNEL,
                    "Computer authentication requests", NotificationManager.IMPORTANCE_HIGH));
            if (manager.getNotificationChannel(CHANNEL).getImportance() == NotificationManager.IMPORTANCE_NONE)
                return false;
            PendingIntent resume = PendingIntent.getActivity(context, 0, intent(),
                    PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
            Intent cancel = new Intent(context, RequestActionReceiver.class)
                    .setAction("com.randiny_games.fingerprintauthenticator.CANCEL_REQUEST")
                    .setData(Uri.parse("pam-cancel:" + owner.token))
                    .putExtra("nonce", owner.nonce).putExtra("request_owner", owner.token);
            PendingIntent end = PendingIntent.getBroadcast(context, 0, cancel,
                    PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
            Intent dismiss = new Intent(context, RequestActionReceiver.class)
                    .setAction("com.randiny_games.fingerprintauthenticator.DISMISS_REQUEST")
                    .setData(Uri.parse("pam-dismiss:" + owner.token))
                    .putExtra("nonce", owner.nonce).putExtra("request_owner", owner.token);
            PendingIntent dismissed = PendingIntent.getBroadcast(context, 0, dismiss,
                    PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
            Notification value = new Notification.Builder(context, CHANNEL)
                    .setSmallIcon(android.R.drawable.ic_lock_lock)
                    .setContentTitle(paused ? "Resume PC unlock" : "Computer sign-in")
                    .setContentText(owner.user + " @ " + owner.host)
                    .setVisibility(Notification.VISIBILITY_PRIVATE)
                    .setOnlyAlertOnce(true).setOngoing(owner.unlimited).setAutoCancel(false)
                    .setContentIntent(resume)
                    .setDeleteIntent(dismissed)
                    .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Cancel", end).build();
            manager.notify(owner.token, NOTIFICATION, value);
            return true;
        } catch (RuntimeException denied) { return false; }
    }

    private boolean notificationUsable() {
        try {
            NotificationManager manager = context.getSystemService(NotificationManager.class);
            NotificationChannel channel = manager == null ? null : manager.getNotificationChannel(CHANNEL);
            if (manager == null || !manager.areNotificationsEnabled() || channel == null ||
                    channel.getImportance() == NotificationManager.IMPORTANCE_NONE) return false;
            for (StatusBarNotification notification : manager.getActiveNotifications()) {
                if (notification.getId() == NOTIFICATION && owner.token.equals(notification.getTag()))
                    return true;
            }
            return false;
        } catch (RuntimeException denied) { return false; }
    }

    private void monitor() {
        if (terminal || cleaned) return;
        if (!Results.active(owner.pending, SystemClock.elapsedRealtime())) { ended(); return; }
        if (!owner.unlimited && SystemClock.elapsedRealtime() >= deadline) { cancel(); return; }
        if (task != null) {
            try {
                if (!matchesTask(task.getTaskInfo().taskId)) { cancel(); return; }
            } catch (RuntimeException removed) { cancel(); return; }
        }
        if (owner.unlimited && !inRecents && !notificationUsable()) {
            // A background launch can be silently refused by the platform.
            // Give initial attachment a bounded grace, never an invisible lease.
            boolean attaching = awaitingAttachment && !binding.bound() && window.get() == null &&
                    SystemClock.elapsedRealtime() < attachDeadline;
            if (!attaching) { cancel(); return; }
        }
        handler.postDelayed(this::monitor, 500);
    }

    private void ended() {
        if (terminal || cleaned) return;
        terminal = true;
        if (!owner.network) RequestOwner.release(owner); // Do not abandon an unread ADB result.
        hideNotification();
        ConfirmationActivity activity = window.get();
        if (activity != null && activity.keepFeedbackVisible()) {
            handler.postDelayed(this::cleanup, 1500);
        } else {
            if (activity != null) activity.requestEnded();
            cleanup();
        }
    }

    private void hideNotification() {
        try {
            NotificationManager manager = context.getSystemService(NotificationManager.class);
            if (manager != null) manager.cancel(owner.token, NOTIFICATION);
        } catch (RuntimeException unavailable) { /* Transport state remains authoritative. */ }
    }

    void cancel() { if (!terminal) Results.cancel(owner.pending); }

    static void cancel(String nonce, String token) {
        RequestUi ui = requests.get(token);
        if (ui != null && ui.owner.nonce.equals(nonce) && ui.live()) ui.cancel();
    }

    static void dismissed(String nonce, String token) {
        RequestUi ui = requests.get(token);
        if (ui != null && !ui.inRecents && ui.owner.nonce.equals(nonce) && ui.live()) ui.cancel();
    }

    static void taskRemoved(Intent root) {
        if (root == null || root.getData() == null) return;
        for (RequestUi ui : requests.values()) {
            if (ui.identity.equals(root.getData()) && ui.owner.unlimited && ui.live()) {
                ui.cancel();
                return;
            }
        }
    }

    void removeTask(ConfirmationActivity activity) {
        if (window.get() == activity && terminal) cleanup();
    }

    private void cleanup() {
        if (cleaned) return;
        cleaned = true;
        handler.removeCallbacksAndMessages(null);
        hideNotification();
        if (task != null) {
            try {
                ActivityManager.RecentTaskInfo info = task.getTaskInfo();
                if (valid(info) && binding.matches(info.taskId, owner.token, info.numActivities == 1)) {
                    task.setExcludeFromRecents(true);
                    task.finishAndRemoveTask();
                }
            } catch (RuntimeException removed) { /* Never remove a different task. */ }
        }
        ConfirmationActivity activity = window.get();
        if (activity != null && !activity.isFinishing()) activity.finish();
        requests.remove(owner.token);
    }
}
