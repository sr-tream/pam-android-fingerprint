package com.randiny_games.fingerprintauthenticator;

import android.app.Activity;
import android.app.NotificationManager;
import android.content.Context;
import android.content.SharedPreferences;
import android.media.AudioAttributes;
import android.media.AudioFormat;
import android.media.AudioManager;
import android.media.AudioTrack;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.os.VibrationAttributes;
import android.os.VibrationEffect;
import android.os.Vibrator;
import android.os.VibratorManager;

/** Optional local signing feedback; never influences an authentication result. */
final class SuccessFeedback {
    private final Activity activity;
    private final Handler handler = new Handler(Looper.getMainLooper());
    private AudioTrack track;

    SuccessFeedback(Activity activity) { this.activity = activity; }

    static SharedPreferences preferences(Context context) {
        return context.getSharedPreferences("success-feedback", Context.MODE_PRIVATE);
    }

    void play() {
        try {
            SharedPreferences settings = preferences(activity);
            if (settings.getBoolean("haptic", true)) vibrate();
            if (settings.getBoolean("sound", false)) sound();
        } catch (RuntimeException unavailable) {
            close();
        }
    }

    private void vibrate() {
        try {
            AudioManager audio = activity.getSystemService(AudioManager.class);
            NotificationManager notifications = activity.getSystemService(NotificationManager.class);
            if (audio == null || notifications == null ||
                    audio.getRingerMode() == AudioManager.RINGER_MODE_SILENT ||
                    notifications.getCurrentInterruptionFilter() != NotificationManager.INTERRUPTION_FILTER_ALL)
                return;
            Vibrator vibrator;
            if (Build.VERSION.SDK_INT >= 31) {
                VibratorManager manager = activity.getSystemService(VibratorManager.class);
                vibrator = manager == null ? null : manager.getDefaultVibrator();
            } else {
                vibrator = activity.getSystemService(Vibrator.class);
            }
            if (vibrator == null || !vibrator.hasVibrator()) return;
            VibrationEffect effect = vibrator.hasAmplitudeControl() ?
                    VibrationEffect.createOneShot(32, 96) :
                    VibrationEffect.createPredefined(VibrationEffect.EFFECT_TICK);
            // A finite app event, not global touch feedback. Notification
            // vibration intensity and system interruption policy still apply.
            if (Build.VERSION.SDK_INT >= 33) {
                vibrator.vibrate(effect, new VibrationAttributes.Builder()
                        .setUsage(VibrationAttributes.USAGE_NOTIFICATION).build());
            } else {
                vibrator.vibrate(effect, new AudioAttributes.Builder()
                        .setUsage(AudioAttributes.USAGE_NOTIFICATION_EVENT)
                        .setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION).build());
            }
            // Never cancel by app UID: an older window must not stop a newer
            // request's pulse. The non-repeating effect ends on its own.
        } catch (RuntimeException unavailable) { /* Feedback is best-effort. */ }
    }

    private void sound() {
        close();
        try {
            AudioManager audio = activity.getSystemService(AudioManager.class);
            NotificationManager notifications = activity.getSystemService(NotificationManager.class);
            if (audio == null || notifications == null ||
                    audio.getRingerMode() != AudioManager.RINGER_MODE_NORMAL ||
                    notifications.getCurrentInterruptionFilter() != NotificationManager.INTERRUPTION_FILTER_ALL ||
                    audio.isStreamMute(AudioManager.STREAM_SYSTEM) ||
                    audio.getStreamVolume(AudioManager.STREAM_SYSTEM) == 0) return;
            // No focus request, forced-audibility flag, policy access request,
            // volume adjustment, or bypass of Silent/Vibrate/DND.
            short[] samples = FeedbackTone.samples();
            AudioTrack created = new AudioTrack.Builder()
                    .setAudioAttributes(new AudioAttributes.Builder()
                            .setUsage(AudioAttributes.USAGE_ASSISTANCE_SONIFICATION)
                            .setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION).build())
                    .setAudioFormat(new AudioFormat.Builder()
                            .setSampleRate(FeedbackTone.SAMPLE_RATE)
                            .setEncoding(AudioFormat.ENCODING_PCM_16BIT)
                            .setChannelMask(AudioFormat.CHANNEL_OUT_MONO).build())
                    .setTransferMode(AudioTrack.MODE_STATIC)
                    .setBufferSizeInBytes(samples.length * 2).build();
            track = created;
            if (created.getState() == AudioTrack.STATE_UNINITIALIZED ||
                    created.write(samples, 0, samples.length, AudioTrack.WRITE_BLOCKING) != samples.length ||
                    created.setVolume(0.25f) != AudioTrack.SUCCESS) {
                release(created);
                return;
            }
            created.setPlaybackPositionUpdateListener(new AudioTrack.OnPlaybackPositionUpdateListener() {
                @Override public void onMarkerReached(AudioTrack value) { release(created); }
                @Override public void onPeriodicNotification(AudioTrack value) {}
            }, handler);
            if (created.setNotificationMarkerPosition(samples.length) != AudioTrack.SUCCESS) {
                release(created);
                return;
            }
            // Also release if an audio route cannot deliver the marker.
            handler.postDelayed(() -> release(created), 500);
            created.play();
        } catch (RuntimeException unavailable) {
            // Includes denied policy queries and unsupported audio formats.
            close();
        }
    }

    private void release(AudioTrack expected) {
        if (track != expected) return;
        track = null;
        handler.removeCallbacksAndMessages(null);
        try { expected.setPlaybackPositionUpdateListener(null); } catch (RuntimeException ignored) {}
        try { expected.release(); } catch (RuntimeException ignored) {}
    }

    void close() {
        handler.removeCallbacksAndMessages(null);
        if (track != null) release(track);
    }
}
