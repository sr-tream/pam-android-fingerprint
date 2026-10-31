package com.randiny_games.fingerprintauthenticator;

/** Per-window scanner epoch; cancellation callbacks can never revive an attempt. */
final class AttemptState {
    private int epoch;
    private boolean foreground, scanning, ended;

    void foreground() { foreground = true; }
    int pause() { scanning = false; return ++epoch; }
    void background() { foreground = false; pause(); }
    void end() { ended = true; background(); }
    int begin() {
        if (!canStart()) throw new IllegalStateException("Window is not available");
        scanning = true;
        return ++epoch;
    }
    boolean canStart() { return foreground && !scanning && !ended; }
    boolean accepts(int value) { return foreground && scanning && !ended && epoch == value; }
    boolean rearm(int value) { return canStart() && epoch == value; }
    boolean visible() { return foreground; }
}
