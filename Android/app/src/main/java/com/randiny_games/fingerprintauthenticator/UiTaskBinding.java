package com.randiny_games.fingerprintauthenticator;

/** One owner may never migrate to a replacement task after its task is removed. */
final class UiTaskBinding {
    private final String token;
    private int id = -1;
    UiTaskBinding(String token) { this.token = token; }
    boolean bind(int candidate, String identity, boolean soleRoot) {
        if (candidate < 0 || !soleRoot || !token.equals(identity)) return false;
        if (id < 0) id = candidate;
        return id == candidate;
    }
    boolean matches(int candidate, String identity, boolean soleRoot) {
        return id >= 0 && id == candidate && soleRoot && token.equals(identity);
    }
    boolean bound() { return id >= 0; }
}
