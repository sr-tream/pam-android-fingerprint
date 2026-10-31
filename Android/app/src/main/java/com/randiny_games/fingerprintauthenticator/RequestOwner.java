package com.randiny_games.fingerprintauthenticator;

import java.security.SecureRandom;

/** A live owner, not an intent/nonce tombstone, authorizes network UI attachment. */
final class RequestOwner {
    private static RequestOwner active;
    final String nonce, host, user, service, token;
    final boolean network, unlimited;
    final Results.Pending pending;
    private volatile Runnable cancelUi;
    private boolean attached;

    private RequestOwner(String nonce, String host, String user, String service,
                         boolean network, boolean unlimited, long now) {
        if (nonce == null || !nonce.matches("[0-9a-f]{64}"))
            throw new IllegalArgumentException("Invalid nonce");
        for (String field : new String[] {host, user, service}) {
            if (field == null || !field.matches("[A-Za-z0-9_.@-]{1,64}"))
                throw new IllegalArgumentException("Invalid context");
        }
        this.nonce = nonce;
        this.host = host;
        this.user = user;
        this.service = service;
        this.network = network;
        this.unlimited = unlimited;
        byte[] random = new byte[32];
        new SecureRandom().nextBytes(random);
        StringBuilder secret = new StringBuilder(64);
        for (byte b : random) secret.append(String.format("%02x", b & 255));
        token = secret.toString();
        pending = Results.start(nonce, network || unlimited, this::cancelUi, now);
    }

    static synchronized RequestOwner start(String nonce, String host, String user, String service,
                                           boolean network, boolean unlimited, long now) {
        if (active != null) throw new IllegalStateException("Another authentication request is active");
        RequestOwner owner = new RequestOwner(nonce, host, user, service, network, unlimited, now);
        active = owner;
        return owner;
    }

    static synchronized RequestOwner attach(String nonce, String token, Runnable cancelUi, long now) {
        RequestOwner owner = active;
        if (owner == null || !owner.network || !owner.nonce.equals(nonce) ||
                !owner.token.equals(token) || owner.attached || !Results.active(owner.pending, now))
            throw new IllegalStateException("No live network request");
        owner.attached = true;
        owner.cancelUi = cancelUi;
        return owner;
    }

    static synchronized RequestOwner lookup(String nonce, String token, long now) {
        RequestOwner owner = active;
        if (owner == null || !owner.nonce.equals(nonce) || !owner.token.equals(token) ||
                !Results.active(owner.pending, now))
            throw new IllegalStateException("No live request");
        return owner;
    }

    synchronized void attachAdb(Runnable cancelUi) {
        if (network || attached) throw new IllegalStateException("Already attached");
        this.cancelUi = cancelUi;
        attached = true;
    }

    private void cancelUi() {
        Runnable callback;
        synchronized (this) { callback = cancelUi; cancelUi = null; }
        if (callback != null) callback.run();
    }

    static synchronized void release(RequestOwner owner) {
        if (active == owner) active = null;
        synchronized (owner) { owner.cancelUi = null; }
    }

    static void close(RequestOwner owner) {
        if (owner == null) return;
        Results.cancel(owner.pending);
        Results.abandon(owner.pending);
        release(owner);
    }
}
