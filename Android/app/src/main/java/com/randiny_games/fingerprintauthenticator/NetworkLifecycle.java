package com.randiny_games.fingerprintauthenticator;

import java.io.Closeable;
import java.util.HashSet;
import java.util.Set;

/** Atomic admission/revocation boundary, independent of Android and socket timing. */
final class NetworkLifecycle {
    private long generation;
    private Closeable listener;
    private final Set<Closeable> peers = new HashSet<>();
    private RequestOwner owner;

    synchronized long generation() { return generation; }
    synchronized boolean current(long epoch) { return generation == epoch; }

    synchronized boolean publish(long epoch, Closeable server) {
        if (!current(epoch)) return false;
        listener = server;
        return true;
    }

    synchronized boolean admit(long epoch, Closeable peer) {
        if (!current(epoch)) return false;
        peers.add(peer);
        return true;
    }

    synchronized RequestOwner start(long epoch, Closeable peer, String nonce,
                                    String host, String user, String service, long now) {
        if (!current(epoch) || !peers.contains(peer))
            throw new IllegalStateException("Network connection was revoked");
        RequestOwner request = RequestOwner.start(nonce, host, user, service,
                true, service.equals("kde-fingerprint"), now);
        owner = request;
        return request;
    }

    void finished(RequestOwner request, Closeable peer) {
        RequestOwner.close(request);
        synchronized (this) {
            if (owner == request) owner = null;
            peers.remove(peer);
        }
        close(peer);
    }

    synchronized void listenerFinished(Closeable server) {
        if (listener == server) listener = null;
    }

    void revoke() {
        Closeable server;
        Set<Closeable> connections;
        RequestOwner request;
        synchronized (this) {
            generation++;
            server = listener;
            listener = null;
            connections = new HashSet<>(peers);
            peers.clear();
            request = owner;
            owner = null;
        }
        // No callbacks or blocking I/O while holding the admission lock.
        RequestOwner.close(request);
        close(server);
        for (Closeable peer : connections) close(peer);
    }

    private static void close(Closeable value) {
        if (value != null) try { value.close(); } catch (Exception ignored) {}
    }
}
