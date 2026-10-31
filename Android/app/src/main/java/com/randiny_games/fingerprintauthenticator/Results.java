package com.randiny_games.fingerprintauthenticator;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

final class Results {
    static final long LEASE_MILLIS = 8000;
    private static final Map<String, Pending> requests = new LinkedHashMap<>();
    private static final Set<String> stopped = new LinkedHashSet<>();
    private static final Set<String> consumed = new LinkedHashSet<>();

    static final class Pending {
        final String nonce;
        final boolean persistent;
        final CompletableFuture<String> future = new CompletableFuture<>();
        Runnable onCancel;
        long leaseUntil;
        boolean cancelled;
        boolean claimed;

        Pending(String nonce, boolean persistent, Runnable onCancel, long now) {
            this.nonce = nonce;
            this.persistent = persistent;
            this.onCancel = onCancel;
            leaseUntil = now + LEASE_MILLIS;
        }
    }

    static Pending start(String nonce, boolean persistent, Runnable onCancel, long now) {
        if (nonce == null || !nonce.matches("[0-9a-f]{64}"))
            throw new IllegalArgumentException("Invalid nonce");
        Runnable evicted = null;
        Pending pending;
        synchronized (Results.class) {
            if (requests.containsKey(nonce) || stopped.contains(nonce) || consumed.contains(nonce))
                throw new IllegalStateException("Request already exists");
            if (requests.size() >= 4) {
                Pending oldest = requests.remove(requests.keySet().iterator().next());
                evicted = markCancelled(oldest, "superseded");
            }
            pending = new Pending(nonce, persistent, onCancel, now);
            requests.put(nonce, pending);
        }
        if (evicted != null) evicted.run();
        return pending;
    }

    private static Runnable markCancelled(Pending pending, String reason) {
        rememberStopped(pending.nonce);
        pending.cancelled = true;
        pending.future.complete("{\"nonce\":\"" + pending.nonce +
                "\",\"error\":\"" + reason + "\"}");
        Runnable callback = pending.onCancel;
        pending.onCancel = null;
        return callback;
    }

    private static void rememberStopped(String nonce) {
        consumed.remove(nonce);
        if (stopped.size() >= 8 && !stopped.contains(nonce))
            stopped.remove(stopped.iterator().next());
        stopped.add(nonce);
    }

    private static void rememberConsumed(String nonce) {
        if (consumed.size() >= 8 && !consumed.contains(nonce))
            consumed.remove(consumed.iterator().next());
        consumed.add(nonce);
    }

    static synchronized boolean complete(Pending pending, String value) {
        if (pending == null || requests.get(pending.nonce) != pending ||
                pending.cancelled || !pending.future.complete(value)) return false;
        pending.onCancel = null;
        return true;
    }

    static synchronized Pending claim(String nonce) {
        Pending pending = requests.get(nonce);
        if (pending == null || pending.claimed)
            throw new IllegalStateException("No unread request");
        pending.claimed = true;
        return pending;
    }

    static String leaseState(String nonce, long now) {
        Runnable expired = null;
        synchronized (Results.class) {
            Pending pending = requests.get(nonce);
            if (pending == null) {
                if (stopped.contains(nonce)) return "cancelled";
                return consumed.contains(nonce) ? "consumed" : "unknown";
            }
            if (pending.cancelled) return "cancelled";
            if (pending.persistent && !pending.future.isDone() && now >= pending.leaseUntil) {
                expired = markCancelled(pending, "client_disconnected");
            } else {
                if (pending.persistent) pending.leaseUntil = now + LEASE_MILLIS;
                return pending.future.isDone() ? "complete" : "pending";
            }
        }
        if (expired != null) expired.run();
        return "cancelled";
    }

    static boolean touch(String nonce, long now) {
        String state = leaseState(nonce, now);
        return state.equals("pending") || state.equals("complete");
    }

    static boolean touch(Pending owner, long now) {
        Runnable expired;
        synchronized (Results.class) {
            if (owner == null || requests.get(owner.nonce) != owner || owner.cancelled) return false;
            if (!owner.persistent || owner.future.isDone() || now < owner.leaseUntil) {
                if (owner.persistent) owner.leaseUntil = now + LEASE_MILLIS;
                return true;
            }
            expired = markCancelled(owner, "client_disconnected");
        }
        if (expired != null) expired.run();
        return false;
    }

    static boolean active(Pending pending, long now) {
        Runnable expire;
        synchronized (Results.class) {
            if (pending == null || requests.get(pending.nonce) != pending ||
                    pending.cancelled || pending.future.isDone()) return false;
            if (!pending.persistent || now < pending.leaseUntil) return true;
            expire = markCancelled(pending, "client_disconnected");
        }
        if (expire != null) expire.run();
        return false;
    }

    static boolean cancel(String nonce) {
        Pending pending;
        Runnable callback;
        synchronized (Results.class) {
            // A shell cancellation may arrive before the Activity's onCreate.
            // Keep a bounded tombstone so that a delayed launch cannot re-arm it.
            rememberStopped(nonce);
            pending = requests.get(nonce);
            if (pending == null || pending.cancelled || pending.future.isDone()) return false;
            callback = markCancelled(pending, "client_cancelled");
        }
        if (callback != null) callback.run();
        return true;
    }

    static boolean cancel(Pending owner) {
        Runnable callback;
        synchronized (Results.class) {
            if (owner == null || requests.get(owner.nonce) != owner) return false;
            rememberStopped(owner.nonce);
            if (owner.cancelled || owner.future.isDone()) return false;
            callback = markCancelled(owner, "client_cancelled");
        }
        if (callback != null) callback.run();
        return true;
    }

    static void abandon(Pending pending) {
        Runnable notify = null;
        synchronized (Results.class) {
            if (pending != null && requests.get(pending.nonce) == pending) {
                if (!pending.future.isDone()) {
                    notify = markCancelled(pending, "reader_closed");
                } else if (!pending.cancelled && pending.claimed) {
                    rememberConsumed(pending.nonce);
                }
                requests.remove(pending.nonce);
            }
        }
        if (notify != null) notify.run();
    }

    static String await(Pending pending) throws Exception {
        try {
            return pending.persistent ? pending.future.get() :
                    pending.future.get(27, TimeUnit.SECONDS);
        } finally { abandon(pending); }
    }

    private Results() {}
}
