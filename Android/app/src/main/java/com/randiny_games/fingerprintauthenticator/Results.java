package com.randiny_games.fingerprintauthenticator;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

final class Results {
    private static final Map<String, CompletableFuture<String>> requests = new LinkedHashMap<>();

    static synchronized CompletableFuture<String> prepare(String nonce) {
        if (!requests.containsKey(nonce)) {
            if (requests.size() >= 4) {
                String oldest = requests.keySet().iterator().next();
                requests.remove(oldest).completeExceptionally(new IllegalStateException("Evicted"));
            }
            requests.put(nonce, new CompletableFuture<>());
        }
        return requests.get(nonce);
    }

    static void complete(String nonce, String value) { prepare(nonce).complete(value); }

    static String await(String nonce) throws Exception {
        CompletableFuture<String> future = prepare(nonce);
        try { return future.get(27, TimeUnit.SECONDS); }
        finally {
            synchronized (Results.class) {
                if (requests.get(nonce) == future) requests.remove(nonce);
            }
        }
    }

    private Results() {}
}
