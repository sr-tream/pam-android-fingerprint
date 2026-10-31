package com.randiny_games.fingerprintauthenticator;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.net.Uri;
import android.os.Binder;
import android.os.ParcelFileDescriptor;
import android.os.SystemClock;
import java.io.FileNotFoundException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

/** No network listener and no stored token: only ADB's shell UID can read results. */
public final class ResultProvider extends ContentProvider {
    @Override public boolean onCreate() { return true; }

    @Override public ParcelFileDescriptor openFile(Uri uri, String mode) throws FileNotFoundException {
        if (Binder.getCallingUid() != 2000 || !"r".equals(mode))
            throw new SecurityException("Only the authorized ADB shell may read results");
        List<String> path = uri.getPathSegments();
        if (path.size() != 2 || !path.get(1).matches("[0-9a-f]{64}"))
            throw new FileNotFoundException("Invalid result URI");
        final String nonce = path.get(1);
        final Results.Pending pending;
        final String immediate;
        switch (path.get(0)) {
            case "result":
                try { pending = Results.claim(nonce); }
                catch (IllegalStateException error) { throw new FileNotFoundException(error.getMessage()); }
                immediate = null;
                break;
            case "lease":
                pending = null;
                String state = Results.leaseState(nonce, SystemClock.elapsedRealtime());
                immediate = "{\"nonce\":\"" + nonce + "\",\"protocol\":\"leased-v1\",\"alive\":" +
                        (state.equals("pending") || state.equals("complete")) +
                        ",\"state\":\"" + state + "\"}";
                break;
            case "cancel":
                pending = null;
                immediate = "{\"nonce\":\"" + nonce + "\",\"protocol\":\"leased-v1\",\"cancelled\":" +
                        Results.cancel(nonce) + "}";
                break;
            default:
                throw new FileNotFoundException("Unknown control operation");
        }
        ParcelFileDescriptor[] pipe = null;
        try {
            pipe = ParcelFileDescriptor.createPipe();
            final ParcelFileDescriptor outputPipe = pipe[1];
            new Thread(() -> {
                try (OutputStream output = new ParcelFileDescriptor.AutoCloseOutputStream(outputPipe)) {
                    String response;
                    try { response = immediate != null ? immediate : Results.await(pending); }
                    catch (Exception error) { response = "{\"nonce\":\"" + nonce + "\",\"error\":\"no_result\"}"; }
                    output.write(response.getBytes(StandardCharsets.UTF_8));
                } catch (Exception ignored) {}
            }, "fingerprint-result").start();
            return pipe[0];
        } catch (Exception error) {
            if (pending != null) Results.abandon(pending);
            if (pipe != null) {
                for (ParcelFileDescriptor descriptor : pipe) {
                    try { descriptor.close(); } catch (Exception ignored) {}
                }
            }
            throw new FileNotFoundException(error.toString());
        }
    }

    @Override public String getType(Uri uri) { return "application/json"; }
    @Override public Cursor query(Uri u, String[] p, String s, String[] a, String o) { throw new SecurityException(); }
    @Override public Uri insert(Uri u, ContentValues v) { throw new SecurityException(); }
    @Override public int delete(Uri u, String s, String[] a) { throw new SecurityException(); }
    @Override public int update(Uri u, ContentValues v, String s, String[] a) { throw new SecurityException(); }
}
