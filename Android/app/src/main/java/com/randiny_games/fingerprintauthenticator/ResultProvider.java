package com.randiny_games.fingerprintauthenticator;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.net.Uri;
import android.os.Binder;
import android.os.ParcelFileDescriptor;
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
        if (path.size() != 2 || !path.get(0).equals("result") ||
                !path.get(1).matches("[0-9a-f]{64}"))
            throw new FileNotFoundException("Invalid result URI");
        final String nonce = path.get(1);
        try {
            ParcelFileDescriptor[] pipe = ParcelFileDescriptor.createPipe();
            new Thread(() -> {
                try (OutputStream output = new ParcelFileDescriptor.AutoCloseOutputStream(pipe[1])) {
                    String response;
                    try { response = Results.await(nonce); }
                    catch (Exception error) { response = "{\"error\":\"no_result\"}"; }
                    output.write(response.getBytes(StandardCharsets.UTF_8));
                } catch (Exception ignored) {}
            }, "fingerprint-result").start();
            return pipe[0];
        } catch (Exception error) { throw new FileNotFoundException(error.toString()); }
    }

    @Override public String getType(Uri uri) { return "application/json"; }
    @Override public Cursor query(Uri u, String[] p, String s, String[] a, String o) { throw new SecurityException(); }
    @Override public Uri insert(Uri u, ContentValues v) { throw new SecurityException(); }
    @Override public int delete(Uri u, String s, String[] a) { throw new SecurityException(); }
    @Override public int update(Uri u, ContentValues v, String s, String[] a) { throw new SecurityException(); }
}
