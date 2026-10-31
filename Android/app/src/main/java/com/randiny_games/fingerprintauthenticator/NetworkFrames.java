package com.randiny_games.fingerprintauthenticator;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.InputStream;
import java.io.IOException;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;

/** Bounded incremental lines with an absolute deadline, including trickled bytes. */
final class NetworkFrames {
    private final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    private long started;

    String poll(InputStream input) throws IOException {
        while (true) {
            long now = System.nanoTime() / 1000000;
            if (bytes.size() != 0 && now - started >= 4000)
                throw new IOException("Frame deadline exceeded");
            final int value;
            try { value = input.read(); }
            catch (SocketTimeoutException timeout) { return null; }
            if (value < 0) throw new EOFException("Client closed");
            if (bytes.size() != 0 && System.nanoTime() / 1000000 - started >= 4000)
                throw new IOException("Frame deadline exceeded");
            if (bytes.size() == 0) started = now;
            if (value == '\n') {
                byte[] line = bytes.toByteArray();
                bytes.reset();
                return StandardCharsets.UTF_8.newDecoder()
                        .onMalformedInput(CodingErrorAction.REPORT)
                        .onUnmappableCharacter(CodingErrorAction.REPORT)
                        .decode(ByteBuffer.wrap(line)).toString();
            }
            bytes.write(value);
            if (bytes.size() > 4096) throw new IOException("Frame too large");
        }
    }
}
