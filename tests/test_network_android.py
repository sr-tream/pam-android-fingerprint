from pathlib import Path
import datetime
import re
import shutil
import subprocess
import tempfile
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


@unittest.skipUnless(shutil.which("javac") and shutil.which("java"), "JDK required")
class AndroidNetworkOwnershipTests(unittest.TestCase):
    def test_atomic_revocation_and_stale_connection_admission(self):
        source = Path(__file__).resolve().parents[1] / "Android/app/src/main/java/com/randiny_games/fingerprintauthenticator"
        harness = """
package com.randiny_games.fingerprintauthenticator;
import java.io.Closeable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;
public final class LifecycleCheck {
    static final class Peer implements Closeable {
        volatile boolean closed;
        public void close() { closed = true; }
    }
    static String nonce(int n) { return String.format("%064x", n); }
    static void reject(Runnable action) {
        try { action.run(); throw new AssertionError("Revoked admission succeeded"); }
        catch (IllegalStateException expected) {}
    }
    public static void main(String[] args) throws Exception {
        NetworkLifecycle state = new NetworkLifecycle();
        long epoch = state.generation();
        Peer server = new Peer(), accepted = new Peer(), late = new Peer();
        if (!state.publish(epoch, server) || !state.admit(epoch, accepted))
            throw new AssertionError("Current admission rejected");
        CountDownLatch ready = new CountDownLatch(1), revoked = new CountDownLatch(1);
        AtomicReference<Throwable> failure = new AtomicReference<>();
        Thread stale = new Thread(() -> {
            try {
                ready.countDown();
                revoked.await();
                if (state.admit(epoch, late)) throw new AssertionError("Stale socket registered");
                reject(() -> state.start(epoch, accepted, nonce(1), "pc", "alice", "sudo", 0));
                if (state.publish(epoch, late)) throw new AssertionError("Stale listener registered");
            } catch (Throwable error) { failure.set(error); }
        });
        stale.start();
        ready.await();
        state.revoke();
        revoked.countDown();
        stale.join();
        if (failure.get() != null) throw new AssertionError(failure.get());
        if (!server.closed || !accepted.closed) throw new AssertionError("Revocation missed admitted socket");
        // The opposite ordering: owner registration completes before revoke starts.
        long next = state.generation();
        Peer connection = new Peer();
        state.admit(next, connection);
        AtomicReference<RequestOwner> owner = new AtomicReference<>();
        CountDownLatch published = new CountDownLatch(1), finish = new CountDownLatch(1);
        Thread worker = new Thread(() -> {
            try {
                owner.set(state.start(next, connection, nonce(2), "pc", "alice", "sudo", 0));
                published.countDown();
                finish.await();
                state.finished(owner.get(), connection);
            } catch (Throwable error) { failure.set(error); published.countDown(); }
        });
        worker.start();
        try {
            published.await();
            if (failure.get() != null) throw new AssertionError(failure.get());
            RequestOwner original = owner.get();
            state.revoke();
            if (!connection.closed || Results.active(original.pending, 1))
                throw new AssertionError("Revocation missed published owner");
            reject(() -> RequestOwner.attach(original.nonce, original.token, () -> {}, 1));
            // Exercise delayed cleanup even after bounded replay tombstones expire.
            for (int i = 20; i < 40; i++) Results.cancel(nonce(i));
            Peer replacementPeer = new Peer(), replacementServer = new Peer();
            long latest = state.generation();
            state.publish(latest, replacementServer);
            state.admit(latest, replacementPeer);
            RequestOwner replacement = state.start(latest, replacementPeer, nonce(2), "pc", "alice", "sudo", 2);
            if (original.token.equals(replacement.token)) throw new AssertionError("Reused notification identity");
            finish.countDown();
            worker.join();
            state.listenerFinished(server);
            if (!Results.active(replacement.pending, 3) || replacementPeer.closed)
                throw new AssertionError("Stale cleanup revoked current request");
            state.revoke();
            if (!replacementServer.closed || !replacementPeer.closed || Results.active(replacement.pending, 3))
                throw new AssertionError("Replacement not revoked");
        } finally {
            finish.countDown();
            worker.join();
            state.revoke();
        }
        if (failure.get() != null) throw new AssertionError(failure.get());
    }
}
"""
        with tempfile.TemporaryDirectory(prefix="pam-network-lifecycle-") as temporary:
            base = Path(temporary)
            test = base / "LifecycleCheck.java"
            test.write_text(harness)
            subprocess.run(["javac", "-d", str(base), *(str(source / name) for name in
                            ("Results.java", "RequestOwner.java", "NetworkLifecycle.java")), str(test)],
                           check=True, capture_output=True, timeout=30)
            subprocess.run(["java", "-cp", str(base),
                            "com.randiny_games.fingerprintauthenticator.LifecycleCheck"],
                           check=True, capture_output=True, timeout=15)
        service = (source / "RequestUi.java").read_text()
        self.assertIn('identity = Uri.parse("pam-confirm:" + owner.token)', service)
        self.assertIn("manager.notify(owner.token,", service)
        self.assertNotIn("cancel(nonce,", service)

    def test_raw_tls_signing_never_changes_biometric_key_policy(self):
        source = Path(__file__).resolve().parents[1] / "Android/app/src/main/java/com/randiny_games/fingerprintauthenticator"
        bio = (source / "Keys.java").read_text()
        channel = (source / "NetworkKeys.java").read_text()
        bio_digests = re.search(r"\.setDigests\(([^)]*)\)", bio).group(1)
        tls_digests = re.search(r"\.setDigests\(([^)]*)\)", channel).group(1)
        self.assertEqual(bio_digests, "KeyProperties.DIGEST_SHA256")
        self.assertIn("KeyProperties.DIGEST_NONE", tls_digests)
        self.assertIn("KeyProperties.DIGEST_SHA256", tls_digests)
        self.assertNotEqual(re.search(r'ALIAS = "([^"]+)"', bio).group(1),
                            re.search(r'ALIAS = "([^"]+)"', channel).group(1))
        self.assertNotIn("deleteEntry", bio)
        self.assertIn("store.deleteEntry(ALIAS)", channel)

    def test_pinned_session_certificate_rechecked_for_expiry_every_connection(self):
        root = Path(__file__).resolve().parents[1]
        source = root / "Android/app/src/main/java/com/randiny_games/fingerprintauthenticator/NetworkTrust.java"
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test desktop")])
        now = datetime.datetime.now(datetime.timezone.utc)
        certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                       .public_key(key.public_key()).serial_number(1)
                       .not_valid_before(now - datetime.timedelta(days=1))
                       .not_valid_after(now + datetime.timedelta(days=1)).sign(key, hashes.SHA256()))
        harness = """
package com.randiny_games.fingerprintauthenticator;
import java.io.*;
import java.security.cert.*;
import java.util.Date;
public final class NetworkTrustCheck {
    public static void main(String[] args) throws Exception {
        X509Certificate cert;
        try (InputStream input = new FileInputStream(args[0])) {
            cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(input);
        }
        NetworkTrust.check(cert, args[1]);
        // Reusing the same already-authenticated leaf must not skip time checks.
        try {
            NetworkTrust.check(cert, args[1], new Date(cert.getNotAfter().getTime() + 1));
            throw new AssertionError("Expired session certificate accepted");
        } catch (CertificateExpiredException expected) {}
        try {
            NetworkTrust.check(cert, args[1], new Date(cert.getNotBefore().getTime() - 1));
            throw new AssertionError("Future session certificate accepted");
        } catch (CertificateNotYetValidException expected) {}
        try {
            NetworkTrust.check(cert, args[1].replaceAll(".", "0"));
            throw new AssertionError("Unpaired session certificate accepted");
        } catch (CertificateException expected) {}
    }
}
"""
        with tempfile.TemporaryDirectory(prefix="pam-network-trust-") as temporary:
            base = Path(temporary)
            test = base / "NetworkTrustCheck.java"
            test.write_text(harness)
            der = base / "client.der"
            der.write_bytes(certificate.public_bytes(serialization.Encoding.DER))
            subprocess.run(["javac", "-d", str(base), str(source), str(test)],
                           check=True, capture_output=True, timeout=30)
            subprocess.run(["java", "-cp", str(base),
                            "com.randiny_games.fingerprintauthenticator.NetworkTrustCheck",
                            str(der), certificate.fingerprint(hashes.SHA256()).hex()],
                           check=True, capture_output=True, timeout=15)

    def test_live_owner_required_and_frames_bounded(self):
        root = Path(__file__).resolve().parents[1]
        source = root / "Android/app/src/main/java/com/randiny_games/fingerprintauthenticator"
        harness = """
package com.randiny_games.fingerprintauthenticator;
import java.io.*;
import java.lang.reflect.Field;
import java.net.SocketTimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
public final class NetworkCheck {
    static String nonce(int n) { return String.format("%064x", n); }
    static void reject(Runnable action) {
        try { action.run(); throw new AssertionError("Expected rejection"); }
        catch (IllegalStateException expected) {}
    }
    public static void main(String[] args) throws Exception {
        for (String local : new String[] {"10.0.0.1", "172.16.0.1", "192.168.1.1", "127.0.0.1", "::1", "fd12::1"}) {
            if (!NetworkAddresses.local(java.net.InetAddress.getByName(local))) throw new AssertionError("LAN peer denied");
        }
        for (String remote : new String[] {"8.8.8.8", "100.64.0.1", "2001:db8::1", "fe80::1"}) {
            if (NetworkAddresses.local(java.net.InetAddress.getByName(remote))) throw new AssertionError("Public peer accepted");
        }
        RequestOwner request = RequestOwner.start(nonce(1), "workstation", "alice", "sudo", true, false, 0);
        if (!request.pending.persistent || request.unlimited)
            throw new AssertionError("Lease must not imply unlimited UI deadline");
        reject(() -> RequestOwner.start(nonce(2), "workstation", "alice", "sudo", false, false, 0));
        reject(() -> RequestOwner.attach(nonce(1), "wrong", () -> {}, 0));
        AtomicInteger cancelled = new AtomicInteger();
        if (RequestOwner.attach(nonce(1), request.token, cancelled::incrementAndGet, 1) != request)
            throw new AssertionError("Wrong owner");
        reject(() -> RequestOwner.attach(nonce(1), request.token, () -> {}, 1));
        RequestOwner.close(request);
        if (cancelled.get() != 1) throw new AssertionError("Cancellation not delivered");
        for (int i = 20; i < 40; i++) Results.cancel(nonce(i));
        reject(() -> RequestOwner.attach(nonce(1), request.token, () -> {}, 2));
        RequestOwner reused = RequestOwner.start(nonce(1), "workstation", "alice", "sudo", true, false, 2);
        RequestOwner.close(request); // A late finally from an old connection owns no new request.
        if (Results.touch(request.pending, 100)) throw new AssertionError("Old owner renewed another lease");
        if (!Results.active(reused.pending, 3)) throw new AssertionError("Old owner cancelled a new request");
        RequestOwner.close(reused);
        RequestOwner next = RequestOwner.start(nonce(3), "workstation", "alice", "kde-fingerprint", true, true, 0);
        reject(() -> RequestOwner.attach(nonce(1), request.token, () -> {}, 2));
        RequestOwner.close(next);
        RequestOwner expired = RequestOwner.start(nonce(4), "workstation", "alice", "sudo", true, false, 0);
        reject(() -> RequestOwner.attach(nonce(4), expired.token, () -> {}, 8000));
        RequestOwner.close(expired);
        NetworkFrames frames = new NetworkFrames();
        if (!"{}".equals(frames.poll(new ByteArrayInputStream("{}\\n".getBytes("UTF-8")))))
            throw new AssertionError("Frame changed");
        try {
            frames.poll(new ByteArrayInputStream(new byte[4097]));
            throw new AssertionError("Oversized frame accepted");
        } catch (IOException expected) {}
        try {
            new NetworkFrames().poll(new ByteArrayInputStream(new byte[] {(byte) 0xc0, (byte) 0xaf, 10}));
            throw new AssertionError("Malformed UTF8 accepted");
        } catch (IOException expected) {}
        NetworkFrames partial = new NetworkFrames();
        InputStream interrupted = new InputStream() {
            int count;
            @Override public int read() throws IOException {
                if (count++ == 0) return '{';
                throw new SocketTimeoutException();
            }
        };
        if (partial.poll(interrupted) != null) throw new AssertionError("Partial frame published");
        if (!"{}".equals(partial.poll(new ByteArrayInputStream("}\\n".getBytes("UTF-8")))))
            throw new AssertionError("Timeout lost partial frame");
        NetworkFrames slow = new NetworkFrames();
        slow.poll(interrupted = new InputStream() {
            int count;
            @Override public int read() throws IOException {
                if (count++ == 0) return '{';
                throw new SocketTimeoutException();
            }
        });
        Field started = NetworkFrames.class.getDeclaredField("started");
        started.setAccessible(true);
        started.setLong(slow, System.nanoTime() / 1000000 - 5000);
        try {
            slow.poll(new ByteArrayInputStream("}\\n".getBytes("UTF-8")));
            throw new AssertionError("Trickled frame accepted");
        } catch (IOException expected) {}
    }
}
"""
        with tempfile.TemporaryDirectory(prefix="pam-network-java-") as temporary:
            base = Path(temporary)
            test = base / "NetworkCheck.java"
            test.write_text(harness)
            subprocess.run(["javac", "-d", str(base), *(str(source / name) for name in
                            ("Results.java", "RequestOwner.java", "NetworkFrames.java", "NetworkAddresses.java")), str(test)],
                           check=True, capture_output=True, timeout=30)
            subprocess.run(["java", "-cp", str(base),
                            "com.randiny_games.fingerprintauthenticator.NetworkCheck"],
                           check=True, capture_output=True, timeout=15)
