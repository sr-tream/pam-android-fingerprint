"""Exercise the Android operation registry as plain Java, without a device."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


@unittest.skipUnless(shutil.which("javac") and shutil.which("java"), "JDK required")
class AndroidResultsTests(unittest.TestCase):
    def test_leases_cancellation_ownership_and_races(self):
        source = Path(__file__).resolve().parents[1] / (
            "Android/app/src/main/java/com/randiny_games/fingerprintauthenticator/Results.java")
        harness = """
package com.randiny_games.fingerprintauthenticator;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

public final class ResultsTest {
    private static int sequence;
    private static String nonce() { return String.format("%064x", ++sequence); }
    private static void check(boolean value) {
        if (!value) throw new AssertionError("Registry invariant failed");
    }
    private static void noClaim(String nonce) {
        try { Results.claim(nonce); }
        catch (IllegalStateException expected) { return; }
        throw new AssertionError("Accepted invalid/duplicate reader");
    }
    public static void main(String[] args) throws Exception {
        AtomicInteger cancelled = new AtomicInteger();
        Results.Pending ordinary = Results.start(nonce(), false, cancelled::incrementAndGet, 0);
        check(Results.active(ordinary, 1000000)); // ordinary wait is governed by activity deadline
        Results.Pending owner = Results.claim(ordinary.nonce);
        noClaim(ordinary.nonce);
        Results.Pending impostor = new Results.Pending(ordinary.nonce, false, () -> {}, 0);
        check(!Results.complete(impostor, "forged"));
        check(Results.complete(ordinary, "signed"));
        check(!Results.complete(ordinary, "second"));
        check(Results.await(owner).equals("signed"));
        check(Results.leaseState(ordinary.nonce, 0).equals("consumed"));
        check(cancelled.get() == 0);
        noClaim(ordinary.nonce);

        Results.Pending leased = Results.start(nonce(), true, cancelled::incrementAndGet, 0);
        check(Results.touch(leased.nonce, Results.LEASE_MILLIS - 1));
        check(Results.active(leased, Results.LEASE_MILLIS + 1));
        check(!Results.active(leased, 2 * Results.LEASE_MILLIS));
        check(cancelled.get() == 1);
        check(!Results.touch(leased.nonce, 2 * Results.LEASE_MILLIS + 1));
        check(!Results.complete(leased, "late-signature"));
        check(Results.await(Results.claim(leased.nonce)).contains("client_disconnected"));

        Results.Pending expired = Results.start(nonce(), true, cancelled::incrementAndGet, 0);
        check(!Results.touch(expired.nonce, Results.LEASE_MILLIS));
        check(!Results.active(expired, 0)); // never revive even if a caller supplies an earlier clock
        check(Results.await(Results.claim(expired.nonce)).contains("client_disconnected"));
        check(cancelled.get() == 2);

        Results.Pending stopped = Results.start(nonce(), true, cancelled::incrementAndGet, 0);
        check(Results.cancel(stopped.nonce));
        check(!Results.cancel(stopped.nonce));
        check(!Results.complete(stopped, "late-signature"));
        check(Results.await(Results.claim(stopped.nonce)).contains("client_cancelled"));
        check(Results.leaseState(stopped.nonce, 0).equals("cancelled"));
        check(cancelled.get() == 3);

        Results.Pending duplicate = Results.start(nonce(), true, cancelled::incrementAndGet, 0);
        try {
            Results.start(duplicate.nonce, true, () -> { throw new AssertionError(); }, 0);
            throw new AssertionError("Duplicate operation replaced its owner");
        } catch (IllegalStateException expected) {}
        check(Results.complete(duplicate, "original"));
        check(Results.await(Results.claim(duplicate.nonce)).equals("original"));

        Results.Pending unread = Results.start(nonce(), true, cancelled::incrementAndGet, 0);
        Results.claim(unread.nonce);
        Results.abandon(unread);
        check(unread.future.get().contains("reader_closed"));
        noClaim(unread.nonce);
        check(cancelled.get() == 4);

        String delayed = nonce();
        check(!Results.cancel(delayed));
        try {
            Results.start(delayed, true, () -> { throw new AssertionError(); }, 0);
            throw new AssertionError("A delayed launch revived a cancelled request");
        } catch (IllegalStateException expected) {}

        AtomicInteger evictions = new AtomicInteger();
        Results.Pending[] bounded = new Results.Pending[5];
        for (int i = 0; i < bounded.length; ++i)
            bounded[i] = Results.start(nonce(), true, evictions::incrementAndGet, 0);
        check(evictions.get() == 1);
        noClaim(bounded[0].nonce);
        check(bounded[0].future.get().contains("superseded"));
        for (int i = 1; i < bounded.length; ++i) {
            check(Results.complete(bounded[i], "done"));
            check(Results.await(Results.claim(bounded[i].nonce)).equals("done"));
        }

        // A cancellation and a successful signature may race, but only one
        // response may ever be published and cancellation cannot be overwritten.
        for (int i = 0; i < 50; ++i) {
            AtomicInteger callbacks = new AtomicInteger();
            Results.Pending race = Results.start(nonce(), true, callbacks::incrementAndGet, 0);
            CountDownLatch gate = new CountDownLatch(1);
            AtomicBoolean signed = new AtomicBoolean();
            AtomicBoolean aborted = new AtomicBoolean();
            AtomicReference<Throwable> error = new AtomicReference<>();
            Thread signer = new Thread(() -> {
                try { gate.await(); signed.set(Results.complete(race, "signed")); }
                catch (Throwable failure) { error.set(failure); }
            });
            Thread canceller = new Thread(() -> {
                try { gate.await(); aborted.set(Results.cancel(race.nonce)); }
                catch (Throwable failure) { error.set(failure); }
            });
            signer.start(); canceller.start(); gate.countDown();
            signer.join(3000); canceller.join(3000);
            check(!signer.isAlive() && !canceller.isAlive() && error.get() == null);
            String value = Results.await(Results.claim(race.nonce));
            check(signed.get() != aborted.get());
            check(value.equals("signed") == signed.get());
            check(callbacks.get() == (aborted.get() ? 1 : 0));
        }
    }
}
"""
        with tempfile.TemporaryDirectory(prefix="android-results-test-") as directory:
            test = Path(directory, "ResultsTest.java")
            test.write_text(harness)
            subprocess.run(["javac", "-d", directory, str(source), str(test)],
                           check=True, capture_output=True, timeout=30)
            subprocess.run(["java", "-cp", directory,
                            "com.randiny_games.fingerprintauthenticator.ResultsTest"],
                           check=True, capture_output=True, timeout=15)
