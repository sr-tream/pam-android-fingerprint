import hashlib
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


@unittest.skipUnless(shutil.which("javac") and shutil.which("java"), "JDK required")
class PairingInfoTests(unittest.TestCase):
    def test_transfer_payload_is_only_a_stable_lowercase_public_key_digest(self):
        root = Path(__file__).resolve().parents[1]
        source = root / "Android/app/src/main/java/com/randiny_games/fingerprintauthenticator/PairingInfo.java"
        expected = hashlib.sha256(bytes([0x30, 0x59, 0x80, 0xFF, 0x00])).hexdigest()
        harness = """
package com.randiny_games.fingerprintauthenticator;
public final class PairingInfoCheck {
    public static void main(String[] args) throws Exception {
        byte[] publicKey = {0x30, 0x59, (byte) 0x80, (byte) 0xff, 0};
        PairingInfo info = new PairingInfo(publicKey);
        publicKey[0] = 0;
        if (!info.fingerprint().matches("[0-9a-f]{64}")) throw new AssertionError("Invalid encoding");
        if (!info.fingerprint().equals(args[0])) throw new AssertionError("Digest changed");
        if (!info.groupedFingerprint().matches("[0-9a-f]{8}(-[0-9a-f]{8}){7}"))
            throw new AssertionError("Invalid grouping");
        if (!info.groupedFingerprint().replace("-", "").equals(info.fingerprint()))
            throw new AssertionError("Grouped digest changed");
        for (byte[] invalid : new byte[][] {null, new byte[0]}) {
            try {
                new PairingInfo(invalid);
                throw new AssertionError("Missing key accepted");
            } catch (IllegalArgumentException expected) {}
        }
    }
}
"""
        with tempfile.TemporaryDirectory(prefix="pairing-info-test-") as temporary:
            base = Path(temporary)
            test = base / "PairingInfoCheck.java"
            test.write_text(harness)
            subprocess.run(["javac", "-d", str(base), str(source), str(test)],
                           check=True, capture_output=True, timeout=30)
            subprocess.run(["java", "-cp", str(base),
                            "com.randiny_games.fingerprintauthenticator.PairingInfoCheck", expected],
                           check=True, capture_output=True, timeout=15)
