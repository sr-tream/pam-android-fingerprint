"""Test presentation geometry without an Android runtime or a connected phone."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


@unittest.skipUnless(shutil.which("javac") and shutil.which("java"), "JDK required")
class DisplayAreaTests(unittest.TestCase):
    def test_bounds_and_percentages(self):
        source = Path(__file__).resolve().parents[1] / (
            "Android/app/src/main/java/com/randiny_games/fingerprintauthenticator/DisplayArea.java")
        harness = """
package com.randiny_games.fingerprintauthenticator;
import java.util.Arrays;
public final class AreaTest {
    private static void reject(int l, int t, int w, int h) {
        try { new DisplayArea(l, t, w, h); }
        catch (IllegalArgumentException expected) { return; }
        throw new AssertionError("Accepted invalid area");
    }
    public static void main(String[] args) {
        int[] actual = new DisplayArea(85, 5, 15, 25).pixels(1000, 600);
        if (!Arrays.equals(actual, new int[]{850, 30, 150, 150}))
            throw new AssertionError(Arrays.toString(actual));
        if (!Arrays.equals(new DisplayArea(0, 0, 100, 100).pixels(600, 1000),
                           new int[]{0, 0, 600, 1000}))
            throw new AssertionError("Default area");
        reject(-1, 0, 100, 100);
        reject(0, -1, 100, 100);
        reject(96, 0, 5, 10);
        reject(0, 96, 10, 5);
        reject(0, 0, 4, 10);
        reject(0, 0, 10, 4);
        reject(0, 0, Integer.MAX_VALUE, 10);
        reject(Integer.MAX_VALUE, 0, 10, 10);
        DisplayArea edge = new DisplayArea(95, 95, 5, 5);
        for (int width : new int[]{1, 7, 1000}) {
            int[] small = edge.pixels(width, 11);
            if (small[0] + small[2] > width || small[1] + small[3] > 11)
                throw new AssertionError("Overflow");
        }
        try { edge.pixels(0, 100); }
        catch (IllegalArgumentException expected) { return; }
        throw new AssertionError("Accepted empty display");
    }
}
"""
        with tempfile.TemporaryDirectory(prefix="display-area-test-") as directory:
            test = Path(directory, "AreaTest.java")
            test.write_text(harness)
            subprocess.run(["javac", "-d", directory, str(source), str(test)],
                           check=True, capture_output=True, timeout=30)
            subprocess.run(["java", "-cp", directory,
                            "com.randiny_games.fingerprintauthenticator.AreaTest"],
                           check=True, capture_output=True, timeout=10)
