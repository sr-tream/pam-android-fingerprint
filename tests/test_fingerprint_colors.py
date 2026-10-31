from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


@unittest.skipUnless(shutil.which("javac") and shutil.which("java"), "JDK required")
class FingerprintColorsTests(unittest.TestCase):
    def test_contrast_distinct_shades_and_symbol_order(self):
        root = Path(__file__).resolve().parents[1]
        source = root / "Android/app/src/main/java/com/randiny_games/fingerprintauthenticator/FingerprintColors.java"
        harness = """
package com.randiny_games.fingerprintauthenticator;
public final class FingerprintColorsCheck {
    public static void main(String[] args) {
        for (char c : "0123456789abcdef-".toCharArray()) {
            int color = FingerprintColors.color(c);
            if ((color >>> 24) != 255) throw new AssertionError("Nonopaque color");
            if (Character.isLetter(c) && color != FingerprintColors.color(Character.toUpperCase(c)))
                throw new AssertionError("Case changed color");
            System.out.printf("%c:%06x%n", c, color & 0xffffff);
        }
        for (char c : "g:_ \\n".toCharArray()) {
            try {
                FingerprintColors.color(c);
                throw new AssertionError("Invalid symbol accepted");
            } catch (IllegalArgumentException expected) {}
        }
        if (FingerprintColors.BACKGROUND != 0xffffffff) throw new AssertionError("Contrast background changed");
    }
}
"""
        with tempfile.TemporaryDirectory(prefix="fingerprint-colors-test-") as temporary:
            base = Path(temporary)
            test = base / "FingerprintColorsCheck.java"
            test.write_text(harness)
            subprocess.run(["javac", "-d", str(base), str(source), str(test)],
                           check=True, capture_output=True, timeout=30)
            result = subprocess.run(
                ["java", "-cp", str(base),
                 "com.randiny_games.fingerprintauthenticator.FingerprintColorsCheck"],
                check=True, capture_output=True, text=True, timeout=15,
            )
        colors = dict(line.split(":") for line in result.stdout.splitlines())
        self.assertEqual(len(set(colors.values())), 17)

        def luminance(color):
            rgb = [int(color[i:i + 2], 16) / 255 for i in (0, 2, 4)]
            linear = [c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4 for c in rgb]
            return sum(c * weight for c, weight in zip(linear, (0.2126, 0.7152, 0.0722)))

        for symbol, color in colors.items():
            with self.subTest(symbol=symbol):
                self.assertGreaterEqual(1.05 / (luminance(color) + 0.05), 4.5)
        for group in ("0123456789", "ae", "bcdf"):
            shades = [luminance(colors[c]) for c in group]
            self.assertEqual(shades, sorted(set(shades)))
