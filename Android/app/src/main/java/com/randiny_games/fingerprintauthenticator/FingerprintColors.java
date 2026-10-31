package com.randiny_games.fingerprintauthenticator;

/** Display-only colors; authentication and transferred text never use colors. */
final class FingerprintColors {
    static final int BACKGROUND = 0xffffffff;
    static final int TEXT = 0xff202124;

    static int color(char symbol) {
        if (symbol >= 'A' && symbol <= 'F') symbol += 'a' - 'A';
        if (symbol >= '0' && symbol <= '9') {
            return blend(0x103c75, 0x1768b5, symbol - '0', 9);
        }
        if (symbol == 'a' || symbol == 'e') {
            return blend(0x703900, 0xa65b00, symbol == 'a' ? 0 : 1, 1);
        }
        int consonant = "bcdf".indexOf(symbol);
        if (consonant >= 0) {
            return blend(0x59206e, 0x9041a6, consonant, 3);
        }
        if (symbol == '-') return 0xff5f6368;
        throw new IllegalArgumentException("Not a hexadecimal fingerprint symbol");
    }

    private static int blend(int dark, int light, int rank, int maximum) {
        int color = 0xff000000;
        for (int shift = 0; shift <= 16; shift += 8) {
            int low = (dark >>> shift) & 255;
            int high = (light >>> shift) & 255;
            int channel = (low * (maximum - rank) + high * rank + maximum / 2) / maximum;
            color |= channel << shift;
        }
        return color;
    }
}
