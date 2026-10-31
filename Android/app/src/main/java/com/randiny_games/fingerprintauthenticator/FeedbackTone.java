package com.randiny_games.fingerprintauthenticator;

/** Short, smoothly enveloped PCM; generated locally, without media assets. */
final class FeedbackTone {
    static final int SAMPLE_RATE = 48000;
    static final int DURATION_MILLIS = 36;

    static short[] samples() {
        int count = SAMPLE_RATE * DURATION_MILLIS / 1000;
        short[] samples = new short[count];
        for (int i = 0; i < count; i++) {
            double envelope = Math.sin(Math.PI * i / (count - 1));
            envelope *= envelope;
            samples[i] = (short) Math.round(Short.MAX_VALUE * 0.16 * envelope *
                    Math.sin(2 * Math.PI * 740 * i / SAMPLE_RATE));
        }
        return samples;
    }
}
