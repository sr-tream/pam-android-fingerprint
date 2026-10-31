package com.randiny_games.fingerprintauthenticator;

/** Screen-relative percentages, interpreted after the requested rotation. */
final class DisplayArea {
    final int left, top, width, height;

    DisplayArea(int left, int top, int width, int height) {
        if (left < 0 || top < 0 || width < 5 || height < 5 ||
                left > 95 || top > 95 || width > 100 - left || height > 100 - top)
            throw new IllegalArgumentException(
                    "Area must fit inside the screen; width and height must be at least 5%.");
        this.left = left;
        this.top = top;
        this.width = width;
        this.height = height;
    }

    int[] pixels(int screenWidth, int screenHeight) {
        if (screenWidth < 1 || screenHeight < 1)
            throw new IllegalArgumentException("Screen dimensions must be positive.");
        int x = (int) ((long) screenWidth * left / 100);
        int y = (int) ((long) screenHeight * top / 100);
        int right = (int) ((long) screenWidth * (left + width) / 100);
        int bottom = (int) ((long) screenHeight * (top + height) / 100);
        return new int[]{x, y, Math.max(1, right - x), Math.max(1, bottom - y)};
    }
}
