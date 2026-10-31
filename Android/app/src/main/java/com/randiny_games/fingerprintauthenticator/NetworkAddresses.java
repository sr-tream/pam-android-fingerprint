package com.randiny_games.fingerprintauthenticator;

import java.net.InetAddress;

final class NetworkAddresses {
    static boolean local(InetAddress address) {
        byte[] bytes = address.getAddress();
        return address.isLoopbackAddress() || address.isSiteLocalAddress() ||
                bytes.length == 16 && (bytes[0] & 0xfe) == 0xfc;
    }
    private NetworkAddresses() {}
}
