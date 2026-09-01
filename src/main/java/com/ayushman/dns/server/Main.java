package com.ayushman.dns.server;

public class Main {
    public static void main(String[] args) throws Exception {
        ServerConfig config = ServerConfig.fromSystem();

        UdpDnsServer server = new UdpDnsServer(config);
        server.start();
    }
}
