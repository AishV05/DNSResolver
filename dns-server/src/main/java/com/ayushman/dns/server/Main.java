package com.ayushman.dns.server;

public class Main {
    public static void main(String[] args) throws Exception {
        ServerConfig config = ServerConfig.fromSystem();
        UdpDnsServer dnsServer = new UdpDnsServer(config);
        HealthServer healthServer = new HealthServer(
                config.healthPort(),
                dnsServer
        );

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            healthServer.close();
            dnsServer.close();
        }, "dns-shutdown"));

        healthServer.start();
        dnsServer.start();
    }
}
