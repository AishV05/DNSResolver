package com.ayushman.dns.server;

public class Main {
    public static void main(String[] args) throws Exception {
        ServerConfig config = ServerConfig.fromSystem();
        PolicySyncConfig policyConfig = PolicySyncConfig.fromSystem();
        PolicySnapshotStore policyStore = new PolicySnapshotStore(
                policyConfig.mode()
        );
        PolicyTelemetry policyTelemetry = PolicyTelemetry.fromConfig(
                policyConfig
        );
        PolicySnapshotSynchronizer policySynchronizer =
                new PolicySnapshotSynchronizer(
                        policyConfig,
                        policyStore,
                        policyTelemetry
                );
        DnsServer dnsServer = new DnsServer(
                config,
                policyStore,
                policyTelemetry
        );
        HealthServer healthServer = new HealthServer(
                config.healthPort(),
                dnsServer
        );
        MetricsServer metricsServer = new MetricsServer(
                config.metricsPort(),
                config.metricsBindAddress(),
                dnsServer
        );

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            policySynchronizer.close();
            metricsServer.close();
            healthServer.close();
            dnsServer.close();
        }, "dns-shutdown"));

        try {
            healthServer.start();
            metricsServer.start();
            policySynchronizer.start();
            dnsServer.start();
        } finally {
            policySynchronizer.close();
            metricsServer.close();
            healthServer.close();
            dnsServer.close();
        }
    }
}
