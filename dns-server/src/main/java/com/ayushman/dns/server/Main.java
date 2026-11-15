package com.ayushman.dns.server;

public class Main {
    public static void main(String[] args) throws Exception {
        ServerConfig config = ServerConfig.fromSystem();
        PolicySyncConfig policyConfig = PolicySyncConfig.fromSystem();
        ResolverReportingConfig reportingConfig =
                ResolverReportingConfig.fromSystem();
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
        ResolverReportingTelemetry reportingTelemetry =
                new ResolverReportingTelemetry(reportingConfig.mode());
        ResolverFleetReporter fleetReporter = new ResolverFleetReporter(
                reportingConfig,
                policyStore,
                policyTelemetry,
                reportingTelemetry
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
                dnsServer,
                fleetReporter
        );

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            fleetReporter.close();
            policySynchronizer.close();
            metricsServer.close();
            healthServer.close();
            dnsServer.close();
        }, "dns-shutdown"));

        try {
            healthServer.start();
            metricsServer.start();
            policySynchronizer.start();
            fleetReporter.start();
            dnsServer.start();
        } finally {
            fleetReporter.close();
            policySynchronizer.close();
            metricsServer.close();
            healthServer.close();
            dnsServer.close();
        }
    }
}
