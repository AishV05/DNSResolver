package com.ayushman.dns.server;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.time.Instant;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import com.ayushman.dns.policy.DnsPolicySnapshot;
import com.ayushman.dns.protocol.DnsHeader;
import com.ayushman.dns.protocol.DnsMessage;
import com.ayushman.dns.protocol.DnsPacketParser;
import com.ayushman.dns.protocol.DnsPacketWriter;
import com.ayushman.dns.protocol.DnsQuestion;
import com.ayushman.dns.resolver.DnsResolver;
import org.junit.jupiter.api.Test;

class DnsRequestProcessorPolicyReadinessTest {

    @Test
    void failsClosedWithoutCallingTheResolverUntilRequiredPolicyIsLoaded()
            throws Exception {
        PolicySnapshotStore policyStore = new PolicySnapshotStore(
                PolicySyncMode.REQUIRED
        );
        AtomicInteger resolverCalls = new AtomicInteger();
        PolicyTelemetry policyTelemetry = PolicyTelemetry.forMode(
                PolicySyncMode.REQUIRED
        );
        DnsResolver resolver = query -> {
            resolverCalls.incrementAndGet();
            return new DnsMessage(
                    new DnsHeader(
                            query.header().id(),
                            0x8180,
                            query.questions().size(),
                            0,
                            0,
                            0
                    ),
                    query.questions(),
                    List.of(),
                    List.of(),
                    List.of()
            );
        };
        DnsRequestProcessor processor = new DnsRequestProcessor(
                resolver,
                new ServerMetrics(),
                policyStore,
                policyTelemetry
        );
        byte[] request = DnsPacketWriter.buildQuery(query());

        DnsMessage unavailable = DnsPacketParser.parse(
                processor.process(request, DnsTransport.UDP)
        );
        assertEquals(2, unavailable.header().flags() & 0x000F);
        assertEquals(0, resolverCalls.get());
        assertEquals(
                1,
                policyTelemetry.snapshot(policyStore.snapshotStatus())
                        .udpUnavailableRequests()
        );

        policyStore.activate(new DnsPolicySnapshot(
                0,
                Instant.parse("2026-10-05T00:00:00Z"),
                List.of()
        ));
        DnsMessage available = DnsPacketParser.parse(
                processor.process(request, DnsTransport.TCP)
        );
        assertEquals(0, available.header().flags() & 0x000F);
        assertEquals(1, resolverCalls.get());
        assertEquals(
                0,
                policyTelemetry.snapshot(policyStore.snapshotStatus())
                        .tcpUnavailableRequests()
        );
    }

    private DnsMessage query() {
        return new DnsMessage(
                new DnsHeader(1234, 0x0100, 1, 0, 0, 0),
                List.of(new DnsQuestion("example.com", 1, 1)),
                List.of(),
                List.of(),
                List.of()
        );
    }
}
