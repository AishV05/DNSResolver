package com.ayushman.dns.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import com.ayushman.dns.policy.DnsPolicyAction;
import com.ayushman.dns.policy.DnsPolicyMatchType;
import com.ayushman.dns.policy.DnsPolicyRule;
import com.ayushman.dns.policy.DnsPolicySnapshot;
import com.ayushman.dns.protocol.DnsHeader;
import com.ayushman.dns.protocol.DnsMessage;
import com.ayushman.dns.protocol.DnsPacketParser;
import com.ayushman.dns.protocol.DnsPacketWriter;
import com.ayushman.dns.protocol.DnsQuestion;
import com.ayushman.dns.protocol.EdnsInfo;
import com.ayushman.dns.resolver.DnsResolver;
import org.junit.jupiter.api.Test;

class DnsRequestProcessorPolicyEnforcementTest {

    private static final int RCODE_FORMERR = 1;
    private static final int RCODE_REFUSED = 5;

    @Test
    void returnsRefusedOverBothTransportsWithoutCallingTheResolver()
            throws Exception {
        TestContext context = requiredContext(rule(
                "example.com",
                DnsPolicyMatchType.EXACT
        ));
        DnsQuestion question = new DnsQuestion("EXAMPLE.COM.", 28, 3);
        DnsMessage request = query(
                0x17D0,
                0x0110,
                List.of(question),
                new EdnsInfo(
                        4_096,
                        0,
                        EdnsInfo.VERSION_ZERO,
                        EdnsInfo.DNSSEC_OK_FLAG,
                        new byte[] {0, 1}
                )
        );

        for (DnsTransport transport : DnsTransport.values()) {
            DnsMessage response = exchange(
                    context.processor(),
                    request,
                    transport
            );

            assertEquals(0x17D0, response.header().id());
            assertEquals(RCODE_REFUSED, rcode(response));
            assertTrue((response.header().flags() & 0x8000) != 0);
            assertTrue((response.header().flags() & 0x0100) != 0);
            assertTrue((response.header().flags() & 0x0080) != 0);
            assertTrue((response.header().flags() & 0x0010) != 0);
            assertEquals(
                    List.of(new DnsQuestion("EXAMPLE.COM", 28, 3)),
                    response.questions()
            );
            assertEquals(List.of(), response.answers());
            assertEquals(List.of(), response.authorities());
            assertEquals(List.of(), response.additionals());

            EdnsInfo edns = response.edns().orElseThrow();
            assertEquals(1_232, edns.udpPayloadSize());
            assertEquals(0, edns.extendedRcode());
            assertEquals(EdnsInfo.VERSION_ZERO, edns.version());
            assertEquals(0, edns.flags());
            assertEquals(0, edns.options().length);
        }

        assertEquals(0, context.resolverCalls().get());
        PolicyTelemetry.Snapshot policyMetrics =
                context.telemetry().snapshot(
                        context.store().snapshotStatus()
                );
        assertEquals(1, policyMetrics.udpBlockedRequests());
        assertEquals(1, policyMetrics.tcpBlockedRequests());
        assertEquals(0, policyMetrics.udpUnavailableRequests());
        assertEquals(0, policyMetrics.tcpUnavailableRequests());
    }

    @Test
    void appliesDomainRulesAcrossQueryTypesAndClassesAtLabelBoundaries()
            throws Exception {
        TestContext context = requiredContext(rule(
                "example.com",
                DnsPolicyMatchType.DOMAIN_AND_SUBDOMAINS
        ));

        assertEquals(
                RCODE_REFUSED,
                rcode(exchange(
                        context.processor(),
                        query("a.b.example.com", 255, 255),
                        DnsTransport.UDP
                ))
        );
        assertEquals(
                0,
                rcode(exchange(
                        context.processor(),
                        query("badexample.com", 1, 1),
                        DnsTransport.TCP
                ))
        );
        assertEquals(
                0,
                rcode(exchange(
                        context.processor(),
                        query("example.com.test", 15, 3),
                        DnsTransport.UDP
                ))
        );

        assertEquals(2, context.resolverCalls().get());
    }

    @Test
    void observesCompleteLiveSnapshotChangesWithoutRestarting()
            throws Exception {
        AtomicInteger resolverCalls = new AtomicInteger();
        PolicySnapshotStore store = new PolicySnapshotStore(
                PolicySyncMode.REQUIRED
        );
        DnsRequestProcessor processor = processor(store, resolverCalls);

        store.activate(snapshot(1, rule(
                "old.example",
                DnsPolicyMatchType.EXACT
        )));
        assertEquals(
                RCODE_REFUSED,
                rcode(exchange(
                        processor,
                        query("old.example", 1, 1),
                        DnsTransport.UDP
                ))
        );

        store.activate(snapshot(2, rule(
                "new.example",
                DnsPolicyMatchType.EXACT
        )));
        assertEquals(
                0,
                rcode(exchange(
                        processor,
                        query("old.example", 1, 1),
                        DnsTransport.UDP
                ))
        );
        assertEquals(
                RCODE_REFUSED,
                rcode(exchange(
                        processor,
                        query("new.example", 28, 1),
                        DnsTransport.TCP
                ))
        );

        store.activate(snapshot(3));
        assertEquals(
                0,
                rcode(exchange(
                        processor,
                        query("new.example", 28, 1),
                        DnsTransport.TCP
                ))
        );
        assertEquals(2, resolverCalls.get());
    }

    @Test
    void disabledModeIsTransparentAndBadversPrecedesPolicy()
            throws Exception {
        AtomicInteger disabledResolverCalls = new AtomicInteger();
        DnsRequestProcessor disabled = processor(
                new PolicySnapshotStore(PolicySyncMode.DISABLED),
                disabledResolverCalls
        );
        assertEquals(
                0,
                rcode(exchange(
                        disabled,
                        query("example.com", 1, 1),
                        DnsTransport.UDP
                ))
        );
        assertEquals(1, disabledResolverCalls.get());

        TestContext required = requiredContext(rule(
                "example.com",
                DnsPolicyMatchType.EXACT
        ));
        DnsMessage unsupportedEdns = query(
                0x17D1,
                0x0100,
                List.of(new DnsQuestion("example.com", 1, 1)),
                new EdnsInfo(1_232, 0, 1, 0, new byte[0])
        );
        DnsMessage response = exchange(
                required.processor(),
                unsupportedEdns,
                DnsTransport.UDP
        );

        assertEquals(0, rcode(response));
        assertEquals(
                1,
                response.edns().orElseThrow().extendedRcode()
        );
        assertEquals(0, required.resolverCalls().get());
    }

    @Test
    void rejectsAmbiguousOrNonQueryMessagesBeforePolicyAndResolution()
            throws Exception {
        TestContext context = requiredContext(rule(
                "blocked.example",
                DnsPolicyMatchType.EXACT
        ));
        List<DnsMessage> malformedQueries = List.of(
                query(10, 0x0100, List.of(), null),
                query(
                        11,
                        0x0100,
                        List.of(
                                new DnsQuestion("allowed.example", 1, 1),
                                new DnsQuestion("blocked.example", 1, 1)
                        ),
                        null
                ),
                query(
                        12,
                        0x8100,
                        List.of(new DnsQuestion("blocked.example", 1, 1)),
                        null
                )
        );

        for (DnsMessage malformed : malformedQueries) {
            DnsMessage response = exchange(
                    context.processor(),
                    malformed,
                    DnsTransport.UDP
            );
            assertEquals(RCODE_FORMERR, rcode(response));
            assertEquals(List.of(), response.questions());
        }

        DnsMessage nonQueryOpcode = query(
                13,
                0x0900,
                List.of(new DnsQuestion("blocked.example", 1, 1)),
                null
        );
        assertEquals(
                4,
                rcode(exchange(
                        context.processor(),
                        nonQueryOpcode,
                        DnsTransport.TCP
                ))
        );
        assertEquals(0, context.resolverCalls().get());
    }

    private TestContext requiredContext(DnsPolicyRule... rules) {
        AtomicInteger resolverCalls = new AtomicInteger();
        PolicySnapshotStore store = new PolicySnapshotStore(
                PolicySyncMode.REQUIRED
        );
        store.activate(snapshot(1, rules));
        PolicyTelemetry telemetry = PolicyTelemetry.forMode(
                PolicySyncMode.REQUIRED
        );
        return new TestContext(
                processor(store, resolverCalls, telemetry),
                resolverCalls,
                store,
                telemetry
        );
    }

    private DnsRequestProcessor processor(
            PolicySnapshotStore store,
            AtomicInteger resolverCalls
    ) {
        return processor(
                store,
                resolverCalls,
                PolicyTelemetry.forMode(store.mode())
        );
    }

    private DnsRequestProcessor processor(
            PolicySnapshotStore store,
            AtomicInteger resolverCalls,
            PolicyTelemetry telemetry
    ) {
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
        return new DnsRequestProcessor(
                resolver,
                new ServerMetrics(),
                store,
                telemetry
        );
    }

    private DnsMessage exchange(
            DnsRequestProcessor processor,
            DnsMessage query,
            DnsTransport transport
    ) throws Exception {
        return DnsPacketParser.parse(processor.process(
                DnsPacketWriter.buildQuery(query),
                transport
        ));
    }

    private int rcode(DnsMessage response) {
        return response.header().flags() & 0x000F;
    }

    private DnsMessage query(String domain, int type, int questionClass) {
        return query(
                0x17D2,
                0x0100,
                List.of(new DnsQuestion(domain, type, questionClass)),
                null
        );
    }

    private DnsMessage query(
            int id,
            int flags,
            List<DnsQuestion> questions,
            EdnsInfo edns
    ) {
        return new DnsMessage(
                new DnsHeader(id, flags, questions.size(), 0, 0, 0),
                questions,
                List.of(),
                List.of(),
                List.of(),
                edns
        );
    }

    private DnsPolicySnapshot snapshot(
            long revision,
            DnsPolicyRule... rules
    ) {
        return new DnsPolicySnapshot(
                revision,
                Instant.parse("2026-10-05T00:00:00Z")
                        .plusSeconds(revision),
                List.of(rules)
        );
    }

    private DnsPolicyRule rule(
            String domain,
            DnsPolicyMatchType matchType
    ) {
        return new DnsPolicyRule(
                domain,
                matchType,
                DnsPolicyAction.BLOCK
        );
    }

    private record TestContext(
            DnsRequestProcessor processor,
            AtomicInteger resolverCalls,
            PolicySnapshotStore store,
            PolicyTelemetry telemetry
    ) {
    }
}
