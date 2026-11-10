package com.ayushman.dns.resolver;

import static com.ayushman.dns.testing.ScriptedDnsHierarchy.TYPE_A;
import static com.ayushman.dns.testing.ScriptedDnsHierarchy.TYPE_CNAME;
import static com.ayushman.dns.testing.ScriptedDnsHierarchy.a;
import static com.ayushman.dns.testing.ScriptedDnsHierarchy.aaaa;
import static com.ayushman.dns.testing.ScriptedDnsHierarchy.cname;
import static com.ayushman.dns.testing.ScriptedDnsHierarchy.failure;
import static com.ayushman.dns.testing.ScriptedDnsHierarchy.ipv4Address;
import static com.ayushman.dns.testing.ScriptedDnsHierarchy.ns;
import static com.ayushman.dns.testing.ScriptedDnsHierarchy.reply;
import static com.ayushman.dns.testing.ScriptedDnsHierarchy.response;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;

import com.ayushman.dns.cache.ResolverCacheConfig;

import org.junit.jupiter.api.Test;

import com.ayushman.dns.protocol.DnsHeader;
import com.ayushman.dns.protocol.DnsMessage;
import com.ayushman.dns.protocol.DnsQuestion;
import com.ayushman.dns.protocol.DnsRecord;
import com.ayushman.dns.testing.ScriptedDnsHierarchy;
import com.ayushman.dns.testing.ScriptedDnsHierarchy.Exchange;

class RecursiveResolverSafetyTest {

    private static final String ROOT_SERVER = "192.0.2.1";

    private static final String QUERY_NAME = "www.example.test";

    private static final String ANSWER_ADDRESS = "192.0.2.80";

    private static final int SCRIPT_BOUND = 64;

    @Test
    void shouldIgnoreUnrelatedAndOutOfBailiwickGlue()
            throws Exception {

        String authoritativeServer = "203.0.113.53";

        ScriptedDnsHierarchy hierarchy =
                new ScriptedDnsHierarchy(
                        response(
                                ROOT_SERVER,
                                QUERY_NAME,
                                reply(
                                        false,
                                        List.of(),
                                        List.of(
                                                ns(
                                                        "example.test",
                                                        "ns1.example.test"
                                                ),
                                                ns(
                                                        "example.test",
                                                        "ns.external.invalid"
                                                )
                                        ),
                                        List.of(
                                                a(
                                                        "unrelated.example.test",
                                                        "203.0.113.200"
                                                ),
                                                a(
                                                        "ns.external.invalid",
                                                        "203.0.113.201"
                                                ),
                                                a(
                                                        "ns1.example.test",
                                                        authoritativeServer
                                                )
                                        )
                                )
                        ),
                        response(
                                authoritativeServer,
                                QUERY_NAME,
                                authoritativeAnswer()
                        )
                );

        DnsMessage result = resolver(hierarchy).resolve(clientQuery());

        hierarchy.assertComplete();
        assertSingleAddress(result, QUERY_NAME, ANSWER_ADDRESS);
        assertEquals(
                List.of(ROOT_SERVER, authoritativeServer),
                hierarchy.hops().stream()
                        .map(ScriptedDnsHierarchy.Hop::serverAddress)
                        .toList()
        );
    }

    @Test
    void shouldFailOverToAnotherEligibleNameServer()
            throws Exception {

        String firstServer = "203.0.113.10";
        String secondServer = "203.0.113.11";

        ScriptedDnsHierarchy hierarchy =
                new ScriptedDnsHierarchy(
                        response(
                                ROOT_SERVER,
                                QUERY_NAME,
                                reply(
                                        false,
                                        List.of(),
                                        List.of(
                                                ns(
                                                        "example.test",
                                                        "ns1.example.test"
                                                ),
                                                ns(
                                                        "example.test",
                                                        "ns2.example.test"
                                                )
                                        ),
                                        List.of(
                                                a(
                                                        "ns1.example.test",
                                                        firstServer
                                                ),
                                                a(
                                                        "ns2.example.test",
                                                        secondServer
                                                )
                                        )
                                )
                        ),
                        failure(
                                firstServer,
                                QUERY_NAME,
                                new UpstreamDnsException(
                                        "scripted nameserver timeout"
                                )
                        ),
                        response(
                                secondServer,
                                QUERY_NAME,
                                authoritativeAnswer()
                        )
                );

        RecordingObserver observer = new RecordingObserver();
        DnsMessage result = resolver(hierarchy, observer)
                .resolve(clientQuery());

        hierarchy.assertComplete();
        assertSingleAddress(result, QUERY_NAME, ANSWER_ADDRESS);
        assertEquals(
                List.of(ROOT_SERVER, firstServer, secondServer),
                hierarchy.hops().stream()
                        .map(ScriptedDnsHierarchy.Hop::serverAddress)
                        .toList()
        );
        assertEquals(1, observer.nameserverFailovers);
    }

    @Test
    void shouldFailOverAfterASemanticallyIrrelevantNameserverResponse()
            throws Exception {
        String firstServer = "203.0.113.20";
        String secondServer = "203.0.113.21";

        ScriptedDnsHierarchy hierarchy =
                new ScriptedDnsHierarchy(
                        response(
                                ROOT_SERVER,
                                QUERY_NAME,
                                reply(
                                        false,
                                        List.of(),
                                        List.of(
                                                ns("example.test", "ns1.example.test"),
                                                ns("example.test", "ns2.example.test")
                                        ),
                                        List.of(
                                                a("ns1.example.test", firstServer),
                                                a("ns2.example.test", secondServer)
                                        )
                                )
                        ),
                        response(
                                firstServer,
                                QUERY_NAME,
                                reply(
                                        true,
                                        List.of(a("attacker.invalid", "203.0.113.200")),
                                        List.of(),
                                        List.of()
                                )
                        ),
                        response(
                                secondServer,
                                QUERY_NAME,
                                authoritativeAnswer()
                        )
                );

        DnsMessage result = resolver(hierarchy).resolve(clientQuery());

        hierarchy.assertComplete();
        assertSingleAddress(result, QUERY_NAME, ANSWER_ADDRESS);
        assertEquals(
                List.of(ROOT_SERVER, firstServer, secondServer),
                hierarchy.hops().stream()
                        .map(ScriptedDnsHierarchy.Hop::serverAddress)
                        .toList()
        );
    }

    @Test
    void shouldUseLinkedInBailiwickIpv6Glue()
            throws Exception {
        String authoritativeServer = "2001:db8:0:0:0:0:0:53";

        ScriptedDnsHierarchy hierarchy =
                new ScriptedDnsHierarchy(
                        response(
                                ROOT_SERVER,
                                QUERY_NAME,
                                reply(
                                        false,
                                        List.of(),
                                        List.of(ns("example.test", "ns1.example.test")),
                                        List.of(aaaa(
                                                "ns1.example.test",
                                                "2001:db8::53"
                                        ))
                                )
                        ),
                        response(
                                authoritativeServer,
                                QUERY_NAME,
                                authoritativeAnswer()
                        )
                );

        DnsMessage result = resolver(hierarchy).resolve(clientQuery());

        hierarchy.assertComplete();
        assertSingleAddress(result, QUERY_NAME, ANSWER_ADDRESS);
    }

    @Test
    void shouldRejectAnUnrelatedReferralAndTryAnotherRoot()
            throws Exception {
        String secondRoot = "192.0.2.2";

        ScriptedDnsHierarchy hierarchy =
                new ScriptedDnsHierarchy(
                        response(
                                ROOT_SERVER,
                                QUERY_NAME,
                                reply(
                                        false,
                                        List.of(),
                                        List.of(ns("attacker.invalid", "ns.attacker.invalid")),
                                        List.of(a("ns.attacker.invalid", "203.0.113.200"))
                                )
                        ),
                        response(
                                secondRoot,
                                QUERY_NAME,
                                authoritativeAnswer()
                        )
                );

        RecursiveResolver resolver = new RecursiveResolver(
                hierarchy,
                List.of(ROOT_SERVER, secondRoot)
        );
        DnsMessage result = resolver.resolve(clientQuery());

        hierarchy.assertComplete();
        assertSingleAddress(result, QUERY_NAME, ANSWER_ADDRESS);
    }

    @Test
    void escapedDotInsideALabelMustNotCreateAFalseBailiwickMatch()
            throws Exception {
        String escapedDotName = "www.evil\\.example.com";
        String secondRoot = "192.0.2.2";

        ScriptedDnsHierarchy hierarchy =
                new ScriptedDnsHierarchy(
                        response(
                                ROOT_SERVER,
                                escapedDotName,
                                reply(
                                        false,
                                        List.of(),
                                        List.of(ns("example.com", "ns.example.com")),
                                        List.of(a("ns.example.com", "203.0.113.200"))
                                )
                        ),
                        response(
                                secondRoot,
                                escapedDotName,
                                reply(
                                        true,
                                        List.of(a(escapedDotName, ANSWER_ADDRESS)),
                                        List.of(),
                                        List.of()
                                )
                        )
                );

        RecursiveResolver resolver = new RecursiveResolver(
                hierarchy,
                List.of(ROOT_SERVER, secondRoot)
        );
        DnsMessage result = resolver.resolve(clientQuery(escapedDotName));

        hierarchy.assertComplete();
        assertSingleAddress(result, escapedDotName, ANSWER_ADDRESS);
    }

    @Test
    void shouldResolveGluelessNameServerBeforeContinuing()
            throws Exception {

        String nameServer = "ns1.names.test";
        String authoritativeServer = "203.0.113.53";

        ScriptedDnsHierarchy hierarchy =
                new ScriptedDnsHierarchy(
                        response(
                                ROOT_SERVER,
                                QUERY_NAME,
                                reply(
                                        false,
                                        List.of(),
                                        List.of(ns("example.test", nameServer)),
                                        List.of()
                                )
                        ),
                        response(
                                ROOT_SERVER,
                                nameServer,
                                reply(
                                        true,
                                        List.of(a(nameServer, authoritativeServer)),
                                        List.of(),
                                        List.of()
                                )
                        ),
                        response(
                                authoritativeServer,
                                QUERY_NAME,
                                authoritativeAnswer()
                        )
                );

        DnsMessage result = resolver(hierarchy).resolve(clientQuery());

        hierarchy.assertComplete();
        assertSingleAddress(result, QUERY_NAME, ANSWER_ADDRESS);
        assertEquals(
                List.of(QUERY_NAME, nameServer, QUERY_NAME),
                hierarchy.hops().stream()
                        .map(hop -> hop.question().name())
                        .toList()
        );
    }

    @Test
    void shouldAcceptCompleteCnameChainFromOneAnswer()
            throws Exception {

        String firstAlias = "edge.example.test";
        String secondAlias = "origin.example.test";

        ScriptedDnsHierarchy hierarchy =
                new ScriptedDnsHierarchy(
                        response(
                                ROOT_SERVER,
                                QUERY_NAME,
                                reply(
                                        true,
                                        List.of(
                                                cname(QUERY_NAME, firstAlias),
                                                cname(firstAlias, secondAlias),
                                                a(secondAlias, ANSWER_ADDRESS)
                                        ),
                                        List.of(),
                                        List.of()
                                )
                        )
                );

        DnsMessage result = resolver(hierarchy).resolve(clientQuery());

        hierarchy.assertComplete();
        assertAnswerTypes(
                result,
                TYPE_CNAME,
                TYPE_CNAME,
                TYPE_A
        );
        assertEquals(
                ANSWER_ADDRESS,
                ipv4Address(result.answers().get(2))
        );
    }

    @Test
    void shouldChaseCnameSplitAcrossResponses()
            throws Exception {

        String firstAlias = "edge.example.test";
        String secondAlias = "origin.example.test";

        ScriptedDnsHierarchy hierarchy =
                new ScriptedDnsHierarchy(
                        response(
                                ROOT_SERVER,
                                QUERY_NAME,
                                reply(
                                        true,
                                        List.of(cname(QUERY_NAME, firstAlias)),
                                        List.of(),
                                        List.of()
                                )
                        ),
                        response(
                                ROOT_SERVER,
                                firstAlias,
                                reply(
                                        true,
                                        List.of(
                                                cname(firstAlias, secondAlias),
                                                a(secondAlias, ANSWER_ADDRESS)
                                        ),
                                        List.of(),
                                        List.of()
                                )
                        )
                );

        DnsMessage result = resolver(hierarchy).resolve(clientQuery());

        hierarchy.assertComplete();
        assertAnswerTypes(
                result,
                TYPE_CNAME,
                TYPE_CNAME,
                TYPE_A
        );
        assertEquals(
                List.of(QUERY_NAME, firstAlias),
                hierarchy.hops().stream()
                        .map(hop -> hop.question().name())
                        .toList()
        );
    }

    @Test
    void shouldReResolveAnOutOfZoneCnameTargetInsteadOfTrustingBundledData()
            throws Exception {
        String authoritativeServer = "203.0.113.53";
        String externalTarget = "origin.external.test";

        ScriptedDnsHierarchy hierarchy =
                new ScriptedDnsHierarchy(
                        response(
                                ROOT_SERVER,
                                QUERY_NAME,
                                reply(
                                        false,
                                        List.of(),
                                        List.of(ns("example.test", "ns1.example.test")),
                                        List.of(a(
                                                "ns1.example.test",
                                                authoritativeServer
                                        ))
                                )
                        ),
                        response(
                                authoritativeServer,
                                QUERY_NAME,
                                reply(
                                        true,
                                        List.of(
                                                cname(QUERY_NAME, externalTarget),
                                                a(externalTarget, "203.0.113.200")
                                        ),
                                        List.of(),
                                        List.of()
                                )
                        ),
                        response(
                                ROOT_SERVER,
                                externalTarget,
                                reply(
                                        true,
                                        List.of(a(externalTarget, ANSWER_ADDRESS)),
                                        List.of(),
                                        List.of()
                                )
                        )
                );

        DnsMessage result = resolver(hierarchy).resolve(clientQuery());

        hierarchy.assertComplete();
        assertAnswerTypes(result, TYPE_CNAME, TYPE_A);
        assertEquals(ANSWER_ADDRESS, ipv4Address(result.answers().get(1)));
    }

    @Test
    void shouldRejectCnameLoop() {
        String alias = "loop.example.test";

        ScriptedDnsHierarchy hierarchy =
                new ScriptedDnsHierarchy(
                        response(
                                ROOT_SERVER,
                                QUERY_NAME,
                                reply(
                                        true,
                                        List.of(cname(QUERY_NAME, alias)),
                                        List.of(),
                                        List.of()
                                )
                        ),
                        response(
                                ROOT_SERVER,
                                alias,
                                reply(
                                        true,
                                        List.of(cname(alias, QUERY_NAME)),
                                        List.of(),
                                        List.of()
                                )
                        )
                );

        RecordingObserver observer = new RecordingObserver();

        assertThrows(
                Exception.class,
                () -> resolver(hierarchy, observer).resolve(clientQuery())
        );

        hierarchy.assertComplete();
        assertEquals(2, hierarchy.hops().size());
        assertEquals(1, observer.cnameLoopRejections);
    }

    @Test
    void shouldBoundCnameDepth() {
        List<Exchange> exchanges = new ArrayList<>();
        String owner = QUERY_NAME;

        for (int index = 0; index < SCRIPT_BOUND; index++) {
            String target = "alias-" + index + ".example.test";

            exchanges.add(
                    response(
                            ROOT_SERVER,
                            owner,
                            reply(
                                    true,
                                    List.of(cname(owner, target)),
                                    List.of(),
                                    List.of()
                            )
                    )
            );
            owner = target;
        }

        ScriptedDnsHierarchy hierarchy =
                new ScriptedDnsHierarchy(exchanges);

        assertThrows(
                Exception.class,
                () -> resolver(hierarchy).resolve(clientQuery())
        );

        assertTrue(
                hierarchy.hops().size() < SCRIPT_BOUND,
                "CNAME traversal must stop at a fixed depth"
        );
    }

    @Test
    void shouldRejectReferralLoopWithinBound() {
        List<Exchange> exchanges = new ArrayList<>();

        for (int index = 0; index < SCRIPT_BOUND; index++) {
            exchanges.add(
                    response(
                            ROOT_SERVER,
                            QUERY_NAME,
                            reply(
                                    false,
                                    List.of(),
                                    List.of(
                                            ns(
                                                    "example.test",
                                                    "ns.loop.example.test"
                                            )
                                    ),
                                    List.of(
                                            a(
                                                    "ns.loop.example.test",
                                                    ROOT_SERVER
                                            )
                                    )
                            )
                    )
            );
        }

        ScriptedDnsHierarchy hierarchy =
                new ScriptedDnsHierarchy(exchanges);

        assertThrows(
                Exception.class,
                () -> resolver(hierarchy).resolve(clientQuery())
        );

        assertTrue(
                hierarchy.hops().size() < SCRIPT_BOUND,
                "Referral traversal must stop at a fixed depth"
        );
    }

    @Test
    void shouldBoundAcyclicReferralDepth() {
        List<Exchange> exchanges = new ArrayList<>();
        String currentServer = ROOT_SERVER;

        for (int index = 0; index < SCRIPT_BOUND; index++) {
            String nameServer =
                    "ns-" + index + ".example.test";
            String nextServer =
                    "198.51.100." + (index + 1);

            exchanges.add(
                    response(
                            currentServer,
                            QUERY_NAME,
                            reply(
                                    false,
                                    List.of(),
                                    List.of(ns("example.test", nameServer)),
                                    List.of(a(nameServer, nextServer))
                            )
                    )
            );
            currentServer = nextServer;
        }

        ScriptedDnsHierarchy hierarchy =
                new ScriptedDnsHierarchy(exchanges);

        assertThrows(
                Exception.class,
                () -> resolver(hierarchy).resolve(clientQuery())
        );

        assertTrue(
                hierarchy.hops().size() < SCRIPT_BOUND,
                "Referral traversal must stop at a fixed depth"
        );
    }

    @Test
    void unrelatedAnswerMustNotEndResolution()
            throws Exception {

        String authoritativeServer = "203.0.113.53";

        ScriptedDnsHierarchy hierarchy =
                new ScriptedDnsHierarchy(
                        response(
                                ROOT_SERVER,
                                QUERY_NAME,
                                reply(
                                        false,
                                        List.of(
                                                a(
                                                        "attacker.invalid",
                                                        "203.0.113.200"
                                                )
                                        ),
                                        List.of(
                                                ns(
                                                        "example.test",
                                                        "ns1.example.test"
                                                )
                                        ),
                                        List.of(
                                                a(
                                                        "ns1.example.test",
                                                        authoritativeServer
                                                )
                                        )
                                )
                        ),
                        response(
                                authoritativeServer,
                                QUERY_NAME,
                                authoritativeAnswer()
                        )
                );

        DnsMessage result = resolver(hierarchy).resolve(clientQuery());

        hierarchy.assertComplete();
        assertSingleAddress(result, QUERY_NAME, ANSWER_ADDRESS);
    }

    private RecursiveResolver resolver(
            ScriptedDnsHierarchy hierarchy
    ) {
        return new RecursiveResolver(
                hierarchy,
                List.of(ROOT_SERVER)
        );
    }

    private RecursiveResolver resolver(
            ScriptedDnsHierarchy hierarchy,
            ResolverObserver observer
    ) {
        return new RecursiveResolver(
                hierarchy,
                List.of(ROOT_SERVER),
                ResolverCacheConfig.defaults(),
                System::nanoTime,
                observer
        );
    }

    private DnsMessage clientQuery() {
        return clientQuery(QUERY_NAME);
    }

    private DnsMessage clientQuery(String name) {
        DnsQuestion question =
                new DnsQuestion(
                        name,
                        TYPE_A,
                        ScriptedDnsHierarchy.CLASS_IN
                );

        return new DnsMessage(
                new DnsHeader(
                        18_004,
                        0x0100,
                        1,
                        0,
                        0,
                        0
                ),
                List.of(question),
                List.of(),
                List.of(),
                List.of()
        );
    }

    private ScriptedDnsHierarchy.Reply authoritativeAnswer() {
        return reply(
                true,
                List.of(a(QUERY_NAME, ANSWER_ADDRESS)),
                List.of(),
                List.of()
        );
    }

    private void assertSingleAddress(
            DnsMessage response,
            String owner,
            String address
    ) {
        assertEquals(1, response.answers().size());

        DnsRecord answer = response.answers().get(0);

        assertEquals(owner, answer.name());
        assertEquals(TYPE_A, answer.type());
        assertEquals(address, ipv4Address(answer));
    }

    private void assertAnswerTypes(
            DnsMessage response,
            Integer... expectedTypes
    ) {
        assertEquals(
                List.of(expectedTypes),
                response.answers().stream()
                        .map(DnsRecord::type)
                        .toList()
        );
    }

    private static final class RecordingObserver implements ResolverObserver {
        private int nameserverFailovers;
        private int cnameLoopRejections;

        @Override
        public void nameserverFailover() {
            nameserverFailovers++;
        }

        @Override
        public void cnameLoopRejected() {
            cnameLoopRejections++;
        }
    }
}
