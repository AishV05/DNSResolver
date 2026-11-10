package com.ayushman.dns.resolver;

import static com.ayushman.dns.testing.ScriptedDnsHierarchy.TYPE_A;
import static com.ayushman.dns.testing.ScriptedDnsHierarchy.a;
import static com.ayushman.dns.testing.ScriptedDnsHierarchy.cname;
import static com.ayushman.dns.testing.ScriptedDnsHierarchy.failure;
import static com.ayushman.dns.testing.ScriptedDnsHierarchy.ns;
import static com.ayushman.dns.testing.ScriptedDnsHierarchy.reply;
import static com.ayushman.dns.testing.ScriptedDnsHierarchy.response;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

import com.ayushman.dns.policy.DnsPolicyRefusedException;
import com.ayushman.dns.policy.DnsResolutionPolicy;
import com.ayushman.dns.protocol.DnsHeader;
import com.ayushman.dns.protocol.DnsMessage;
import com.ayushman.dns.protocol.DnsQuestion;
import com.ayushman.dns.testing.ScriptedDnsHierarchy;

class RecursiveResolverPolicyIntegrityTest {

    private static final String ROOT = "192.0.2.1";
    private static final String ALIAS = "alias.example.test";
    private static final String TARGET = "blocked.example.test";

    @Test
    void blocksTargetBeforeLookupAndRechecksWarmCacheAfterPolicyChanges()
            throws Exception {
        ScriptedDnsHierarchy hierarchy = new ScriptedDnsHierarchy(
                response(ROOT, ALIAS, authoritativeCname()),
                response(ROOT, ALIAS, authoritativeCname()),
                response(
                        ROOT,
                        TARGET,
                        reply(
                                true,
                                List.of(a(TARGET, "192.0.2.80")),
                                List.of(),
                                List.of()
                        )
                )
        );
        RecursiveResolver resolver = new RecursiveResolver(
                hierarchy,
                List.of(ROOT)
        );
        DnsMessage query = query(ALIAS);

        assertThrows(
                DnsPolicyRefusedException.class,
                () -> resolver.resolve(query, block(TARGET))
        );
        assertEquals(1, hierarchy.hops().size());

        DnsMessage allowed = resolver.resolve(
                query,
                DnsResolutionPolicy.ALLOW_ALL
        );
        assertEquals(2, allowed.answers().size());
        assertEquals(3, hierarchy.hops().size());

        assertThrows(
                DnsPolicyRefusedException.class,
                () -> resolver.resolve(query, block(TARGET))
        );
        assertEquals(3, hierarchy.hops().size());

        DnsMessage allowedAgain = resolver.resolve(
                query,
                DnsResolutionPolicy.ALLOW_ALL
        );
        assertEquals(2, allowedAgain.answers().size());
        assertEquals(3, hierarchy.hops().size());
        hierarchy.assertComplete();
    }

    @Test
    void blocksSameResponseCnameTargetBeforeReturningOrCaching()
            throws Exception {
        ScriptedDnsHierarchy hierarchy = new ScriptedDnsHierarchy(
                response(
                        ROOT,
                        ALIAS,
                        reply(
                                true,
                                List.of(
                                        cname(ALIAS, TARGET),
                                        a(TARGET, "192.0.2.80")
                                ),
                                List.of(),
                                List.of()
                        )
                )
        );
        RecursiveResolver resolver = new RecursiveResolver(
                hierarchy,
                List.of(ROOT)
        );

        assertThrows(
                DnsPolicyRefusedException.class,
                () -> resolver.resolve(query(ALIAS), block(TARGET))
        );
        hierarchy.assertComplete();
    }

    @Test
    void exemptsNameServerInfrastructureAliasesFromClientPolicy()
            throws Exception {
        String queryName = "www.example.test";
        String nameServer = "ns.blocked.example";
        String addressAlias = "host.blocked.example";
        String authoritativeServer = "203.0.113.53";
        ScriptedDnsHierarchy hierarchy = new ScriptedDnsHierarchy(
                response(
                        ROOT,
                        queryName,
                        reply(
                                false,
                                List.of(),
                                List.of(ns("example.test", nameServer)),
                                List.of()
                        )
                ),
                response(
                        ROOT,
                        nameServer,
                        reply(
                                true,
                                List.of(
                                        cname(nameServer, addressAlias),
                                        a(addressAlias, authoritativeServer)
                                ),
                                List.of(),
                                List.of()
                        )
                ),
                response(
                        authoritativeServer,
                        queryName,
                        reply(
                                true,
                                List.of(a(queryName, "192.0.2.80")),
                                List.of(),
                                List.of()
                        )
                )
        );
        List<String> evaluated = new ArrayList<>();
        DnsResolutionPolicy policy = question -> {
            evaluated.add(question.name());
            if (question.name().toLowerCase().contains("blocked.example")) {
                throw new DnsPolicyRefusedException();
            }
        };

        DnsMessage result = new RecursiveResolver(
                hierarchy,
                List.of(ROOT)
        ).resolve(query(queryName), policy);

        assertEquals(1, result.answers().size());
        assertEquals(List.of(queryName), evaluated);
        hierarchy.assertComplete();
    }

    @Test
    void failedResolutionDoesNotPopulateThePositiveCache() throws Exception {
        String name = "retry.example.test";
        ScriptedDnsHierarchy hierarchy = new ScriptedDnsHierarchy(
                failure(ROOT, name, new UpstreamDnsException("timeout")),
                response(
                        ROOT,
                        name,
                        reply(
                                true,
                                List.of(a(name, "192.0.2.80")),
                                List.of(),
                                List.of()
                        )
                )
        );
        RecursiveResolver resolver = new RecursiveResolver(
                hierarchy,
                List.of(ROOT)
        );

        assertThrows(UpstreamDnsException.class, () -> resolver.resolve(query(name)));
        assertEquals(1, resolver.resolve(query(name)).answers().size());
        assertEquals(2, hierarchy.hops().size());
        hierarchy.assertComplete();
    }

    private ScriptedDnsHierarchy.Reply authoritativeCname() {
        return reply(
                true,
                List.of(cname(ALIAS, TARGET)),
                List.of(),
                List.of()
        );
    }

    private DnsResolutionPolicy block(String blockedName) {
        return question -> {
            if (question.name().equalsIgnoreCase(blockedName)) {
                throw new DnsPolicyRefusedException();
            }
        };
    }

    private DnsMessage query(String name) {
        DnsQuestion question = new DnsQuestion(name, TYPE_A, 1);
        return new DnsMessage(
                new DnsHeader(0x18E0, 0x0100, 1, 0, 0, 0),
                List.of(question),
                List.of(),
                List.of(),
                List.of()
        );
    }
}
