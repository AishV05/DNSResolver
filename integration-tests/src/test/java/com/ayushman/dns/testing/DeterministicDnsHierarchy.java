package com.ayushman.dns.testing;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import com.ayushman.dns.protocol.DnsHeader;
import com.ayushman.dns.protocol.DnsMessage;
import com.ayushman.dns.protocol.DnsNameCodec;
import com.ayushman.dns.protocol.DnsQuestion;
import com.ayushman.dns.protocol.DnsRecord;
import com.ayushman.dns.resolver.UpstreamDnsClient;

/**
 * A deterministic, in-memory root-to-authority DNS hierarchy for tests.
 */
public final class DeterministicDnsHierarchy
        extends UpstreamDnsClient {

    public static final String ROOT_SERVER =
            "192.0.2.53";

    public static final String TLD_SERVER =
            "198.51.100.53";

    public static final String AUTHORITATIVE_SERVER =
            "203.0.113.53";

    public static final String QUERY_NAME =
            "www.example.test";

    public static final String ANSWER_ADDRESS =
            "192.0.2.80";

    private static final int TYPE_A = 1;

    private static final int TYPE_NS = 2;

    private static final int CLASS_IN = 1;

    private static final long REFERRAL_TTL_SECONDS =
            86_400;

    private static final long ANSWER_TTL_SECONDS =
            300;

    private static final List<String> EXPECTED_SERVERS =
            List.of(
                    ROOT_SERVER,
                    TLD_SERVER,
                    AUTHORITATIVE_SERVER
            );

    private final List<Hop> hops =
            new ArrayList<>();

    public DeterministicDnsHierarchy() {
        super(1, 1, 53);
    }

    @Override
    public synchronized DnsMessage query(
            String serverIp,
            DnsMessage query
    ) {

        DnsQuestion question =
                requireSupportedQuestion(query);

        int hopIndex =
                hops.size();

        if (hopIndex >= EXPECTED_SERVERS.size()) {
            throw new IllegalStateException(
                    "The scripted hierarchy received too many queries"
            );
        }

        String expectedServer =
                EXPECTED_SERVERS.get(hopIndex);

        if (!expectedServer.equals(serverIp)) {
            throw new IllegalStateException(
                    "Expected query to "
                            + expectedServer
                            + " but received query to "
                            + serverIp
            );
        }

        hops.add(
                new Hop(serverIp, question)
        );

        return switch (serverIp) {
            case ROOT_SERVER -> rootReferral(query, question);
            case TLD_SERVER -> tldReferral(query, question);
            case AUTHORITATIVE_SERVER ->
                    authoritativeAnswer(query, question);
            default -> throw new IllegalStateException(
                    "No scripted DNS server for " + serverIp
            );
        };
    }

    public synchronized List<Hop> hops() {
        return List.copyOf(hops);
    }

    private DnsQuestion requireSupportedQuestion(
            DnsMessage query
    ) {

        if (query.questions().size() != 1) {
            throw new IllegalStateException(
                    "The scripted hierarchy expects one question"
            );
        }

        DnsQuestion question =
                query.questions().get(0);

        if (!QUERY_NAME.equals(question.name())
                || question.type() != TYPE_A
                || question.qclass() != CLASS_IN) {

            throw new IllegalStateException(
                    "Unsupported scripted question: " + question
            );
        }

        return question;
    }

    private DnsMessage rootReferral(
            DnsMessage query,
            DnsQuestion question
    ) {

        DnsRecord nameServer =
                new DnsRecord(
                        "test",
                        TYPE_NS,
                        CLASS_IN,
                        REFERRAL_TTL_SECONDS,
                        encodedName("ns1.test")
                );

        DnsRecord glue =
                new DnsRecord(
                        "ns1.test",
                        TYPE_A,
                        CLASS_IN,
                        REFERRAL_TTL_SECONDS,
                        ipv4(TLD_SERVER)
                );

        return response(
                query,
                question,
                false,
                List.of(),
                List.of(nameServer),
                List.of(glue)
        );
    }

    private DnsMessage tldReferral(
            DnsMessage query,
            DnsQuestion question
    ) {

        DnsRecord nameServer =
                new DnsRecord(
                        "example.test",
                        TYPE_NS,
                        CLASS_IN,
                        REFERRAL_TTL_SECONDS,
                        encodedName("ns1.example.test")
                );

        DnsRecord glue =
                new DnsRecord(
                        "ns1.example.test",
                        TYPE_A,
                        CLASS_IN,
                        REFERRAL_TTL_SECONDS,
                        ipv4(AUTHORITATIVE_SERVER)
                );

        return response(
                query,
                question,
                false,
                List.of(),
                List.of(nameServer),
                List.of(glue)
        );
    }

    private DnsMessage authoritativeAnswer(
            DnsMessage query,
            DnsQuestion question
    ) {

        DnsRecord answer =
                new DnsRecord(
                        QUERY_NAME,
                        TYPE_A,
                        CLASS_IN,
                        ANSWER_TTL_SECONDS,
                        ipv4(ANSWER_ADDRESS)
                );

        return response(
                query,
                question,
                true,
                List.of(answer),
                List.of(),
                List.of()
        );
    }

    private DnsMessage response(
            DnsMessage query,
            DnsQuestion question,
            boolean authoritative,
            List<DnsRecord> answers,
            List<DnsRecord> authorities,
            List<DnsRecord> additionals
    ) {

        int recursionDesired =
                query.header().flags() & 0x0100;

        int flags =
                0x8000 | recursionDesired;

        if (authoritative) {
            flags |= 0x0400;
        }

        DnsHeader header =
                new DnsHeader(
                        query.header().id(),
                        flags,
                        1,
                        answers.size(),
                        authorities.size(),
                        additionals.size()
                );

        return new DnsMessage(
                header,
                List.of(question),
                answers,
                authorities,
                additionals
        );
    }

    private byte[] encodedName(
            String name
    ) {

        ByteBuffer buffer =
                ByteBuffer.allocate(255);

        DnsNameCodec.encode(name, buffer);

        return Arrays.copyOf(
                buffer.array(),
                buffer.position()
        );
    }

    private byte[] ipv4(
            String address
    ) {

        String[] octets =
                address.split("\\.");

        if (octets.length != 4) {
            throw new IllegalArgumentException(
                    "Expected an IPv4 address: " + address
            );
        }

        byte[] result =
                new byte[4];

        for (int i = 0; i < octets.length; i++) {
            result[i] =
                    (byte) Integer.parseInt(octets[i]);
        }

        return result;
    }

    public record Hop(
            String serverAddress,
            DnsQuestion question
    ) {
    }
}
