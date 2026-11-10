package com.ayushman.dns.testing;

import java.nio.ByteBuffer;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Deque;
import java.util.List;
import java.util.Locale;

import com.ayushman.dns.protocol.DnsHeader;
import com.ayushman.dns.protocol.DnsMessage;
import com.ayushman.dns.protocol.DnsNameCodec;
import com.ayushman.dns.protocol.DnsQuestion;
import com.ayushman.dns.protocol.DnsRecord;
import com.ayushman.dns.resolver.UpstreamDnsClient;

/**
 * Executes an ordered set of in-memory DNS exchanges.
 *
 * <p>The fixture deliberately checks the destination and question before
 * returning a response. A resolver therefore cannot make an unexpected
 * network hop without failing the test that supplied the script.</p>
 */
public final class ScriptedDnsHierarchy
        extends UpstreamDnsClient {

    public static final int TYPE_A = 1;

    public static final int TYPE_NS = 2;

    public static final int TYPE_CNAME = 5;

    public static final int CLASS_IN = 1;

    private static final int FLAG_RESPONSE = 0x8000;

    private static final int FLAG_AUTHORITATIVE = 0x0400;

    private final Deque<Exchange> remaining;

    private final List<Hop> hops = new ArrayList<>();

    public ScriptedDnsHierarchy(
            Exchange... exchanges
    ) {
        this(List.of(exchanges));
    }

    public ScriptedDnsHierarchy(
            Collection<Exchange> exchanges
    ) {
        super(1, 1, 53);
        remaining = new ArrayDeque<>(exchanges);
    }

    @Override
    public synchronized DnsMessage query(
            String serverIp,
            DnsMessage query
    ) throws Exception {

        if (query.questions().size() != 1) {
            throw new AssertionError(
                    "Expected one question but received "
                            + query.questions().size()
            );
        }

        Exchange exchange = remaining.pollFirst();

        if (exchange == null) {
            throw new AssertionError(
                    "Unexpected query to "
                            + serverIp
                            + " for "
                            + query.questions().get(0)
            );
        }

        DnsQuestion question = query.questions().get(0);

        requireEqual(
                exchange.serverAddress(),
                serverIp,
                "server address"
        );
        requireEqual(
                canonicalName(exchange.questionName()),
                canonicalName(question.name()),
                "question name"
        );
        requireEqual(
                exchange.questionType(),
                question.type(),
                "question type"
        );
        requireEqual(
                exchange.questionClass(),
                question.qclass(),
                "question class"
        );

        hops.add(new Hop(serverIp, question));

        if (exchange.failure() != null) {
            throw exchange.failure();
        }

        Reply reply = exchange.reply();
        int flags = FLAG_RESPONSE | reply.responseCode();

        if (reply.authoritative()) {
            flags |= FLAG_AUTHORITATIVE;
        }

        return new DnsMessage(
                new DnsHeader(
                        query.header().id(),
                        flags,
                        1,
                        reply.answers().size(),
                        reply.authorities().size(),
                        reply.additionals().size()
                ),
                List.of(question),
                reply.answers(),
                reply.authorities(),
                reply.additionals()
        );
    }

    public synchronized List<Hop> hops() {
        return List.copyOf(hops);
    }

    public synchronized void assertComplete() {
        if (!remaining.isEmpty()) {
            throw new AssertionError(
                    "Script still contains "
                            + remaining.size()
                            + " unconsumed exchange(s)"
            );
        }
    }

    public static Exchange response(
            String serverAddress,
            String questionName,
            Reply reply
    ) {
        return response(
                serverAddress,
                questionName,
                TYPE_A,
                reply
        );
    }

    public static Exchange response(
            String serverAddress,
            String questionName,
            int questionType,
            Reply reply
    ) {
        return new Exchange(
                serverAddress,
                questionName,
                questionType,
                CLASS_IN,
                reply,
                null
        );
    }

    public static Exchange failure(
            String serverAddress,
            String questionName,
            Exception failure
    ) {
        return new Exchange(
                serverAddress,
                questionName,
                TYPE_A,
                CLASS_IN,
                null,
                failure
        );
    }

    public static Reply reply(
            boolean authoritative,
            List<DnsRecord> answers,
            List<DnsRecord> authorities,
            List<DnsRecord> additionals
    ) {
        return new Reply(
                authoritative,
                0,
                answers,
                authorities,
                additionals
        );
    }

    public static DnsRecord a(
            String owner,
            String address
    ) {
        return new DnsRecord(
                owner,
                TYPE_A,
                CLASS_IN,
                300,
                ipv4(address)
        );
    }

    public static DnsRecord aaaa(
            String owner,
            String address
    ) {
        byte[] data;
        try {
            data = InetAddress.getByName(address).getAddress();
        } catch (UnknownHostException invalidAddress) {
            throw new IllegalArgumentException(
                    "Expected an IPv6 address: " + address,
                    invalidAddress
            );
        }
        if (data.length != 16) {
            throw new IllegalArgumentException(
                    "Expected an IPv6 address: " + address
            );
        }

        return new DnsRecord(
                owner,
                28,
                CLASS_IN,
                300,
                data
        );
    }

    public static DnsRecord ns(
            String zone,
            String nameServer
    ) {
        return nameRecord(
                zone,
                TYPE_NS,
                86_400,
                nameServer
        );
    }

    public static DnsRecord cname(
            String owner,
            String target
    ) {
        return nameRecord(
                owner,
                TYPE_CNAME,
                300,
                target
        );
    }

    public static String ipv4Address(
            DnsRecord record
    ) {
        byte[] address = record.rdata();

        if (record.type() != TYPE_A || address.length != 4) {
            throw new IllegalArgumentException(
                    "Record does not contain an IPv4 address"
            );
        }

        return (address[0] & 0xFF)
                + "."
                + (address[1] & 0xFF)
                + "."
                + (address[2] & 0xFF)
                + "."
                + (address[3] & 0xFF);
    }

    private static DnsRecord nameRecord(
            String owner,
            int type,
            long ttl,
            String target
    ) {
        ByteBuffer buffer = ByteBuffer.allocate(255);
        DnsNameCodec.encode(target, buffer);

        return new DnsRecord(
                owner,
                type,
                CLASS_IN,
                ttl,
                Arrays.copyOf(buffer.array(), buffer.position())
        );
    }

    private static byte[] ipv4(
            String address
    ) {
        String[] octets = address.split("\\.");

        if (octets.length != 4) {
            throw new IllegalArgumentException(
                    "Expected an IPv4 address: " + address
            );
        }

        byte[] result = new byte[4];

        for (int index = 0; index < octets.length; index++) {
            int value = Integer.parseInt(octets[index]);

            if (value < 0 || value > 255) {
                throw new IllegalArgumentException(
                        "Expected an IPv4 address: " + address
                );
            }

            result[index] = (byte) value;
        }

        return result;
    }

    private static String canonicalName(
            String name
    ) {
        String canonical = name.toLowerCase(Locale.ROOT);

        if (canonical.endsWith(".")) {
            return canonical.substring(0, canonical.length() - 1);
        }

        return canonical;
    }

    private static void requireEqual(
            Object expected,
            Object actual,
            String field
    ) {
        if (!expected.equals(actual)) {
            throw new AssertionError(
                    "Expected "
                            + field
                            + " "
                            + expected
                            + " but received "
                            + actual
            );
        }
    }

    public record Exchange(
            String serverAddress,
            String questionName,
            int questionType,
            int questionClass,
            Reply reply,
            Exception failure
    ) {
        public Exchange {
            if ((reply == null) == (failure == null)) {
                throw new IllegalArgumentException(
                        "Exactly one scripted outcome is required"
                );
            }
        }
    }

    public record Reply(
            boolean authoritative,
            int responseCode,
            List<DnsRecord> answers,
            List<DnsRecord> authorities,
            List<DnsRecord> additionals
    ) {
        public Reply {
            if (responseCode < 0 || responseCode > 15) {
                throw new IllegalArgumentException(
                        "responseCode must be between 0 and 15"
                );
            }

            answers = List.copyOf(answers);
            authorities = List.copyOf(authorities);
            additionals = List.copyOf(additionals);
        }
    }

    public record Hop(
            String serverAddress,
            DnsQuestion question
    ) {
    }
}
