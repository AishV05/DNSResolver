package com.ayushman.dns.server;

import java.util.List;

import com.ayushman.dns.protocol.DnsHeader;
import com.ayushman.dns.protocol.DnsMessage;
import com.ayushman.dns.protocol.DnsPacketParser;
import com.ayushman.dns.protocol.DnsPacketWriter;
import com.ayushman.dns.protocol.DnsQuestion;
import com.ayushman.dns.protocol.EdnsInfo;
import com.ayushman.dns.resolver.DnsResolver;

/**
 * Transport-neutral DNS parsing and resolution. UDP applies its negotiated
 * payload limit; TCP always returns the complete DNS message.
 */
final class DnsRequestProcessor {

    private static final int DEFAULT_UDP_PAYLOAD_SIZE = 512;
    private static final int SERVER_UDP_PAYLOAD_SIZE = 1_232;
    private static final int BADVERS_EXTENDED_RCODE = 1;
    private static final int TRUNCATED_FLAG = 0x0200;
    private static final int QUERY_RESPONSE_FLAG = 0x8000;
    private static final int OPCODE_MASK = 0x7800;
    private static final int RECURSION_DESIRED_FLAG = 0x0100;
    private static final int RECURSION_AVAILABLE_FLAG = 0x0080;
    private static final int CHECKING_DISABLED_FLAG = 0x0010;

    private final DnsResolver resolver;
    private final ServerMetrics metrics;
    private final PolicySnapshotStore policyStore;
    private final PolicyTelemetry policyTelemetry;

    DnsRequestProcessor(
            DnsResolver resolver,
            ServerMetrics metrics
    ) {
        this(
                resolver,
                metrics,
                new PolicySnapshotStore(PolicySyncMode.DISABLED),
                PolicyTelemetry.forMode(PolicySyncMode.DISABLED)
        );
    }

    DnsRequestProcessor(
            DnsResolver resolver,
            ServerMetrics metrics,
            PolicySnapshotStore policyStore
    ) {
        this(
                resolver,
                metrics,
                policyStore,
                PolicyTelemetry.forMode(policyStore == null
                        ? null
                        : policyStore.mode())
        );
    }

    DnsRequestProcessor(
            DnsResolver resolver,
            ServerMetrics metrics,
            PolicySnapshotStore policyStore,
            PolicyTelemetry policyTelemetry
    ) {
        if (resolver == null
                || metrics == null
                || policyStore == null
                || policyTelemetry == null) {
            throw new IllegalArgumentException(
                    "processor dependencies must not be null"
            );
        }
        if (policyStore.mode() != policyTelemetry.mode()) {
            throw new IllegalArgumentException(
                    "policy store and telemetry modes must match"
            );
        }

        this.resolver = resolver;
        this.metrics = metrics;
        this.policyStore = policyStore;
        this.policyTelemetry = policyTelemetry;
    }

    byte[] process(
            byte[] requestData,
            DnsTransport transport
    ) throws Exception {
        if (requestData == null || transport == null) {
            throw new IllegalArgumentException(
                    "requestData and transport must not be null"
            );
        }

        long startTime = System.nanoTime();
        DnsMessage query;

        try {
            query = DnsPacketParser.parse(requestData);
        } catch (Exception parseFailure) {
            metrics.recordMalformedRequest(transport);
            return prepareResponse(
                    formatError(requestData),
                    DEFAULT_UDP_PAYLOAD_SIZE,
                    transport
            );
        }

        if (hasUnsupportedEdnsVersion(query)) {
            metrics.recordUnsupportedEdnsVersion(transport);
            return prepareResponse(
                    badVersion(query),
                    responsePayloadSize(query),
                    transport
            );
        }

        if ((query.header().flags() & QUERY_RESPONSE_FLAG) != 0
                || query.questions().size() != 1) {
            return prepareResponse(
                    formError(query),
                    responsePayloadSize(query),
                    transport
            );
        }
        if ((query.header().flags() & OPCODE_MASK) != 0) {
            return prepareResponse(
                    notImplemented(query),
                    responsePayloadSize(query),
                    transport
            );
        }

        switch (policyDecision(query)) {
            case UNAVAILABLE -> {
                policyTelemetry.recordUnavailable(transport);
                return prepareResponse(
                        servFail(query),
                        responsePayloadSize(query),
                        transport
                );
            }
            case BLOCK -> {
                policyTelemetry.recordBlocked(transport);
                return prepareResponse(
                        refused(query),
                        responsePayloadSize(query),
                        transport
                );
            }
            case ALLOW -> {
                // Continue to recursive resolution below.
            }
        }

        try {
            DnsMessage response = withEdnsForClient(
                    resolver.resolve(query),
                    query
            );
            byte[] encoded = prepareResponse(
                    response,
                    responsePayloadSize(query),
                    transport
            );
            metrics.recordResolvedRequest(
                    transport,
                    System.nanoTime() - startTime
            );
            return encoded;
        } catch (Exception resolverFailure) {
            metrics.recordResolverFailure(transport);
            return prepareResponse(
                    servFail(query),
                    responsePayloadSize(query),
                    transport
            );
        }
    }

    private PolicySnapshotStore.EvaluationResult policyDecision(
            DnsMessage query
    ) {
        try {
            return policyStore.evaluate(query.questions().get(0));
        } catch (RuntimeException unavailable) {
            return PolicySnapshotStore.EvaluationResult.UNAVAILABLE;
        }
    }

    private DnsMessage refused(
            DnsMessage query
    ) {
        return questionErrorResponse(query, 0x0005);
    }

    private DnsMessage servFail(
            DnsMessage query
    ) {
        return questionErrorResponse(query, 0x0002);
    }

    private DnsMessage notImplemented(
            DnsMessage query
    ) {
        return questionErrorResponse(query, 0x0004);
    }

    private DnsMessage formError(
            DnsMessage query
    ) {
        int flags = responseFlags(query.header().flags(), 0x0001);

        return new DnsMessage(
                new DnsHeader(query.header().id(), flags, 0, 0, 0, 0),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                query.edns().map(ignored -> responseEdns(query)).orElse(null)
        );
    }

    private DnsMessage questionErrorResponse(
            DnsMessage query,
            int responseCode
    ) {
        int flags = responseFlags(query.header().flags(), responseCode);
        List<DnsQuestion> questions = query.questions();

        return new DnsMessage(
                new DnsHeader(
                        query.header().id(),
                        flags,
                        questions.size(),
                        0,
                        0,
                        0
                ),
                questions,
                List.of(),
                List.of(),
                List.of(),
                query.edns().map(ignored -> responseEdns(query)).orElse(null)
        );
    }

    private DnsMessage badVersion(
            DnsMessage query
    ) {
        int flags = responseFlags(query.header().flags(), 0);

        return new DnsMessage(
                new DnsHeader(
                        query.header().id(),
                        flags,
                        query.questions().size(),
                        0,
                        0,
                        0
                ),
                query.questions(),
                List.of(),
                List.of(),
                List.of(),
                new EdnsInfo(
                        responsePayloadSize(query),
                        BADVERS_EXTENDED_RCODE,
                        EdnsInfo.VERSION_ZERO,
                        0,
                        new byte[0]
                )
        );
    }

    private DnsMessage formatError(
            byte[] requestData
    ) {
        int id = requestData.length >= 2
                ? ((requestData[0] & 0xFF) << 8)
                        | (requestData[1] & 0xFF)
                : 0;
        int requestFlags = requestData.length >= 4
                ? ((requestData[2] & 0xFF) << 8)
                        | (requestData[3] & 0xFF)
                : 0;
        int flags = responseFlags(requestFlags, 0x0001);

        return new DnsMessage(
                new DnsHeader(id, flags, 0, 0, 0, 0),
                List.of(),
                List.of(),
                List.of(),
                List.of()
        );
    }

    private boolean hasUnsupportedEdnsVersion(
            DnsMessage query
    ) {
        return query.edns()
                .map(edns -> edns.version() != EdnsInfo.VERSION_ZERO)
                .orElse(false);
    }

    private int responseFlags(int requestFlags, int responseCode) {
        return QUERY_RESPONSE_FLAG
                | (requestFlags & (
                        OPCODE_MASK
                                | RECURSION_DESIRED_FLAG
                                | CHECKING_DISABLED_FLAG
                ))
                | RECURSION_AVAILABLE_FLAG
                | responseCode;
    }

    private DnsMessage withEdnsForClient(
            DnsMessage resolverResponse,
            DnsMessage clientQuery
    ) {
        return new DnsMessage(
                resolverResponse.header(),
                resolverResponse.questions(),
                resolverResponse.answers(),
                resolverResponse.authorities(),
                resolverResponse.additionals(),
                clientQuery.edns()
                        .map(ignored -> responseEdns(clientQuery))
                        .orElse(null)
        );
    }

    private EdnsInfo responseEdns(
            DnsMessage query
    ) {
        return new EdnsInfo(
                responsePayloadSize(query),
                0,
                EdnsInfo.VERSION_ZERO,
                0,
                new byte[0]
        );
    }

    private int responsePayloadSize(
            DnsMessage query
    ) {
        return query.edns()
                .map(EdnsInfo::effectiveUdpPayloadSize)
                .map(size -> Math.min(size, SERVER_UDP_PAYLOAD_SIZE))
                .orElse(DEFAULT_UDP_PAYLOAD_SIZE);
    }

    private byte[] prepareResponse(
            DnsMessage response,
            int udpPayloadSize,
            DnsTransport transport
    ) throws Exception {
        byte[] encoded = DnsPacketWriter.buildResponse(response);

        if (transport == DnsTransport.UDP
                && encoded.length > udpPayloadSize) {
            return DnsPacketWriter.buildResponse(
                    truncatedResponse(response)
            );
        }

        return encoded;
    }

    private DnsMessage truncatedResponse(
            DnsMessage response
    ) {
        DnsHeader header = response.header();

        return new DnsMessage(
                new DnsHeader(
                        header.id(),
                        header.flags() | TRUNCATED_FLAG,
                        response.questions().size(),
                        0,
                        0,
                        0
                ),
                response.questions(),
                List.of(),
                List.of(),
                List.of(),
                response.edns().orElse(null)
        );
    }
}
