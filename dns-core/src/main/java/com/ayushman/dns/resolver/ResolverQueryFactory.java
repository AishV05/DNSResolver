package com.ayushman.dns.resolver;

import java.security.SecureRandom;
import java.util.List;
import java.util.Objects;

import com.ayushman.dns.protocol.DnsHeader;
import com.ayushman.dns.protocol.DnsMessage;
import com.ayushman.dns.protocol.DnsQuestion;
import com.ayushman.dns.protocol.EdnsInfo;

public final class ResolverQueryFactory {

    public static final int UPSTREAM_UDP_PAYLOAD_SIZE = 1_232;
    static final int TRANSACTION_ID_BOUND = 1 << 16;

    private static final SecureRandom TRANSACTION_ID_RANDOM = new SecureRandom();

    private ResolverQueryFactory() {}

    public static DnsMessage create(
            DnsQuestion question
    ) {
        return create(question, TRANSACTION_ID_RANDOM);
    }

    static DnsMessage create(
            DnsQuestion question,
            SecureRandom transactionIdRandom
    ) {
        Objects.requireNonNull(question, "question");
        Objects.requireNonNull(transactionIdRandom, "transactionIdRandom");

        int transactionId =
                transactionIdRandom.nextInt(TRANSACTION_ID_BOUND);

        if (transactionId < 0 || transactionId >= TRANSACTION_ID_BOUND) {
            throw new IllegalStateException(
                    "Transaction ID source returned an out-of-range value: "
                            + transactionId
            );
        }

        DnsHeader header =
                new DnsHeader(
                        transactionId,
                        0,
                        1,
                        0,
                        0,
                        0
                );

        return new DnsMessage(
                header,
                List.of(question),
                List.of(),
                List.of(),
                List.of(),
                new EdnsInfo(
                        UPSTREAM_UDP_PAYLOAD_SIZE,
                        0,
                        0,
                        0,
                        new byte[0]
                )
        );
    }
}
