package com.ayushman.dns.cache;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.ayushman.dns.protocol.DnsMessage;
import com.ayushman.dns.protocol.DnsRecord;

final class CacheRecordSupport {

    private static final long RFC_2181_MAX_TTL = 0x7FFF_FFFFL;

    private CacheRecordSupport() {
    }

    static CachedDnsData normalizedPositive(
            DnsMessage response,
            long maximumTtlSeconds
    ) {
        if (response == null || response.answers().isEmpty()) {
            return null;
        }

        List<DnsRecord> allRecords = new ArrayList<>();
        allRecords.addAll(response.answers());
        allRecords.addAll(response.authorities());
        allRecords.addAll(response.additionals());

        Map<RecordSetKey, Long> rrsetTtls = new HashMap<>();
        try {
            for (DnsRecord record : allRecords) {
                long ttl = effectiveTtl(record.ttl(), maximumTtlSeconds);
                rrsetTtls.merge(RecordSetKey.from(record), ttl, Math::min);
            }
        } catch (IllegalArgumentException malformedName) {
            return null;
        }

        if (rrsetTtls.values().stream().anyMatch(ttl -> ttl == 0)) {
            return null;
        }

        return new CachedDnsData(
                response.questions(),
                normalize(response.answers(), rrsetTtls),
                normalize(response.authorities(), rrsetTtls),
                normalize(response.additionals(), rrsetTtls)
        );
    }

    static CachedDnsData age(CachedDnsData data, long elapsedSeconds) {
        return new CachedDnsData(
                data.questions(),
                age(data.answers(), elapsedSeconds),
                age(data.authorities(), elapsedSeconds),
                age(data.additionals(), elapsedSeconds)
        );
    }

    static long minimumTtl(CachedDnsData data) {
        long minimum = Long.MAX_VALUE;
        for (DnsRecord record : data.answers()) {
            minimum = Math.min(minimum, record.ttl());
        }
        for (DnsRecord record : data.authorities()) {
            minimum = Math.min(minimum, record.ttl());
        }
        for (DnsRecord record : data.additionals()) {
            minimum = Math.min(minimum, record.ttl());
        }
        return minimum == Long.MAX_VALUE ? 0 : minimum;
    }

    static long effectiveTtl(long ttl, long maximumTtlSeconds) {
        if (ttl < 0 || ttl > RFC_2181_MAX_TTL) {
            return 0;
        }
        return Math.min(ttl, maximumTtlSeconds);
    }

    static long durationNanos(long ttlSeconds) {
        try {
            return Math.multiplyExact(ttlSeconds, 1_000_000_000L);
        } catch (ArithmeticException overflow) {
            return Long.MAX_VALUE;
        }
    }

    static DnsRecord copyWithTtl(DnsRecord record, long ttl) {
        return new DnsRecord(
                record.name(),
                record.type(),
                record.qclass(),
                ttl,
                record.rdata()
        );
    }

    private static List<DnsRecord> normalize(
            List<DnsRecord> records,
            Map<RecordSetKey, Long> rrsetTtls
    ) {
        List<DnsRecord> normalized = new ArrayList<>(records.size());
        for (DnsRecord record : records) {
            normalized.add(copyWithTtl(
                    record,
                    rrsetTtls.get(RecordSetKey.from(record))
            ));
        }
        return List.copyOf(normalized);
    }

    private static List<DnsRecord> age(
            List<DnsRecord> records,
            long elapsedSeconds
    ) {
        List<DnsRecord> aged = new ArrayList<>(records.size());
        for (DnsRecord record : records) {
            aged.add(copyWithTtl(
                    record,
                    Math.max(record.ttl() - elapsedSeconds, 0)
            ));
        }
        return List.copyOf(aged);
    }

    private record RecordSetKey(
            CanonicalDnsName name,
            int type,
            int qclass
    ) {
        private static RecordSetKey from(DnsRecord record) {
            return new RecordSetKey(
                    CanonicalDnsName.from(record.name()),
                    record.type(),
                    record.qclass()
            );
        }
    }
}
