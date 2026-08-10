package com.ayushman.dns.resolver;

import java.util.ArrayList;
import java.util.List;

import com.ayushman.dns.protocol.DnsRecord;

public final class DnsRecordCloner {

    private DnsRecordCloner() {
    }

    public static List<DnsRecord> cloneRecords(

            List<DnsRecord> records,

            long ttl

    ) {

        List<DnsRecord> cloned =
                new ArrayList<>();

        for (DnsRecord record : records) {

            cloned.add(

                    new DnsRecord(

                            record.name(),

                            record.type(),

                            record.qclass(),

                            ttl,

                            record.rdata().clone()

                    )

            );

        }

        return cloned;
    }
}