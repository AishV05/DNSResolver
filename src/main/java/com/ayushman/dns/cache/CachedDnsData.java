package com.ayushman.dns.cache;

import java.util.List;

import com.ayushman.dns.protocol.DnsQuestion;
import com.ayushman.dns.protocol.DnsRecord;

/**
 * Immutable DNS dataset stored in the cache.
 *
 * This intentionally excludes the DNS header because
 * headers are client-specific transport metadata.
 */
public record CachedDnsData(

        List<DnsQuestion> questions,

        List<DnsRecord> answers,

        List<DnsRecord> authorities,

        List<DnsRecord> additionals

) {}