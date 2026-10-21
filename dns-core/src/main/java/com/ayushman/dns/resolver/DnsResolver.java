package com.ayushman.dns.resolver;

import com.ayushman.dns.protocol.DnsMessage;

/** Resolves a parsed DNS query without imposing a transport or framework. */
@FunctionalInterface
public interface DnsResolver {

    DnsMessage resolve(DnsMessage query) throws Exception;
}
