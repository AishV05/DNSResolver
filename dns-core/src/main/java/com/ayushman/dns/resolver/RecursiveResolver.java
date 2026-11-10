package com.ayushman.dns.resolver;

import java.util.List;
import java.util.function.LongSupplier;

import com.ayushman.dns.cache.CachedDnsData;
import com.ayushman.dns.cache.DnsCache;
import com.ayushman.dns.cache.NegativeCache;
import com.ayushman.dns.cache.NegativeCacheEntry;
import com.ayushman.dns.cache.NegativeCacheType;
import com.ayushman.dns.cache.ResolverCacheConfig;
import com.ayushman.dns.policy.DnsResolutionPolicy;
import com.ayushman.dns.protocol.DnsMessage;
import com.ayushman.dns.protocol.DnsQuestion;
import com.ayushman.dns.protocol.DnsRecord;

/** Iterative resolver with bounded, TTL-aware positive and negative caches. */
public class RecursiveResolver implements DnsResolver {

    private static final int TYPE_SOA = 6;
    private static final int RCODE_MASK = 0x000F;

    private final IterativeResolverEngine iterativeResolver;
    private final DnsCache cache;
    private final NegativeCache negativeCache;
    private final Object cacheMutationLock = new Object();

    public RecursiveResolver() {
        this(
                new UpstreamDnsClient(),
                RootServers.ROOT_SERVERS,
                ResolverCacheConfig.defaults(),
                System::nanoTime
        );
    }

    public RecursiveResolver(UpstreamDnsClient client) {
        this(
                client,
                RootServers.ROOT_SERVERS,
                ResolverCacheConfig.defaults(),
                System::nanoTime
        );
    }

    public RecursiveResolver(
            UpstreamDnsClient client,
            List<String> rootServers
    ) {
        this(
                client,
                rootServers,
                ResolverCacheConfig.defaults(),
                System::nanoTime
        );
    }

    public RecursiveResolver(
            UpstreamDnsClient client,
            List<String> rootServers,
            ResolverCacheConfig cacheConfig
    ) {
        this(client, rootServers, cacheConfig, System::nanoTime);
    }

    public RecursiveResolver(
            UpstreamDnsClient client,
            List<String> rootServers,
            ResolverCacheConfig cacheConfig,
            LongSupplier ticker
    ) {
        this(
                client,
                rootServers,
                cacheConfig,
                ticker,
                ResolverObserver.NOOP
        );
    }

    public RecursiveResolver(
            UpstreamDnsClient client,
            List<String> rootServers,
            ResolverCacheConfig cacheConfig,
            LongSupplier ticker,
            ResolverObserver observer
    ) {
        if (client == null || cacheConfig == null || ticker == null
                || observer == null) {
            throw new IllegalArgumentException(
                    "resolver client, cache config, and ticker must not be null"
            );
        }
        if (rootServers == null || rootServers.isEmpty()) {
            throw new IllegalArgumentException(
                    "rootServers must not be empty"
            );
        }

        iterativeResolver = new IterativeResolverEngine(
                client,
                rootServers,
                observer
        );
        cache = new DnsCache(
                cacheConfig.positiveMaxEntries(),
                cacheConfig.positiveMaxTtlSeconds(),
                ticker,
                observer
        );
        negativeCache = new NegativeCache(
                cacheConfig.negativeMaxEntries(),
                cacheConfig.negativeMaxTtlSeconds(),
                ticker,
                observer
        );
    }

    @Override
    public DnsMessage resolve(DnsMessage clientQuery) throws Exception {
        return resolve(clientQuery, DnsResolutionPolicy.ALLOW_ALL);
    }

    @Override
    public DnsMessage resolve(
            DnsMessage clientQuery,
            DnsResolutionPolicy policy
    ) throws Exception {
        DnsResolutionPolicyEnforcer.requireOriginalQuestionAllowed(
                clientQuery,
                policy
        );
        DnsQuestion question = clientQuery.questions().get(0);

        NegativeCacheEntry negative = negativeCache.get(
                question,
                NegativeCacheType.NXDOMAIN
        );
        if (negative == null) {
            negative = negativeCache.get(
                    question,
                    NegativeCacheType.NODATA
            );
        }
        if (negative != null) {
            DnsResolutionPolicyEnforcer.requireCnameTargetsAllowed(
                    negative.response(),
                    question,
                    policy
            );
            return ResolverResponseFactory.fromUpstream(
                    clientQuery,
                    negative.response()
            );
        }

        CachedDnsData cached = cache.get(question);
        if (cached != null) {
            DnsMessage cachedResponse = ResolverResponseFactory.create(
                    clientQuery,
                    cached
            );
            DnsResolutionPolicyEnforcer.requireCnameTargetsAllowed(
                    cachedResponse,
                    question,
                    policy
            );
            return cachedResponse;
        }

        DnsMessage upstreamResponse = iterativeResolver.resolve(
                question,
                policy
        );
        DnsResolutionPolicyEnforcer.requireCnameTargetsAllowed(
                upstreamResponse,
                question,
                policy
        );

        int rcode = upstreamResponse.header().flags() & RCODE_MASK;
        if (rcode == 3) {
            if (upstreamResponse.answers().isEmpty()
                    && findSoaRecord(upstreamResponse) != null) {
                synchronized (cacheMutationLock) {
                    cache.invalidateName(question);
                    negativeCache.invalidateName(question);
                    negativeCache.put(
                            question,
                            NegativeCacheType.NXDOMAIN,
                            upstreamResponse
                    );
                }
            }
            return ResolverResponseFactory.fromUpstream(
                    clientQuery,
                    upstreamResponse
            );
        }

        if (rcode == 0 && upstreamResponse.answers().isEmpty()) {
            if (findSoaRecord(upstreamResponse) != null) {
                synchronized (cacheMutationLock) {
                    cache.invalidate(question);
                    negativeCache.invalidate(
                            question,
                            NegativeCacheType.NXDOMAIN
                    );
                    negativeCache.put(
                            question,
                            NegativeCacheType.NODATA,
                            upstreamResponse
                    );
                }
            }
            return ResolverResponseFactory.fromUpstream(
                    clientQuery,
                    upstreamResponse
            );
        }

        if (rcode == 0 && !upstreamResponse.answers().isEmpty()) {
            synchronized (cacheMutationLock) {
                negativeCache.invalidate(
                        question,
                        NegativeCacheType.NXDOMAIN
                );
                negativeCache.invalidate(
                        question,
                        NegativeCacheType.NODATA
                );
                cache.put(question, upstreamResponse);
            }
            return ResolverResponseFactory.fromUpstream(
                    clientQuery,
                    upstreamResponse
            );
        }

        throw new UpstreamDnsException(
                "Resolution completed without a usable answer"
        );
    }

    private DnsRecord findSoaRecord(DnsMessage response) {
        for (DnsRecord record : response.authorities()) {
            if (record.type() == TYPE_SOA) {
                return record;
            }
        }
        return null;
    }
}
