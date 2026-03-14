package com.ayushman.dns.cache;

import java.util.concurrent.ConcurrentHashMap;

import com.ayushman.dns.protocol.DnsMessage;
import com.ayushman.dns.protocol.DnsQuestion;

public class DnsCache{
    private final ConcurrentHashMap<String, CacheEntry> cache = new ConcurrentHashMap<>();
    private String key(DnsQuestion question){
        return question.name() + ":" + question.type();
    }

    public DnsMessage get(DnsQuestion question){
        CacheEntry entry = cache.get(key(question));

        if(entry == null){
            return null;
        }
        if(entry.isExpired()){
            cache.remove(key(question));
            return null;
        }
        return entry.response();
    }

    public void put(DnsQuestion question, DnsMessage response, long ttl){
        cache.put(key(question), new CacheEntry(response, ttl));
    }

}