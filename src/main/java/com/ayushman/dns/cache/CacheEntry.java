package com.ayushman.dns.cache;
import com.ayushman.dns.protocol.DnsMessage;

public class CacheEntry {
    private final DnsMessage response;
    private final long expiryTime;

    public CacheEntry(DnsMessage response, long ttlSeconds) {
        this.response = response;
        this.expiryTime = System.currentTimeMillis() + (ttlSeconds * 1000);
    }
    public boolean isExpired(){
        return System.currentTimeMillis() > expiryTime;
    }
    public DnsMessage response(){
        return response;
    }

    
}