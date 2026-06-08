package com.ayushman.dns.resolver;

import java.util.List;

import com.ayushman.dns.protocol.DnsMessage;
import com.ayushman.dns.protocol.DnsRecord;

public class RecursiveResolver{
    private final UpstreamDnsClient client = new UpstreamDnsClient();
    public DnsMessage resolve(DnsMessage query) throws Exception{
        String currentServer = RootServers.ROOT_SERVERS.get(0);

        while (true) { 
            System.out.println("Querying Server: " + currentServer);
            DnsMessage response = client.query(currentServer, query);

            if(!response.answers().isEmpty()){
                return response;
            }
            List<DnsRecord> authority = response.answers();
            if(authority.isEmpty()){
                throw new RuntimeException("No answer found");
            } 
        }
    }
}