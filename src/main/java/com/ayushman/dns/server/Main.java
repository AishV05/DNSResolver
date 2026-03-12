package com.ayushman.dns.server;
public class Main {
    public static void main(String[] args) throws Exception{
        int port = 5354;

        UdpDnsServer server = new UdpDnsServer(port);
        server.start();

    }
}
