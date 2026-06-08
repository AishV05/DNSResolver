package com.ayushman.dns.resolver;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;

import com.ayushman.dns.protocol.DnsMessage;
import com.ayushman.dns.protocol.DnsPacketParser;
import com.ayushman.dns.protocol.DnsPacketWriter;


public class UpstreamDnsClient{
    public DnsMessage query(String serverIp, DnsMessage query) throws Exception{
        byte[] request = DnsPacketWriter.buildResponse(query);
        DatagramPacket responsePacket;
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setSoTimeout(2000);
            InetAddress serverAddress = InetAddress.getByName(serverIp);
            DatagramPacket packet = new DatagramPacket(
                    request, request.length, serverAddress, 53);
            socket.send(packet);
            byte[] buffer = new byte[512];
            responsePacket = new DatagramPacket(buffer, buffer.length);
            socket.receive(responsePacket);
        }

        byte[] responseData = new byte[responsePacket.getLength()];

        System.arraycopy(responsePacket.getData(), 0, responseData, 0, responsePacket.getLength());

        return DnsPacketParser.parse(responseData);
    }
}