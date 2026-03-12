package com.ayushman.dns.protocol;
import java.util.ArrayList;
import java.util.List;


public class DnsPacketParser{

    public static DnsMessage parse(byte[] packet){
        ByteReader reader = new ByteReader(packet);

        DnsHeader header = new DnsHeader(
            reader.readU16(),
            reader.readU16(),
            reader.readU16(),
            reader.readU16(),
            reader.readU16(), 
            reader.readU16()
        );


        List<DnsQuestion> questions = new ArrayList<>();

        for(int i = 0;i< header.qdCount();i++){
            String name = DnsNameCodec.decode(reader, packet);
            int type = reader.readU16();
            int qclass = reader.readU16();

            questions.add(new DnsQuestion(name,type,qclass));
        }

    return new DnsMessage(header, questions, List.of());
    }
}
