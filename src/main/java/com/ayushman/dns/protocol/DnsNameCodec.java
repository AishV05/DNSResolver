package com.ayushman.dns.protocol;

import java.nio.ByteBuffer;

public final class DnsNameCodec{
    private DnsNameCodec(){}

    public static String decode(ByteReader reader, byte[] packet){
        StringBuilder name = new StringBuilder();
        int originalPos = reader.position();
        boolean jumped = false;
     
        while(true){
            int len = packet[reader.position()] & 0xFF;

            if((len & 0xC0) == 0xC0){
                int pointer = ((len & 0x3F) << 8) | (packet[reader.position() + 1] & 0xFF);
                if(!jumped){
                    reader.position(reader.position() + 2);
                }
                reader.position(pointer);
                jumped = true;
                continue;
            }
            reader.position(reader.position() + 1);

            if(len == 0){
                break;
            }
            if(name.length() > 0){
                name.append('.');
            }
            for(int i = 0;i< len;i++){
                int currentPos = reader.position();
                name.append((char) (packet[currentPos] & 0xFF));
                reader.position(currentPos + 1);
            }

        }
        if (jumped) {
        reader.position(originalPos + 2);
    }

        return name.toString();
    }

    public static void encode(String name, ByteBuffer buffer){
        String[] labels = name.split("\\.");

        for(String label: labels){
            buffer.put((byte)label.length());
            for(char c:label.toCharArray()){
                buffer.put((byte)c);
            }
        }
        buffer.put((byte)0);
    }


}