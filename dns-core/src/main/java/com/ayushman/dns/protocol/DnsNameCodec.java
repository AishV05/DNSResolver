package com.ayushman.dns.protocol;

import java.nio.ByteBuffer;

public final class DnsNameCodec {

    private DnsNameCodec() {
    }

    public static String decode(
            ByteReader reader,
            byte[] packet
    ) {

        StringBuilder name =
                new StringBuilder();

        boolean jumped = false;
        int returnPosition = -1;

        while (true) {

            int currentPosition =
                    reader.position();

            int len =
                    packet[currentPosition] & 0xFF;

            if ((len & 0xC0) == 0xC0) {

                int pointer =
                        ((len & 0x3F) << 8)
                                | (packet[currentPosition + 1] & 0xFF);

                if (!jumped) {

                    returnPosition =
                            currentPosition + 2;

                    jumped = true;
                }

                reader.position(pointer);

                continue;
            }

            reader.position(
                    currentPosition + 1
            );

            if (len == 0) {
                break;
            }

            if (name.length() > 0) {
                name.append('.');
            }

            for (int i = 0; i < len; i++) {

                int position =
                        reader.position();

                name.append(
                        (char) (
                                packet[position]
                                        & 0xFF
                        )
                );

                reader.position(
                        position + 1
                );
            }
        }

        if (jumped) {
            reader.position(returnPosition);
        }

        return name.toString();
    }

    public static void encode(
            String name,
            ByteBuffer buffer
    ) {

        if (name == null || name.isEmpty()) {
            buffer.put((byte) 0);
            return;
        }

        String[] labels =
                name.split("\\.");

        for (String label : labels) {

            buffer.put(
                    (byte) label.length()
            );

            for (char c :
                    label.toCharArray()) {

                buffer.put(
                        (byte) c
                );
            }
        }

        buffer.put((byte) 0);
    }
}