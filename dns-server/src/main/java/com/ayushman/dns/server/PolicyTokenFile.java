package com.ayushman.dns.server;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;

/** Reads a bounded RFC 6750-compatible opaque token without trimming it. */
final class PolicyTokenFile {

    private static final int MINIMUM_TOKEN_LENGTH = 32;
    private static final int MAXIMUM_TOKEN_LENGTH = 512;

    private PolicyTokenFile() {
    }

    static String read(Path path) throws IOException {
        if (path == null || !path.isAbsolute()) {
            throw new IllegalArgumentException(
                    "policy token file must be an absolute path"
            );
        }

        BasicFileAttributes attributes = Files.readAttributes(
                path,
                BasicFileAttributes.class,
                LinkOption.NOFOLLOW_LINKS
        );
        if (!attributes.isRegularFile()) {
            throw new IOException(
                    "policy token path must be a regular, non-symlink file"
            );
        }
        if (attributes.size() < MINIMUM_TOKEN_LENGTH
                || attributes.size() > MAXIMUM_TOKEN_LENGTH) {
            throw new IOException(
                    "policy token file must contain 32 to 512 bytes"
            );
        }

        byte[] bytes;
        try (InputStream input = Files.newInputStream(path)) {
            bytes = input.readNBytes(MAXIMUM_TOKEN_LENGTH + 1);
        }
        if (bytes.length < MINIMUM_TOKEN_LENGTH
                || bytes.length > MAXIMUM_TOKEN_LENGTH) {
            throw new IOException(
                    "policy token file must contain 32 to 512 bytes"
            );
        }

        String token = decodeUtf8(bytes);
        if (token.length() < MINIMUM_TOKEN_LENGTH
                || token.length() > MAXIMUM_TOKEN_LENGTH
                || !isBearerToken(token)) {
            throw new IOException(
                    "policy token file contains an invalid Bearer token"
            );
        }
        return token;
    }

    private static String decodeUtf8(byte[] bytes) throws IOException {
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes))
                    .toString();
        } catch (CharacterCodingException invalidUtf8) {
            throw new IOException(
                    "policy token file must contain valid UTF-8",
                    invalidUtf8
            );
        }
    }

    private static boolean isBearerToken(String token) {
        boolean paddingStarted = false;
        boolean tokenCharacterSeen = false;
        for (int index = 0; index < token.length(); index++) {
            char character = token.charAt(index);
            if (character == '=') {
                paddingStarted = true;
                continue;
            }
            if (paddingStarted || !isTokenCharacter(character)) {
                return false;
            }
            tokenCharacterSeen = true;
        }
        return tokenCharacterSeen;
    }

    private static boolean isTokenCharacter(char character) {
        return character >= 'a' && character <= 'z'
                || character >= 'A' && character <= 'Z'
                || character >= '0' && character <= '9'
                || character == '-'
                || character == '.'
                || character == '_'
                || character == '~'
                || character == '+'
                || character == '/';
    }
}
