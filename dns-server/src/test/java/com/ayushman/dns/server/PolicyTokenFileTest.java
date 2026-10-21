package com.ayushman.dns.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class PolicyTokenFileTest {

    @TempDir
    private Path temporaryDirectory;

    @Test
    void readsAnExactBoundedBearerToken() throws Exception {
        String token = "abcdefghijklmnopqrstuvwxyz-ABCDEFG_1234567890";
        Path file = temporaryDirectory.resolve("token");
        Files.writeString(file, token);

        assertEquals(token, PolicyTokenFile.read(file));
    }

    @Test
    void rejectsWhitespaceShortTokensAndSymlinks() throws Exception {
        Path newline = temporaryDirectory.resolve("newline");
        Files.writeString(
                newline,
                "abcdefghijklmnopqrstuvwxyz-ABCDEFG_1234567890\n"
        );
        assertThrows(IOException.class, () -> PolicyTokenFile.read(newline));

        Path shortToken = temporaryDirectory.resolve("short");
        Files.writeString(shortToken, "too-short");
        assertThrows(
                IOException.class,
                () -> PolicyTokenFile.read(shortToken)
        );

        Path paddingOnly = temporaryDirectory.resolve("padding-only");
        Files.writeString(paddingOnly, "=".repeat(32));
        assertThrows(
                IOException.class,
                () -> PolicyTokenFile.read(paddingOnly)
        );

        Path target = temporaryDirectory.resolve("target");
        Files.writeString(
                target,
                "abcdefghijklmnopqrstuvwxyz-ABCDEFG_1234567890"
        );
        Path link = temporaryDirectory.resolve("link");
        Files.createSymbolicLink(link, target);
        assertThrows(IOException.class, () -> PolicyTokenFile.read(link));
    }
}
