package com.ayushman.dns.server;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.UUID;

import com.ayushman.dns.fleet.ResolverRuntimeReport;
import com.ayushman.dns.fleet.ResolverSessionLease;
import com.ayushman.dns.fleet.ResolverSessionStart;
import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.core.StreamReadFeature;

/** Strict JSON codec for the version-one resolver fleet protocol. */
final class ResolverFleetJsonCodec {

    private static final JsonFactory JSON_FACTORY = JsonFactory.builder()
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .streamReadConstraints(StreamReadConstraints.builder()
                    .maxNestingDepth(4)
                    .maxStringLength(128)
                    .maxNumberLength(20)
                    .build())
            .build();

    private ResolverFleetJsonCodec() {
    }

    static byte[] writeSessionStart(ResolverSessionStart start)
            throws IOException {
        if (start == null) {
            throw new IllegalArgumentException(
                    "resolver session start must not be null"
            );
        }
        ByteArrayOutputStream output = new ByteArrayOutputStream(192);
        try (JsonGenerator generator = JSON_FACTORY.createGenerator(output)) {
            generator.writeStartObject();
            generator.writeNumberField("schemaVersion", start.schemaVersion());
            generator.writeStringField("bootId", start.bootId().toString());
            generator.writeStringField(
                    "applicationVersion",
                    start.applicationVersion()
            );
            generator.writeEndObject();
        }
        return output.toByteArray();
    }

    static byte[] writeRuntimeReport(ResolverRuntimeReport report)
            throws IOException {
        if (report == null) {
            throw new IllegalArgumentException(
                    "resolver runtime report must not be null"
            );
        }
        ByteArrayOutputStream output = new ByteArrayOutputStream(384);
        try (JsonGenerator generator = JSON_FACTORY.createGenerator(output)) {
            generator.writeStartObject();
            generator.writeNumberField("schemaVersion", report.schemaVersion());
            generator.writeStringField("sessionId", report.sessionId().toString());
            generator.writeStringField("bootId", report.bootId().toString());
            generator.writeNumberField(
                    "sessionGeneration",
                    report.sessionGeneration()
            );
            generator.writeNumberField("sequence", report.sequence());
            generator.writeStringField(
                    "applicationVersion",
                    report.applicationVersion()
            );
            generator.writeStringField(
                    "policyMode",
                    report.policyMode().name()
            );
            generator.writeBooleanField(
                    "policySnapshotLoaded",
                    report.policySnapshotLoaded()
            );
            generator.writeNumberField(
                    "policyRevision",
                    report.policyRevision()
            );
            generator.writeNumberField(
                    "policyRuleCount",
                    report.policyRuleCount()
            );
            generator.writeBooleanField("policyReady", report.policyReady());
            generator.writeStringField(
                    "policySyncState",
                    report.policySyncState().name()
            );
            generator.writeEndObject();
        }
        return output.toByteArray();
    }

    static ResolverSessionLease readSessionLease(byte[] body)
            throws IOException {
        if (body == null) {
            throw new IllegalArgumentException(
                    "resolver session lease body must not be null"
            );
        }

        try (JsonParser parser = JSON_FACTORY.createParser(body)) {
            require(parser.nextToken(), JsonToken.START_OBJECT, "lease root");
            Integer schemaVersion = null;
            String resolverId = null;
            UUID sessionId = null;
            UUID bootId = null;
            Long generation = null;

            while (parser.nextToken() != JsonToken.END_OBJECT) {
                require(
                        parser.currentToken(),
                        JsonToken.FIELD_NAME,
                        "lease field"
                );
                String field = parser.currentName();
                JsonToken value = parser.nextToken();
                switch (field) {
                    case "schemaVersion" -> {
                        require(value, JsonToken.VALUE_NUMBER_INT, field);
                        schemaVersion = parser.getIntValue();
                    }
                    case "resolverId" ->
                            resolverId = readString(parser, value, field);
                    case "sessionId" -> sessionId = readUuid(
                            readString(parser, value, field),
                            field
                    );
                    case "bootId" -> bootId = readUuid(
                            readString(parser, value, field),
                            field
                    );
                    case "sessionGeneration" -> {
                        require(value, JsonToken.VALUE_NUMBER_INT, field);
                        generation = parser.getLongValue();
                    }
                    default -> throw invalid(
                            "unknown resolver session lease field: " + field
                    );
                }
            }
            if (parser.nextToken() != null) {
                throw invalid("resolver session lease has trailing JSON data");
            }
            if (schemaVersion == null
                    || resolverId == null
                    || sessionId == null
                    || bootId == null
                    || generation == null) {
                throw invalid("resolver session lease is missing a field");
            }
            try {
                return new ResolverSessionLease(
                        schemaVersion,
                        resolverId,
                        sessionId,
                        bootId,
                        generation
                );
            } catch (RuntimeException invalidLease) {
                throw invalid("resolver session lease is invalid", invalidLease);
            }
        }
    }

    private static String readString(
            JsonParser parser,
            JsonToken token,
            String field
    ) throws IOException {
        require(token, JsonToken.VALUE_STRING, field);
        return parser.getText();
    }

    private static UUID readUuid(String value, String field)
            throws IOException {
        try {
            return UUID.fromString(value);
        } catch (IllegalArgumentException invalidUuid) {
            throw invalid(field + " must be a UUID", invalidUuid);
        }
    }

    private static void require(
            JsonToken actual,
            JsonToken expected,
            String context
    ) throws IOException {
        if (actual != expected) {
            throw invalid(context + " has an invalid JSON type");
        }
    }

    private static IOException invalid(String message) {
        return new IOException(message);
    }

    private static IOException invalid(String message, Throwable cause) {
        return new IOException(message, cause);
    }
}
