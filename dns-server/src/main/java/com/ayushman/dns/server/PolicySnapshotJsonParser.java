package com.ayushman.dns.server;

import java.io.IOException;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;

import com.ayushman.dns.policy.DnsPolicyAction;
import com.ayushman.dns.policy.DnsPolicyMatchType;
import com.ayushman.dns.policy.DnsPolicyRule;
import com.ayushman.dns.policy.DnsPolicySnapshot;
import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.core.StreamReadFeature;

/** Strict, bounded parser for the version-one policy snapshot contract. */
final class PolicySnapshotJsonParser {

    private static final JsonFactory JSON_FACTORY = JsonFactory.builder()
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .streamReadConstraints(StreamReadConstraints.builder()
                    .maxNestingDepth(8)
                    .maxStringLength(1_024)
                    .maxNumberLength(20)
                    .build())
            .build();

    private PolicySnapshotJsonParser() {
    }

    static DnsPolicySnapshot parse(byte[] body, int maxRules)
            throws IOException {
        if (body == null) {
            throw new IllegalArgumentException(
                    "policy snapshot body must not be null"
            );
        }
        if (maxRules <= 0) {
            throw new IllegalArgumentException("maxRules must be positive");
        }

        try (JsonParser parser = JSON_FACTORY.createParser(body)) {
            requireToken(parser.nextToken(), JsonToken.START_OBJECT, "root");

            Integer schemaVersion = null;
            Long revision = null;
            Instant publishedAt = null;
            List<DnsPolicyRule> rules = null;

            while (parser.nextToken() != JsonToken.END_OBJECT) {
                requireToken(
                        parser.currentToken(),
                        JsonToken.FIELD_NAME,
                        "root field"
                );
                String field = parser.currentName();
                JsonToken valueToken = parser.nextToken();
                switch (field) {
                    case "schemaVersion" ->
                            schemaVersion = readInteger(
                                    parser,
                                    valueToken,
                                    field
                            );
                    case "revision" ->
                            revision = readLong(parser, valueToken, field);
                    case "publishedAt" ->
                            publishedAt = readInstant(
                                    parser,
                                    valueToken,
                                    field
                            );
                    case "rules" ->
                            rules = readRules(parser, valueToken, maxRules);
                    default -> throw invalid(
                            "unknown policy snapshot field: " + field
                    );
                }
            }

            if (parser.nextToken() != null) {
                throw invalid("policy snapshot contains trailing JSON data");
            }
            if (schemaVersion == null
                    || revision == null
                    || publishedAt == null
                    || rules == null) {
                throw invalid("policy snapshot is missing a required field");
            }

            return new DnsPolicySnapshot(
                    schemaVersion,
                    revision,
                    publishedAt,
                    rules
            );
        }
    }

    private static List<DnsPolicyRule> readRules(
            JsonParser parser,
            JsonToken token,
            int maxRules
    ) throws IOException {
        requireToken(token, JsonToken.START_ARRAY, "rules");
        List<DnsPolicyRule> rules = new ArrayList<>();
        while (parser.nextToken() != JsonToken.END_ARRAY) {
            if (rules.size() >= maxRules) {
                throw invalid("policy snapshot exceeds the rule limit");
            }
            rules.add(readRule(parser));
        }
        return rules;
    }

    private static DnsPolicyRule readRule(JsonParser parser)
            throws IOException {
        requireToken(parser.currentToken(), JsonToken.START_OBJECT, "rule");

        String domainName = null;
        DnsPolicyMatchType matchType = null;
        DnsPolicyAction action = null;

        while (parser.nextToken() != JsonToken.END_OBJECT) {
            requireToken(
                    parser.currentToken(),
                    JsonToken.FIELD_NAME,
                    "rule field"
            );
            String field = parser.currentName();
            JsonToken valueToken = parser.nextToken();
            switch (field) {
                case "domainName" ->
                        domainName = readString(parser, valueToken, field);
                case "matchType" -> matchType = readMatchType(
                        readString(parser, valueToken, field)
                );
                case "action" -> action = readAction(
                        readString(parser, valueToken, field)
                );
                default -> throw invalid(
                        "unknown policy rule field: " + field
                );
            }
        }

        if (domainName == null || matchType == null || action == null) {
            throw invalid("policy rule is missing a required field");
        }
        try {
            return new DnsPolicyRule(domainName, matchType, action);
        } catch (RuntimeException invalidRule) {
            throw invalid("policy rule is invalid", invalidRule);
        }
    }

    private static int readInteger(
            JsonParser parser,
            JsonToken token,
            String field
    ) throws IOException {
        requireToken(token, JsonToken.VALUE_NUMBER_INT, field);
        try {
            return parser.getIntValue();
        } catch (RuntimeException invalidNumber) {
            throw invalid(field + " must be a 32-bit integer", invalidNumber);
        }
    }

    private static long readLong(
            JsonParser parser,
            JsonToken token,
            String field
    ) throws IOException {
        requireToken(token, JsonToken.VALUE_NUMBER_INT, field);
        try {
            return parser.getLongValue();
        } catch (RuntimeException invalidNumber) {
            throw invalid(field + " must be a 64-bit integer", invalidNumber);
        }
    }

    private static Instant readInstant(
            JsonParser parser,
            JsonToken token,
            String field
    ) throws IOException {
        String value = readString(parser, token, field);
        try {
            return Instant.parse(value);
        } catch (DateTimeParseException invalidInstant) {
            throw invalid(field + " must be an ISO-8601 instant", invalidInstant);
        }
    }

    private static String readString(
            JsonParser parser,
            JsonToken token,
            String field
    ) throws IOException {
        requireToken(token, JsonToken.VALUE_STRING, field);
        return parser.getText();
    }

    private static DnsPolicyMatchType readMatchType(String value)
            throws IOException {
        try {
            return DnsPolicyMatchType.valueOf(value);
        } catch (IllegalArgumentException invalidValue) {
            throw invalid("unsupported policy match type", invalidValue);
        }
    }

    private static DnsPolicyAction readAction(String value)
            throws IOException {
        try {
            return DnsPolicyAction.valueOf(value);
        } catch (IllegalArgumentException invalidValue) {
            throw invalid("unsupported policy action", invalidValue);
        }
    }

    private static void requireToken(
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
