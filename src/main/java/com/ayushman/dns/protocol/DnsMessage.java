package com.ayushman.dns.protocol;

import java.util.List;
import java.util.Optional;

public class DnsMessage {

    private final DnsHeader header;

    private final List<DnsQuestion> questions;

    private final List<DnsRecord> answers;

    private final List<DnsRecord> authorities;

    private final List<DnsRecord> additionals;

    private final EdnsInfo edns;

    public DnsMessage(
            DnsHeader header,
            List<DnsQuestion> questions,
            List<DnsRecord> answers,
            List<DnsRecord> authorities,
            List<DnsRecord> additionals
    ) {
        this(
                header,
                questions,
                answers,
                authorities,
                additionals,
                null
        );
    }

    public DnsMessage(
            DnsHeader header,
            List<DnsQuestion> questions,
            List<DnsRecord> answers,
            List<DnsRecord> authorities,
            List<DnsRecord> additionals,
            EdnsInfo edns
    ) {
        this.header = header;
        this.questions = questions;
        this.answers = answers;
        this.authorities = authorities;
        this.additionals = additionals;
        this.edns = edns;
    }

    public DnsHeader header() {
        return header;
    }

    public List<DnsQuestion> questions() {
        return questions;
    }

    public List<DnsRecord> answers() {
        return answers;
    }

    public List<DnsRecord> authorities() {
        return authorities;
    }

    public List<DnsRecord> additionals() {
        return additionals;
    }

    public Optional<EdnsInfo> edns() {
        return Optional.ofNullable(edns);
    }
}
