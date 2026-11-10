package com.ayushman.dns.resolver;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import com.ayushman.dns.policy.DnsResolutionPolicy;
import com.ayushman.dns.protocol.DnsHeader;
import com.ayushman.dns.protocol.DnsMessage;
import com.ayushman.dns.protocol.DnsQuestion;
import com.ayushman.dns.protocol.DnsRecord;

/**
 * Performs one cache-independent iterative resolution transaction.
 *
 * <p>All traversal state is request-local. A response is returned only after
 * its answer, referral, or negative proof has been related to the question
 * that caused the exchange.</p>
 */
final class IterativeResolverEngine {

    private static final int TYPE_A = 1;
    private static final int TYPE_NS = 2;
    private static final int TYPE_CNAME = 5;
    private static final int TYPE_SOA = 6;
    private static final int TYPE_AAAA = 28;
    private static final int TYPE_IXFR = 251;
    private static final int TYPE_AXFR = 252;
    private static final int TYPE_ANY = 255;
    private static final int CLASS_IN = 1;

    private static final int FLAG_QR = 0x8000;
    private static final int FLAG_AA = 0x0400;
    private static final int FLAG_TC = 0x0200;
    private static final int OPCODE_MASK = 0x7800;
    private static final int RCODE_MASK = 0x000F;

    private static final int MAX_REFERRAL_DEPTH = 16;
    private static final int MAX_CNAME_HOPS = 16;
    private static final int MAX_UPSTREAM_EXCHANGES = 64;
    private static final int MAX_NS_TARGETS = 16;
    private static final int MAX_ADDRESSES_PER_NS = 8;
    private static final int MAX_CANDIDATE_ADDRESSES = 32;
    private static final int MAX_NS_ADDRESS_LOOKUPS = 16;

    private final UpstreamDnsClient client;
    private final List<String> rootServers;
    private final ResolverObserver observer;
    private final ResolverDnsName rootZone = ResolverDnsName.from("");

    private enum ResolutionPurpose {
        CLIENT_ANSWER,
        NAMESERVER_INFRASTRUCTURE
    }

    IterativeResolverEngine(
            UpstreamDnsClient client,
            List<String> rootServers
    ) {
        this(client, rootServers, ResolverObserver.NOOP);
    }

    IterativeResolverEngine(
            UpstreamDnsClient client,
            List<String> rootServers,
            ResolverObserver observer
    ) {
        if (client == null || rootServers == null || rootServers.isEmpty()
                || observer == null) {
            throw new IllegalArgumentException(
                    "resolver engine dependencies must not be null or empty"
            );
        }
        this.client = client;
        this.rootServers = List.copyOf(rootServers);
        this.observer = observer;
    }

    DnsMessage resolve(DnsQuestion question) throws Exception {
        return resolve(question, DnsResolutionPolicy.ALLOW_ALL);
    }

    DnsMessage resolve(
            DnsQuestion question,
            DnsResolutionPolicy policy
    ) throws Exception {
        if (question == null || policy == null) {
            throw new IllegalArgumentException(
                    "question and policy must not be null"
            );
        }
        if (question.qclass() != CLASS_IN
                || question.type() == TYPE_IXFR
                || question.type() == TYPE_AXFR) {
            throw failure("Unsupported recursive DNS question");
        }

        ResolutionContext context = new ResolutionContext(policy);
        LinkedHashSet<ResolverDnsName> aliases = new LinkedHashSet<>();
        aliases.add(nameOf(question.name(), "question"));

        return resolveFromRoots(
                question,
                context,
                aliases,
                ResolutionPurpose.CLIENT_ANSWER
        );
    }

    private DnsMessage resolveFromRoots(
            DnsQuestion question,
            ResolutionContext context,
            LinkedHashSet<ResolverDnsName> aliases,
            ResolutionPurpose purpose
    ) throws Exception {
        return resolveAtZone(
                question,
                rootZone,
                rootServers,
                0,
                context,
                aliases,
                purpose
        );
    }

    private DnsMessage resolveAtZone(
            DnsQuestion question,
            ResolverDnsName currentZone,
            List<String> servers,
            int referralDepth,
            ResolutionContext context,
            LinkedHashSet<ResolverDnsName> aliases,
            ResolutionPurpose purpose
    ) throws Exception {
        if (referralDepth > MAX_REFERRAL_DEPTH) {
            throw failure("Referral depth limit exceeded");
        }

        UpstreamDnsException lastFailure = null;

        for (String server : servers) {
            if (lastFailure != null) {
                observer.nameserverFailover();
            }
            try {
                LinkedHashSet<ResolverDnsName> branchAliases =
                        new LinkedHashSet<>(aliases);
                context.consumeExchange();
                DnsMessage response = client.query(
                        server,
                        ResolverQueryFactory.create(question)
                );

                validateEnvelope(question, response);
                return classifyResponse(
                        question,
                        currentZone,
                        response,
                        referralDepth,
                        context,
                        branchAliases,
                        purpose
                );
            } catch (UpstreamDnsException candidateFailure) {
                lastFailure = candidateFailure;
            }
        }

        throw new UpstreamDnsException(
                "No eligible nameserver produced a valid response for "
                        + question.name(),
                lastFailure
        );
    }

    private DnsMessage classifyResponse(
            DnsQuestion question,
            ResolverDnsName currentZone,
            DnsMessage response,
            int referralDepth,
            ResolutionContext context,
            LinkedHashSet<ResolverDnsName> aliases,
            ResolutionPurpose purpose
    ) throws Exception {
        int rcode = response.header().flags() & RCODE_MASK;

        if (rcode == 3) {
            return authoritativeNegative(
                    question,
                    currentZone,
                    response
            );
        }

        if (rcode != 0) {
            throw failure("Unsupported upstream response code " + rcode);
        }

        DnsMessage positive = relevantPositiveAnswer(
                question,
                currentZone,
                response,
                context,
                aliases,
                purpose
        );
        if (positive != null) {
            return positive;
        }

        Delegation delegation = extractDelegation(
                question,
                currentZone,
                response
        );
        if (delegation != null) {
            return followDelegation(
                    question,
                    response,
                    delegation,
                    referralDepth,
                    context,
                    aliases,
                    purpose
            );
        }

        DnsRecord soa = relevantSoa(question, currentZone, response);
        if (isAuthoritative(response) && soa != null) {
            return sanitized(
                    question,
                    response.header().flags(),
                    List.of(),
                    List.of(soa)
            );
        }

        throw failure(
                "Upstream response contained no relevant answer, negative proof, or referral"
        );
    }

    private DnsMessage relevantPositiveAnswer(
            DnsQuestion question,
            ResolverDnsName currentZone,
            DnsMessage response,
            ResolutionContext context,
            LinkedHashSet<ResolverDnsName> aliases,
            ResolutionPurpose purpose
    ) throws Exception {
        ResolverDnsName currentName = nameOf(question.name(), "question");
        String currentPresentation = question.name();
        List<DnsRecord> accepted = new ArrayList<>();

        while (true) {
            List<DnsRecord> terminal = terminalRecords(
                    response.answers(),
                    currentName,
                    question.type(),
                    question.qclass()
            );

            List<DnsRecord> cnames = recordsAtOwner(
                    response.answers(),
                    currentName,
                    TYPE_CNAME,
                    question.qclass()
            );

            boolean cnameConflict = !cnames.isEmpty()
                    && terminal.stream()
                            .anyMatch(record -> record.type() != TYPE_CNAME);
            if (cnameConflict) {
                throw failure(
                        "A DNS owner cannot contain both CNAME and terminal data"
                );
            }

            if (question.type() == TYPE_ANY && !terminal.isEmpty()) {
                requireAuthoritative(response);
                requireCnameTargetAllowed(
                        cnames,
                        question,
                        context,
                        purpose
                );
                accepted.addAll(terminal);
                return sanitized(
                        question,
                        response.header().flags(),
                        accepted,
                        List.of()
                );
            }

            if (question.type() == TYPE_CNAME && !cnames.isEmpty()) {
                requireAuthoritative(response);
                requireCnameTargetAllowed(
                        cnames,
                        question,
                        context,
                        purpose
                );
                accepted.addAll(cnames);
                return sanitized(
                        question,
                        response.header().flags(),
                        accepted,
                        List.of()
                );
            }

            if (!terminal.isEmpty()) {
                requireAuthoritative(response);
                accepted.addAll(terminal);
                return sanitized(
                        question,
                        response.header().flags(),
                        accepted,
                        List.of()
                );
            }

            if (cnames.isEmpty()) {
                if (accepted.isEmpty()) {
                    return null;
                }

                DnsQuestion targetQuestion = new DnsQuestion(
                        currentPresentation,
                        question.type(),
                        question.qclass()
                );
                DnsMessage targetResponse = resolveFromRoots(
                        targetQuestion,
                        context,
                        aliases,
                        purpose
                );

                List<DnsRecord> combined = new ArrayList<>(accepted);
                combined.addAll(targetResponse.answers());
                return sanitized(
                        question,
                        targetResponse.header().flags(),
                        combined,
                        targetResponse.authorities()
                );
            }

            requireAuthoritative(response);
            CnameTarget target = requireSingleCnameTarget(cnames);
            requireCnameTargetAllowed(
                    target,
                    question,
                    context,
                    purpose
            );
            context.consumeCnameHop();

            if (!aliases.add(target.name())) {
                observer.cnameLoopRejected();
                throw failure("CNAME loop detected");
            }

            accepted.addAll(cnames);
            currentName = target.name();
            currentPresentation = target.presentation();

            if (!currentName.isAtOrBelow(currentZone)
                    || !containsOwner(response.answers(), currentName)) {
                DnsQuestion targetQuestion = new DnsQuestion(
                        target.presentation(),
                        question.type(),
                        question.qclass()
                );
                DnsMessage targetResponse = resolveFromRoots(
                        targetQuestion,
                        context,
                        aliases,
                        purpose
                );

                List<DnsRecord> combined = new ArrayList<>(accepted);
                combined.addAll(targetResponse.answers());
                return sanitized(
                        question,
                        targetResponse.header().flags(),
                        combined,
                        targetResponse.authorities()
                );
            }
        }
    }

    private DnsMessage authoritativeNegative(
            DnsQuestion question,
            ResolverDnsName currentZone,
            DnsMessage response
    ) throws UpstreamDnsException {
        requireAuthoritative(response);

        if (!response.answers().isEmpty()) {
            throw failure(
                    "NXDOMAIN response unexpectedly contained answer records"
            );
        }

        DnsRecord soa = relevantSoa(question, currentZone, response);
        if (soa == null) {
            throw failure(
                    "NXDOMAIN response did not contain a relevant SOA proof"
            );
        }

        return sanitized(
                question,
                response.header().flags(),
                List.of(),
                List.of(soa)
        );
    }

    private Delegation extractDelegation(
            DnsQuestion question,
            ResolverDnsName currentZone,
            DnsMessage response
    ) throws UpstreamDnsException {
        ResolverDnsName questionName = nameOf(question.name(), "question");
        ResolverDnsName selectedZone = null;

        for (DnsRecord record : response.authorities()) {
            if (record.type() != TYPE_NS || record.qclass() != CLASS_IN) {
                continue;
            }

            ResolverDnsName owner = nameOf(record.name(), "NS owner");
            if (!questionName.isAtOrBelow(owner)
                    || !owner.isStrictlyBelow(currentZone)) {
                continue;
            }

            if (selectedZone == null
                    || owner.labelCount() > selectedZone.labelCount()) {
                selectedZone = owner;
            }
        }

        if (selectedZone == null) {
            return null;
        }

        LinkedHashSet<ResolverDnsName> seenTargets = new LinkedHashSet<>();
        List<NameServerTarget> targets = new ArrayList<>();

        for (DnsRecord record : response.authorities()) {
            if (record.type() != TYPE_NS || record.qclass() != CLASS_IN
                    || !nameOf(record.name(), "NS owner").equals(selectedZone)) {
                continue;
            }

            String presentation;
            try {
                presentation = DnsRecordUtil.getDomainName(record);
            } catch (RuntimeException malformedRdata) {
                throw failure("Malformed NS target", malformedRdata);
            }

            if (presentation == null) {
                throw failure("Malformed NS target");
            }

            ResolverDnsName target = nameOf(presentation, "NS target");
            if (seenTargets.add(target)) {
                if (targets.size() >= MAX_NS_TARGETS) {
                    throw failure("Referral contains too many nameserver targets");
                }
                targets.add(new NameServerTarget(presentation, target));
            }
        }

        if (targets.isEmpty()) {
            return null;
        }

        return new Delegation(selectedZone, List.copyOf(targets));
    }

    private DnsMessage followDelegation(
            DnsQuestion question,
            DnsMessage referralResponse,
            Delegation delegation,
            int referralDepth,
            ResolutionContext context,
            LinkedHashSet<ResolverDnsName> aliases,
            ResolutionPurpose purpose
    ) throws Exception {
        if (referralDepth >= MAX_REFERRAL_DEPTH) {
            throw failure("Referral depth limit exceeded");
        }

        int candidateCount = 0;
        UpstreamDnsException lastFailure = null;

        for (NameServerTarget target : delegation.targets()) {
            List<String> addresses;

            if (target.name().isAtOrBelow(delegation.zone())) {
                addresses = linkedGlueAddresses(
                        referralResponse,
                        target.name()
                );
            } else {
                addresses = resolveNameServerAddresses(
                        target,
                        context
                );
            }

            if (addresses.isEmpty()) {
                continue;
            }

            int remaining = MAX_CANDIDATE_ADDRESSES - candidateCount;
            if (remaining <= 0) {
                break;
            }

            List<String> bounded = addresses.subList(
                    0,
                    Math.min(addresses.size(), remaining)
            );
            candidateCount += bounded.size();

            if (lastFailure != null) {
                observer.nameserverFailover();
            }
            try {
                return resolveAtZone(
                        question,
                        delegation.zone(),
                        bounded,
                        referralDepth + 1,
                        context,
                        aliases,
                        purpose
                );
            } catch (UpstreamDnsException branchFailure) {
                lastFailure = branchFailure;
            }
        }

        throw new UpstreamDnsException(
                "Delegation contained no usable nameserver for "
                        + question.name(),
                lastFailure
        );
    }

    private List<String> linkedGlueAddresses(
            DnsMessage response,
            ResolverDnsName target
    ) throws UpstreamDnsException {
        LinkedHashSet<String> addresses = new LinkedHashSet<>();

        for (DnsRecord record : response.additionals()) {
            if (record.qclass() != CLASS_IN
                    || (record.type() != TYPE_A
                    && record.type() != TYPE_AAAA)) {
                continue;
            }
            if (!nameOf(record.name(), "glue owner").equals(target)) {
                continue;
            }

            String address = DnsRecordUtil.getIpAddress(record);
            if (address == null) {
                throw failure("Malformed glue address");
            }

            addresses.add(address);
            if (addresses.size() >= MAX_ADDRESSES_PER_NS) {
                break;
            }
        }

        return List.copyOf(addresses);
    }

    private List<String> resolveNameServerAddresses(
            NameServerTarget target,
            ResolutionContext context
    ) throws Exception {
        context.beginNameServerLookup(target.name());

        try {
            List<String> ipv4 = resolveAddressType(
                    target.presentation(),
                    TYPE_A,
                    context
            );
            if (!ipv4.isEmpty()) {
                return ipv4;
            }

            return resolveAddressType(
                    target.presentation(),
                    TYPE_AAAA,
                    context
            );
        } finally {
            context.endNameServerLookup(target.name());
        }
    }

    private List<String> resolveAddressType(
            String name,
            int type,
            ResolutionContext context
    ) throws Exception {
        DnsQuestion addressQuestion = new DnsQuestion(name, type, CLASS_IN);
        LinkedHashSet<ResolverDnsName> aliases = new LinkedHashSet<>();
        aliases.add(nameOf(name, "nameserver address question"));

        DnsMessage response;
        try {
            response = resolveFromRoots(
                    addressQuestion,
                    context,
                    aliases,
                    ResolutionPurpose.NAMESERVER_INFRASTRUCTURE
            );
        } catch (UpstreamDnsException unavailable) {
            return List.of();
        }

        LinkedHashSet<String> addresses = new LinkedHashSet<>();
        for (DnsRecord answer : response.answers()) {
            if (answer.type() != type || answer.qclass() != CLASS_IN) {
                continue;
            }

            String address = DnsRecordUtil.getIpAddress(answer);
            if (address != null) {
                addresses.add(address);
            }
            if (addresses.size() >= MAX_ADDRESSES_PER_NS) {
                break;
            }
        }
        return List.copyOf(addresses);
    }

    private List<DnsRecord> terminalRecords(
            List<DnsRecord> answers,
            ResolverDnsName owner,
            int requestedType,
            int requestedClass
    ) throws UpstreamDnsException {
        List<DnsRecord> records = new ArrayList<>();

        for (DnsRecord record : answers) {
            if (record.qclass() != requestedClass
                    || !nameOf(record.name(), "answer owner").equals(owner)) {
                continue;
            }

            if (requestedType == TYPE_ANY
                    || record.type() == requestedType) {
                records.add(record);
            }
        }

        return List.copyOf(records);
    }

    private List<DnsRecord> recordsAtOwner(
            List<DnsRecord> records,
            ResolverDnsName owner,
            int type,
            int recordClass
    ) throws UpstreamDnsException {
        List<DnsRecord> matches = new ArrayList<>();

        for (DnsRecord record : records) {
            if (record.type() == type
                    && record.qclass() == recordClass
                    && nameOf(record.name(), "record owner").equals(owner)) {
                matches.add(record);
            }
        }
        return List.copyOf(matches);
    }

    private boolean containsOwner(
            List<DnsRecord> records,
            ResolverDnsName owner
    ) throws UpstreamDnsException {
        for (DnsRecord record : records) {
            if (nameOf(record.name(), "answer owner").equals(owner)) {
                return true;
            }
        }
        return false;
    }

    private CnameTarget requireSingleCnameTarget(
            List<DnsRecord> cnames
    ) throws UpstreamDnsException {
        CnameTarget selected = null;

        for (DnsRecord cname : cnames) {
            String presentation;
            try {
                presentation = DnsRecordUtil.getDomainName(cname);
            } catch (RuntimeException malformedRdata) {
                throw failure("Malformed CNAME target", malformedRdata);
            }
            if (presentation == null) {
                throw failure("Malformed CNAME target");
            }

            ResolverDnsName name = nameOf(presentation, "CNAME target");
            CnameTarget candidate = new CnameTarget(presentation, name);

            if (selected != null && !selected.name().equals(name)) {
                throw failure("Conflicting CNAME targets for one owner");
            }
            selected = candidate;
        }

        if (selected == null) {
            throw failure("CNAME record set is empty");
        }
        return selected;
    }

    private DnsRecord relevantSoa(
            DnsQuestion question,
            ResolverDnsName currentZone,
            DnsMessage response
    ) throws UpstreamDnsException {
        ResolverDnsName questionName = nameOf(question.name(), "question");
        DnsRecord selected = null;
        int selectedLabels = -1;

        for (DnsRecord record : response.authorities()) {
            if (record.type() != TYPE_SOA
                    || record.qclass() != question.qclass()) {
                continue;
            }

            ResolverDnsName owner = nameOf(record.name(), "SOA owner");
            if (!questionName.isAtOrBelow(owner)
                    || !owner.isAtOrBelow(currentZone)) {
                continue;
            }

            if (owner.labelCount() > selectedLabels) {
                selected = record;
                selectedLabels = owner.labelCount();
            }
        }

        return selected;
    }

    private void validateEnvelope(
            DnsQuestion question,
            DnsMessage response
    ) throws UpstreamDnsException {
        if (response == null) {
            throw failure("Upstream response must not be null");
        }

        int flags = response.header().flags();
        if ((flags & FLAG_QR) == 0
                || (flags & FLAG_TC) != 0
                || (flags & OPCODE_MASK) != 0) {
            throw failure("Upstream response has an invalid header profile");
        }
        if (response.questions().size() != 1) {
            throw failure("Upstream response must echo exactly one question");
        }

        DnsQuestion echoed = response.questions().get(0);
        if (echoed.type() != question.type()
                || echoed.qclass() != question.qclass()
                || !nameOf(echoed.name(), "echoed question").equals(
                nameOf(question.name(), "question")
        )) {
            throw failure("Upstream response question does not match the query");
        }
    }

    private void requireAuthoritative(
            DnsMessage response
    ) throws UpstreamDnsException {
        if (!isAuthoritative(response)) {
            throw failure("Terminal upstream response is not authoritative");
        }
    }

    private boolean isAuthoritative(DnsMessage response) {
        return (response.header().flags() & FLAG_AA) != 0;
    }

    private void requireCnameTargetAllowed(
            List<DnsRecord> cnames,
            DnsQuestion originalQuestion,
            ResolutionContext context,
            ResolutionPurpose purpose
    ) throws Exception {
        if (cnames.isEmpty()) {
            return;
        }
        requireCnameTargetAllowed(
                requireSingleCnameTarget(cnames),
                originalQuestion,
                context,
                purpose
        );
    }

    private void requireCnameTargetAllowed(
            CnameTarget target,
            DnsQuestion originalQuestion,
            ResolutionContext context,
            ResolutionPurpose purpose
    ) throws Exception {
        if (purpose != ResolutionPurpose.CLIENT_ANSWER) {
            return;
        }
        context.policy.requireAllowed(new DnsQuestion(
                target.presentation(),
                originalQuestion.type(),
                originalQuestion.qclass()
        ));
    }

    private ResolverDnsName nameOf(
            String presentation,
            String field
    ) throws UpstreamDnsException {
        try {
            return ResolverDnsName.from(presentation);
        } catch (RuntimeException malformedName) {
            throw failure("Invalid " + field + " name", malformedName);
        }
    }

    private DnsMessage sanitized(
            DnsQuestion question,
            int flags,
            List<DnsRecord> answers,
            List<DnsRecord> authorities
    ) {
        DnsHeader header = new DnsHeader(
                0,
                flags,
                1,
                answers.size(),
                authorities.size(),
                0
        );
        return new DnsMessage(
                header,
                List.of(question),
                answers,
                authorities,
                List.of()
        );
    }

    private UpstreamDnsException failure(String message) {
        return new UpstreamDnsException(message);
    }

    private UpstreamDnsException failure(
            String message,
            Throwable cause
    ) {
        return new UpstreamDnsException(message, cause);
    }

    private record Delegation(
            ResolverDnsName zone,
            List<NameServerTarget> targets
    ) {
    }

    private record NameServerTarget(
            String presentation,
            ResolverDnsName name
    ) {
    }

    private record CnameTarget(
            String presentation,
            ResolverDnsName name
    ) {
    }

    private final class ResolutionContext {
        private final DnsResolutionPolicy policy;
        private int upstreamExchanges;
        private int cnameHops;
        private int nameServerLookups;
        private final Set<ResolverDnsName> activeNameServerLookups =
                new LinkedHashSet<>();

        private ResolutionContext(DnsResolutionPolicy policy) {
            this.policy = policy;
        }

        private void consumeExchange() throws UpstreamDnsException {
            if (upstreamExchanges >= MAX_UPSTREAM_EXCHANGES) {
                throw failure("Upstream exchange limit exceeded");
            }
            upstreamExchanges++;
        }

        private void consumeCnameHop() throws UpstreamDnsException {
            if (cnameHops >= MAX_CNAME_HOPS) {
                observer.cnameLoopRejected();
                throw failure("CNAME hop limit exceeded");
            }
            cnameHops++;
        }

        private void beginNameServerLookup(
                ResolverDnsName name
        ) throws UpstreamDnsException {
            if (nameServerLookups >= MAX_NS_ADDRESS_LOOKUPS) {
                throw failure("Nameserver address lookup limit exceeded");
            }
            if (!activeNameServerLookups.add(name)) {
                throw failure("Nameserver address dependency loop detected");
            }
            nameServerLookups++;
        }

        private void endNameServerLookup(ResolverDnsName name) {
            activeNameServerLookups.remove(name);
        }
    }
}
