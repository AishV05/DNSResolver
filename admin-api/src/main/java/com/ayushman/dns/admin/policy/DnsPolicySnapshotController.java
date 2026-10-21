package com.ayushman.dns.admin.policy;

import java.util.Arrays;

import com.ayushman.dns.policy.DnsPolicySnapshot;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Machine-facing policy distribution endpoint. Its representation is stable
 * for one global revision and supports conditional polling with a strong ETag.
 */
@RestController
@RequestMapping("/api/v1/internal/policy-snapshot")
class DnsPolicySnapshotController {

    private final DnsPolicySnapshotService snapshotService;

    DnsPolicySnapshotController(DnsPolicySnapshotService snapshotService) {
        this.snapshotService = snapshotService;
    }

    @GetMapping
    ResponseEntity<DnsPolicySnapshot> currentSnapshot(
            @RequestHeader(
                    name = HttpHeaders.IF_NONE_MATCH,
                    required = false
            ) String ifNoneMatch
    ) {
        DnsPolicySnapshot snapshot = snapshotService.currentSnapshot();
        String etag = etag(snapshot);

        HttpHeaders headers = new HttpHeaders();
        headers.setETag(etag);
        headers.setCacheControl(CacheControl.noCache().cachePrivate());

        if (matches(ifNoneMatch, etag)) {
            return new ResponseEntity<>(headers, HttpStatus.NOT_MODIFIED);
        }
        return new ResponseEntity<>(snapshot, headers, HttpStatus.OK);
    }

    private String etag(DnsPolicySnapshot snapshot) {
        return "\"policy-v"
                + snapshot.schemaVersion()
                + "-r"
                + snapshot.revision()
                + "\"";
    }

    private boolean matches(String ifNoneMatch, String currentEtag) {
        if (ifNoneMatch == null || ifNoneMatch.isBlank()) {
            return false;
        }
        return Arrays.stream(ifNoneMatch.split(","))
                .map(String::trim)
                .anyMatch(candidate -> {
                    if ("*".equals(candidate)) {
                        return true;
                    }
                    String comparable = candidate.startsWith("W/")
                            ? candidate.substring(2).trim()
                            : candidate;
                    return currentEtag.equals(comparable);
                });
    }
}
