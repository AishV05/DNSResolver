package com.ayushman.dns.admin.metrics;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.List;

import com.ayushman.dns.admin.fleet.ResolverFleetStatusResponse;
import com.ayushman.dns.admin.fleet.ResolverFleetStatusService;
import com.ayushman.dns.admin.fleet.ResolverSessionRetentionService;
import com.ayushman.dns.admin.fleet.ResolverSessionRetentionSnapshot;
import com.ayushman.dns.fleet.ResolverFleetPolicyState;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

class ResolverFleetPrometheusControllerTest {

    @Test
    void evaluatesOneSnapshotPerScrapeAndDisablesCaching() {
        ResolverFleetStatusService service = mock(ResolverFleetStatusService.class);
        ResolverSessionRetentionService retentionService = mock(
                ResolverSessionRetentionService.class
        );
        ResolverFleetStatusResponse status = new ResolverFleetStatusResponse(
                1,
                Instant.EPOCH,
                120_000,
                0,
                0,
                0,
                ResolverFleetPolicyState.DATA_PLANE_UNOBSERVED,
                0,
                0,
                0,
                0,
                List.of()
        );
        when(service.currentStatus()).thenReturn(status);
        when(retentionService.currentSnapshot()).thenReturn(retention());
        ResolverFleetPrometheusController controller =
                new ResolverFleetPrometheusController(service, retentionService);

        ResponseEntity<String> response = controller.metrics();

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getHeaders().getContentType()).isEqualTo(
                ResolverFleetPrometheusController.PROMETHEUS_TEXT_FORMAT
        );
        assertThat(response.getHeaders().getCacheControl()).isEqualTo("no-store");
        assertThat(response.getBody()).contains(
                "dns_admin_fleet_policy_state{state=\"unobserved\"} 1"
        );
        verify(service).currentStatus();
        verify(retentionService).currentSnapshot();
        verifyNoMoreInteractions(service);
        verifyNoMoreInteractions(retentionService);
    }

    private ResolverSessionRetentionSnapshot retention() {
        return new ResolverSessionRetentionSnapshot(
                0, 0, 0, 0, 2_592_000_000L,
                1, 0, 0, 1_794_659_696_000L, 0, false
        );
    }
}
