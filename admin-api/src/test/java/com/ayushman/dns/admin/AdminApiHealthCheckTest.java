package com.ayushman.dns.admin;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AdminApiHealthCheckTest {

    @Test
    void reportsHealthyForAnOkActuatorResponse() {
        assertTrue(AdminApiHealthCheck.isHealthyResponseCode(200));
    }

    @Test
    void reportsUnhealthyForNonOkActuatorResponses() {
        assertFalse(AdminApiHealthCheck.isHealthyResponseCode(503));
        assertFalse(AdminApiHealthCheck.isHealthyResponseCode(401));
    }
}
