package com.ayushman.dns.admin.fleet;

import com.ayushman.dns.fleet.ResolverSessionLease;

record ResolverSessionStartResult(
        ResolverSessionLease lease,
        boolean created
) {
}
