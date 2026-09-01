# Platform Architecture

The platform separates the DNS data plane from the operational entry points.

```text
DNS clients
    |
    v
dns-server  --->  dns-core  --->  authoritative DNS servers
    |
    +-- admission control, configuration, health, metrics

integration-tests
    +-- exercises dns-server and dns-core together over loopback sockets
```

`dns-core` owns DNS names, messages, cache entries, recursive resolution, and
upstream transport. It must not depend on `dns-server`, a web framework, a
database, or a deployment tool. `dns-server` owns process lifecycle and UDP
transport and depends on `dns-core`.

Week 10 adds `admin-api` as a separate management-plane module. It may use
core-level management interfaces but must not be on the UDP query path.
