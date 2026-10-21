ARG APP_VERSION=0.1.0-SNAPSHOT
ARG VCS_REF=unknown
ARG BUILD_DATE=1970-01-01T00:00:00Z
ARG SOURCE_URL=https://github.com/AishV05/DNSResolver

FROM maven:3.9.11-eclipse-temurin-17@sha256:e4a7ace3dc0d645ed97f8d9ad0b0d3f0b14fa8d150138f27f116d7105a639b82 AS build

ARG APP_VERSION

WORKDIR /build
COPY pom.xml ./
COPY dns-core/pom.xml ./dns-core/pom.xml
COPY dns-server/pom.xml ./dns-server/pom.xml
COPY admin-api/pom.xml ./admin-api/pom.xml
COPY integration-tests/pom.xml ./integration-tests/pom.xml
RUN --mount=type=cache,id=dns-platform-maven,target=/root/.m2,sharing=locked \
    mvn -B -ntp -pl dns-server -am -Drevision="${APP_VERSION}" \
        -DskipTests dependency:go-offline
COPY dns-core/src ./dns-core/src
COPY dns-server/src ./dns-server/src
RUN --mount=type=cache,id=dns-platform-maven,target=/root/.m2,sharing=locked \
    mvn -B -ntp -pl dns-server -am -Drevision="${APP_VERSION}" \
        -DskipTests package

FROM eclipse-temurin:17-jre-jammy@sha256:ec72ba5962b45ae4e7f96bfb5ebf6eeb34a488b967f937c8e14f0aaec688954f

ARG APP_VERSION
ARG VCS_REF
ARG BUILD_DATE
ARG SOURCE_URL

LABEL org.opencontainers.image.title="DNS Resolver" \
      org.opencontainers.image.source="${SOURCE_URL}" \
      org.opencontainers.image.version="${APP_VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}"

RUN groupadd --system dns && useradd --system --gid dns --home /app dns
WORKDIR /app
COPY --from=build --chown=dns:dns \
    /build/dns-server/target/dns-server-*.jar /tmp/dns-artifacts/
RUN set -eux; \
    set -- /tmp/dns-artifacts/dns-server-*.jar; \
    test "$#" -eq 1; \
    mv "$1" /app/dns-resolver.jar; \
    rmdir /tmp/dns-artifacts

USER dns
EXPOSE 5354/udp 5354/tcp

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD java -cp /app/dns-resolver.jar com.ayushman.dns.server.HealthCheck ${DNS_HEALTH_PORT:-8080}

ENTRYPOINT ["java", "-jar", "/app/dns-resolver.jar"]
