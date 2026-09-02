FROM maven:3.9.11-eclipse-temurin-17 AS build

WORKDIR /build
COPY pom.xml ./
COPY dns-core/pom.xml ./dns-core/pom.xml
COPY dns-server/pom.xml ./dns-server/pom.xml
COPY admin-api/pom.xml ./admin-api/pom.xml
COPY integration-tests/pom.xml ./integration-tests/pom.xml
RUN mvn -q -pl dns-server -am -DskipTests dependency:go-offline
COPY dns-core/src ./dns-core/src
COPY dns-server/src ./dns-server/src
RUN mvn -q -pl dns-server -am -DskipTests package

FROM eclipse-temurin:17-jre-jammy

RUN groupadd --system dns && useradd --system --gid dns --home /app dns
WORKDIR /app
COPY --from=build --chown=dns:dns /build/dns-server/target/dns-server-1.0-SNAPSHOT.jar ./dns-resolver.jar

USER dns
EXPOSE 5354/udp

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD java -cp /app/dns-resolver.jar com.ayushman.dns.server.HealthCheck ${DNS_HEALTH_PORT:-8080}

ENTRYPOINT ["java", "-jar", "/app/dns-resolver.jar"]
