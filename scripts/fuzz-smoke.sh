#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
REPOSITORY_ROOT="$(CDPATH= cd -- "${SCRIPT_DIR}/.." && pwd)"

cd "${REPOSITORY_ROOT}"

./mvnw -B -ntp -pl dns-core test-compile \
    dependency:build-classpath \
    -Dmdep.includeScope=test \
    -Dmdep.outputFile=target/fuzz-classpath.txt

if [[ -n "${JAVA_HOME:-}" && -x "${JAVA_HOME}/bin/java" ]]; then
    JAVA_COMMAND="${JAVA_HOME}/bin/java"
else
    JAVA_COMMAND="$(command -v java)"
fi

FUZZ_CLASSPATH="dns-core/target/test-classes:dns-core/target/classes:$(<dns-core/target/fuzz-classpath.txt)"
FUZZ_WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/dns-wire-fuzz.XXXXXX")"

cleanup() {
    if [[ -n "${FUZZ_WORK_DIR:-}" && -d "${FUZZ_WORK_DIR}" ]]; then
        rm -rf -- "${FUZZ_WORK_DIR}"
    fi
}
trap cleanup EXIT

cp dns-core/src/test/resources/fuzz-corpus/dns-packet/* "${FUZZ_WORK_DIR}/"
mkdir -p dns-core/target/jazzer-artifacts

"${JAVA_COMMAND}" \
    -Djdk.attach.allowAttachSelf=true \
    -cp "${FUZZ_CLASSPATH}" \
    com.code_intelligence.jazzer.Jazzer \
    --target_class=com.ayushman.dns.protocol.DnsPacketFuzzTarget \
    -max_total_time=10 \
    -rss_limit_mb=1024 \
    -verbosity=0 \
    -artifact_prefix=dns-core/target/jazzer-artifacts/ \
    "${FUZZ_WORK_DIR}"
