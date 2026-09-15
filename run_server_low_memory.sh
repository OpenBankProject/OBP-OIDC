#!/bin/bash

# Copyright (c) 2025 TESOBE
#
# This file is part of OBP-OIDC.
#
# OBP-OIDC is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# OBP-OIDC is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with OBP-OIDC. If not, see <http://www.gnu.org/licenses/>.

# OBP-OIDC Low Memory Server Runner
#
# Same as run-server.sh, but sizes the JVM for an OIDC provider instead of
# letting it size itself for the whole machine. With no flags the JVM picks
# max heap = 1/4 of system RAM, one GC thread per core and one cats-effect
# compute thread per core, which is how a ~55MB live set becomes ~380MB RSS.
#
# Measured baseline (16-core / 62GB host, plain `java -jar`):
#   RSS 391MB = 90MB heap committed (54MB live) + 69MB metaspace
#             + 22MB code cache + 54 threads + G1 structures sized for a
#               15.9GB heap reservation
#
# Usage:
#   ./run_server_low_memory.sh                      # tuned defaults below
#   OIDC_MAX_HEAP=512m ./run_server_low_memory.sh   # override any single knob
#   JAVA_OPTS="..." ./run_server_low_memory.sh      # replace the set entirely
#   OIDC_AOT_TRAIN=true ./run_server_low_memory.sh  # record an AOT cache, then exit
#
# All other behaviour (.env loading, JAR check, shutdown handling) is
# inherited from run-server.sh, which this script delegates to.

set -e

cd "$(dirname "$0")"

# ---------------------------------------------------------------------------
# Tunables - override any of these from the environment
# ---------------------------------------------------------------------------
OIDC_MAX_HEAP="${OIDC_MAX_HEAP:-256m}"          # live set measured at ~54MB
OIDC_MIN_HEAP="${OIDC_MIN_HEAP:-64m}"
OIDC_MAX_METASPACE="${OIDC_MAX_METASPACE:-192m}" # ~11k classes load at ~69MB
OIDC_CODE_CACHE="${OIDC_CODE_CACHE:-96m}"        # ~22MB actually used
OIDC_DIRECT_MEM="${OIDC_DIRECT_MEM:-64m}"        # ember/NIO buffers
OIDC_THREAD_STACK="${OIDC_THREAD_STACK:-512k}"
OIDC_CPU_COUNT="${OIDC_CPU_COUNT:-4}"            # caps GC *and* io-compute pool
OIDC_AOT_CACHE="${OIDC_AOT_CACHE:-target/obp-oidc.aot}"

JAR_FILE="target/obp-oidc-1.0.0-SNAPSHOT.jar"

# ---------------------------------------------------------------------------
# Build the flag set (unless the caller supplied a complete JAVA_OPTS)
# ---------------------------------------------------------------------------
if [ -z "$JAVA_OPTS" ]; then
    JAVA_OPTS="-Xms${OIDC_MIN_HEAP} -Xmx${OIDC_MAX_HEAP}"

    # SerialGC: on a <=256MB heap this removes ~17 GC threads plus G1's
    # per-thread remembered-set and PLAB machinery. Pauses stay in the low
    # milliseconds at this heap size.
    JAVA_OPTS="$JAVA_OPTS -XX:+UseSerialGC"

    # 12 -> 8 byte object headers (product flag in JDK 24+). Scala allocates
    # many small objects, so this pays well. Skipped on older JDKs.
    if java -XX:+UseCompactObjectHeaders -version >/dev/null 2>&1; then
        JAVA_OPTS="$JAVA_OPTS -XX:+UseCompactObjectHeaders"
    fi

    JAVA_OPTS="$JAVA_OPTS -XX:MaxMetaspaceSize=${OIDC_MAX_METASPACE}"
    JAVA_OPTS="$JAVA_OPTS -XX:ReservedCodeCacheSize=${OIDC_CODE_CACHE}"
    JAVA_OPTS="$JAVA_OPTS -XX:MaxDirectMemorySize=${OIDC_DIRECT_MEM}"
    JAVA_OPTS="$JAVA_OPTS -Xss${OIDC_THREAD_STACK}"

    # Caps GC threads AND the cats-effect compute pool, which otherwise sizes
    # itself to availableProcessors (16 io-compute threads on this host).
    # NOTE: this is also a concurrency ceiling - raise OIDC_CPU_COUNT if the
    # server is CPU-bound rather than memory-bound.
    JAVA_OPTS="$JAVA_OPTS -XX:ActiveProcessorCount=${OIDC_CPU_COUNT}"

    # Fail fast rather than thrash if the smaller heap ever proves too small.
    JAVA_OPTS="$JAVA_OPTS -XX:+ExitOnOutOfMemoryError"
fi

# glibc keeps up to 8 malloc arenas per core; 2 is plenty for this workload.
export MALLOC_ARENA_MAX="${MALLOC_ARENA_MAX:-2}"

# ---------------------------------------------------------------------------
# Optional AOT cache (JDK 24+): moves class metadata into a read-only mapped
# file, cutting anonymous metaspace RSS and startup time.
# ---------------------------------------------------------------------------
if [ "$OIDC_AOT_TRAIN" = "true" ]; then
    echo "Recording AOT cache to $OIDC_AOT_CACHE"
    echo "Let the server start fully, then stop it with Ctrl+C so the cache is written."
    echo ""
    if [ ! -f "$JAR_FILE" ]; then
        echo "Error: JAR not found at $JAR_FILE - run 'mvn package -DskipTests' first"
        exit 1
    fi
    [ -f ".env" ] && set -a && . ./.env && set +a
    exec java -XX:AOTCacheOutput="$OIDC_AOT_CACHE" $JAVA_OPTS -jar "$JAR_FILE"
fi

if [ -f "$OIDC_AOT_CACHE" ]; then
    JAVA_OPTS="-XX:AOTMode=auto -XX:AOTCache=$OIDC_AOT_CACHE $JAVA_OPTS"
    AOT_STATUS="enabled ($OIDC_AOT_CACHE)"
else
    AOT_STATUS="not present - create with OIDC_AOT_TRAIN=true $0"
fi

echo "OBP-OIDC - Low Memory Mode"
echo "=========================="
echo "  JVM flags:  $JAVA_OPTS"
echo "  Malloc arenas: $MALLOC_ARENA_MAX"
echo "  AOT cache:  $AOT_STATUS"
echo ""
echo "  Expected RSS ~150-200MB (vs ~380MB unflagged)."
echo "  Check it once warm with:  ps -o rss= -p \$(pgrep -f obp-oidc-1.0.0-SNAPSHOT.jar)"
echo ""

export JAVA_OPTS
exec ./run-server.sh
