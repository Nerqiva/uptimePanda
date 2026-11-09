# syntax=docker/dockerfile:1

###############################################################################
# uptimePanda — multi-stage build
#
#   builder : rust:slim (latest stable toolchain) -> release binary, native glibc
#   runtime : debian:stable-slim (glibc-dynamic Lightpanda host; Alpine/musl is
#             ruled out by docs/phase0-validation.md — the Lightpanda binary is
#             not static and upstream ships debian:stable-slim)
#
# Multi-arch: build with docker buildx (`--platform linux/amd64,linux/arm64`).
# TARGETARCH selects the matching Lightpanda release asset; the Rust binary
# compiles natively for the target platform (QEMU), never via cross-targets.
#
# Lightpanda is resolved to the LATEST release at image build time (GitHub
# API) and SHA-256 verified (fail-closed). Escape hatch: pin LIGHTPANDA_VERSION
# + the matching LIGHTPANDA_SHA256_* args (see the fetch layer below).
###############################################################################

FROM rust:slim AS builder

# rust:slim ships only a minimal Debian; rusqlite (bundled) needs a C toolchain.
# No OpenSSL/TLS build deps are required: the crate tree contains no openssl,
# native-tls, rustls, or reqwest (verified against Cargo.lock).
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential pkg-config ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Dependency layer: cached until the manifests change.
# Cargo parses the manifest to resolve deps and requires a target to exist,
# so prime with a dummy main.rs before fetching (real sources overwrite it).
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && printf 'fn main() {}\n' > src/main.rs && cargo fetch --locked && rm -rf src

# Sources (Askama templates and VERSION are embedded at compile time).
COPY src/ src/
COPY templates/ templates/
COPY public/ public/
COPY VERSION ./

RUN cargo build --release --locked -j"$(nproc)"

###############################################################################

FROM debian:stable-slim

# BuildKit predefines TARGETARCH (amd64|arm64). Empty under classic
# `docker build` -> fall back to the build host's dpkg architecture.
ARG TARGETARCH

# Escape hatch (latest-at-build-time policy, plan §0.9): leave LIGHTPANDA_VERSION
# empty to resolve the latest release from the GitHub API at build time.
# When set, LIGHTPANDA_SHA256_X86_64 / LIGHTPANDA_SHA256_AARCH64 become
# MANDATORY and the build fails without them (fail-closed). Pin args accept a
# bare 64-char hex digest (case-insensitive; normalized to lowercase).
ARG LIGHTPANDA_VERSION=
ARG LIGHTPANDA_SHA256_X86_64=
ARG LIGHTPANDA_SHA256_AARCH64=

# Optional source revision stamped into the image labels (CI passes it).
ARG GITHUB_SHA=

# curl is kept in the final image on purpose (decision, documented in the
# README/report): the HEALTHCHECK below uses it, and it is handy for operators.
# ca-certificates is required — Lightpanda makes outbound TLS connections to
# the monitored sites. tzdata for Asia/Omsk (UTC+6) and timezone-aware logs.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates tzdata curl \
 && rm -rf /var/lib/apt/lists/*

# --- Lightpanda: latest release at build time, SHA-256 verified (fail-closed) --
RUN set -eu; \
    LP_VERSION="${LIGHTPANDA_VERSION:-}"; \
    LP_SHA_X86_64="${LIGHTPANDA_SHA256_X86_64:-}"; \
    LP_SHA_AARCH64="${LIGHTPANDA_SHA256_AARCH64:-}"; \
    ARCH="${TARGETARCH:-$(dpkg --print-architecture)}"; \
    case "$ARCH" in \
      amd64) LP_ARCH=x86_64 ;; \
      arm64) LP_ARCH=aarch64 ;; \
      *) echo "error: unsupported TARGETARCH '$ARCH' (expected amd64 or arm64)" >&2; exit 1 ;; \
    esac; \
    ASSET="lightpanda-${LP_ARCH}-linux"; \
    if [ -n "$LP_VERSION" ]; then \
      TAG="$LP_VERSION"; \
      case "$ARCH" in \
        amd64) PIN_SHA256="$LP_SHA_X86_64" ;; \
        arm64) PIN_SHA256="$LP_SHA_AARCH64" ;; \
      esac; \
      if [ -z "$PIN_SHA256" ]; then \
        echo "error: LIGHTPANDA_VERSION='${TAG}' is pinned but its SHA-256 is missing." >&2; \
        echo "       set LIGHTPANDA_SHA256_X86_64 and LIGHTPANDA_SHA256_AARCH64 (both, for multi-arch builds)." >&2; \
        exit 1; \
      fi; \
      DIGEST=$(printf '%s' "$PIN_SHA256" | tr 'A-F' 'a-f'); \
    else \
      echo "LIGHTPANDA_VERSION not set; resolving latest release from the GitHub API..."; \
      curl -fsSL https://api.github.com/repos/lightpanda-io/browser/releases/latest -o /tmp/rel.json; \
      TAG=$(sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' /tmp/rel.json | head -1); \
      if [ -z "$TAG" ]; then \
        echo "error: could not parse tag_name from the GitHub release metadata" >&2; exit 1; \
      fi; \
      DIGEST=$(awk -v name="$ASSET" '$0 ~ "\"name\": *\""name"\"" {f=1} f && /"digest"/ {match($0,/sha256:[0-9a-f]+/); print substr($0,RSTART+7,64); exit}' /tmp/rel.json); \
    fi; \
    case "$DIGEST" in \
      *[!0-9a-f]*|'') echo "error: no valid sha256 digest resolved for ${ASSET} (got '${DIGEST}')" >&2; exit 1 ;; \
    esac; \
    if [ "${#DIGEST}" -ne 64 ]; then \
      echo "error: digest for ${ASSET} is ${#DIGEST} hex chars, expected 64" >&2; exit 1; \
    fi; \
    URL="https://github.com/lightpanda-io/browser/releases/download/${TAG}/${ASSET}"; \
    echo "downloading ${URL}"; \
    curl -fSL --retry 3 --retry-delay 5 --connect-timeout 15 -o /tmp/lightpanda "$URL"; \
    echo "${DIGEST}  /tmp/lightpanda" | sha256sum -c -; \
    install -m 0755 /tmp/lightpanda /usr/local/bin/lightpanda; \
    mkdir -p /usr/local/share/uptimepanda; \
    printf '%s\n' "$TAG" > /usr/local/share/uptimepanda/lightpanda-version; \
    rm -f /tmp/lightpanda /tmp/rel.json; \
    echo "installed lightpanda ${TAG} (${LP_ARCH}), sha256 ${DIGEST}"

# Non-root runtime user; /app doubles as home and data root (VOLUME below).
RUN useradd --uid 10001 --create-home --home-dir /app --shell /usr/sbin/nologin uptimepanda

WORKDIR /app

COPY --from=builder /build/target/release/uptimepanda /app/uptimepanda
COPY public/ /app/public/
RUN mkdir -p /app/data/backups \
 && chown -R uptimepanda:uptimepanda /app

VOLUME /app/data
EXPOSE 8080

# LIGHTPANDA_VERSION: when the escape-hatch ARG is used it carries the pinned
# tag; in the default (latest-at-build-time) build it reports "latest" and the
# exact resolved tag is persisted in /usr/local/share/uptimepanda/lightpanda-version
# (Docker cannot promote a RUN-computed value into ENV). Build logs and
# `lightpanda version` inside the container are authoritative.
ENV PORT=8080 \
    BIND_ADDR=0.0.0.0 \
    DATABASE_PATH=/app/data/uptimepanda.db \
    BACKUP_DIR=/app/data/backups \
    TZ=Asia/Omsk \
    LIGHTPANDA_CDP_PORT=9222 \
    RUST_LOG=info \
    LIGHTPANDA_DISABLE_TELEMETRY=true \
    LIGHTPANDA_VERSION=${LIGHTPANDA_VERSION:-latest} \
    LIGHTPANDA_VERSION_FILE=/usr/local/share/uptimepanda/lightpanda-version

LABEL org.opencontainers.image.source="https://github.com/Nerqiva/uptimePanda" \
      org.opencontainers.image.title="uptimePanda" \
      org.opencontainers.image.description="Rust + Lightpanda lightweight synthetic website monitor (512MB/0.15 vCPU target)" \
      org.opencontainers.image.revision="${GITHUB_SHA:-unknown}"

USER uptimepanda

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8080/health || exit 1

ENTRYPOINT ["/app/uptimepanda"]
