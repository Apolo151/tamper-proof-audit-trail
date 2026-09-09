# syntax=docker/dockerfile:1

# ---- build stage -----------------------------------------------------------
# Pinned major.minor; CI always resolves the latest patch so Go stdlib CVEs
# stay fixed.
FROM golang:1.27-bookworm AS build

WORKDIR /src

# Cache module downloads separately from the source tree. There are currently
# no third-party dependencies, but this keeps the layering correct if that
# changes.
COPY go.mod ./
RUN go mod download

COPY . .

# - CGO disabled  -> a fully static binary that runs on distroless/static
# - -trimpath     -> strip local filesystem paths from the binary (build flag,
#                    NOT an ldflag) for reproducibility
# - -w -s         -> drop DWARF + symbol table: smaller image, less to fingerprint
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-w -s" -o /out/auditd ./cmd/auditd

# Pre-create the data directory owned by the non-root runtime UID. distroless
# has no shell, so we cannot mkdir/chown at runtime.
RUN mkdir -p /out/data && chown 65532:65532 /out/data

# ---- runtime stage -------------------------------------------------------
# distroless/static:nonroot -> no shell, no package manager, no libc, runs as
# uid/gid 65532. Minimal attack surface for a Trivy image scan.
FROM gcr.io/distroless/static:nonroot

COPY --from=build /out/auditd /auditd
COPY --from=build --chown=65532:65532 /out/data /data

USER 65532:65532
ENV DATA_DIR=/data \
    PORT=8080 \
    LOG_LEVEL=info
EXPOSE 8080
VOLUME ["/data"]

# The binary probes itself (exec form, no shell). Kubernetes uses its own
# HTTP probes instead - see deploy/k8s/deployment.yaml.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/auditd", "-healthcheck"]

ENTRYPOINT ["/auditd"]
