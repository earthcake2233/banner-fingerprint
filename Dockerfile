# syntax=docker/dockerfile:1.7
#
# Multi-stage build:
#   build  - compiles fully static binaries from *vendored* dependencies, so the
#            image build needs no network access to the Go module proxy
#   test   - `docker build --target test .` runs go vet + the unit tests
#   runtime- minimal image, non-root, no compiler, no package manager
#
# The same image carries both programs: docker compose picks the binary per
# service via entrypoint/command, so server and client can never drift apart.

ARG GO_VERSION=1.26

# ---------------------------------------------------------------- build stage
FROM golang:${GO_VERSION}-alpine AS build

WORKDIR /src
ARG VERSION=docker
ENV CGO_ENABLED=0 \
    GOOS=linux \
    GOFLAGS=-mod=vendor \
    GOTOOLCHAIN=local

COPY go.mod go.sum ./
COPY vendor/ ./vendor/
COPY cmd/ ./cmd/
COPY internal/ ./internal/

RUN go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" \
        -o /out/fingerprint-server ./cmd/server \
 && go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" \
        -o /out/fingerprint-client ./cmd/client \
 && ls -l /out

# ----------------------------------------------------------------- test stage
FROM build AS test
# The tests assert that the shipped rules file, its embedded fallback copy and
# the sample data stay in sync, so those two directories have to be present.
COPY rules/ ./rules/
COPY samples/ ./samples/
RUN go vet ./... && go test ./...

# -------------------------------------------------------------- runtime stage
FROM alpine:3.21 AS runtime

RUN addgroup -g 65532 -S app \
 && adduser -u 65532 -S -G app -h /app -s /sbin/nologin app

WORKDIR /app
COPY --from=build /out/fingerprint-server /app/fingerprint-server
COPY --from=build /out/fingerprint-client /app/fingerprint-client
# Rules ship inside the image AND can be overridden by a read-only bind mount
# (see compose.yaml) - detection knowledge is data, not code.
COPY rules/ /etc/fingerprint/

USER 65532:65532
EXPOSE 8080

# The binary probes its own /health endpoint: no curl/wget needed in the image.
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/app/fingerprint-server", "-healthcheck", "http://127.0.0.1:8080/health"]

ENTRYPOINT ["/app/fingerprint-server"]
