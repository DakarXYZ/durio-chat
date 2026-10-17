# Build Stage
ARG BASE_IMAGE=ghcr.io/stoatchat/base:latest
FROM ${BASE_IMAGE} AS builder
FROM debian:13 AS debian

# Bundle Stage
FROM gcr.io/distroless/cc-debian13:nonroot
COPY --from=builder /home/rust/src/target/release/revolt-bonfire ./
COPY --from=builder /home/rust/src/target/release/healthcheck /usr/local/bin/healthcheck
COPY --from=debian /usr/bin/uname /usr/bin/uname

EXPOSE 14703
USER nonroot
CMD ["./revolt-bonfire"]
