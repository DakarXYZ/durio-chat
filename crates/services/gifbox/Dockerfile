# Build Stage
ARG BASE_IMAGE=ghcr.io/stoatchat/base:latest
FROM ${BASE_IMAGE} AS builder

# Bundle Stage
FROM gcr.io/distroless/cc-debian13:nonroot
COPY --from=builder /home/rust/src/target/release/revolt-gifbox ./
COPY --from=builder /home/rust/src/target/release/healthcheck /usr/local/bin/healthcheck

EXPOSE 14706
USER nonroot
CMD ["./revolt-gifbox"]
