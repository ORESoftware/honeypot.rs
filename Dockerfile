# syntax=docker/dockerfile:1.7
FROM docker.io/library/rust:1.88.0-alpine3.22 AS builder
WORKDIR /src
RUN apk add --no-cache musl-dev
COPY Cargo.toml rust-toolchain.toml build.rs ./
COPY src ./src
RUN cargo generate-lockfile && cargo build --release --locked

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /src/target/release/honeypot-rs /usr/local/bin/honeypot-rs
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/honeypot-rs"]
