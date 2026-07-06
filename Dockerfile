FROM rustlang/rust:nightly-bookworm AS chef
RUN cargo install cargo-chef
WORKDIR /app

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
RUN apt-get update && apt-get install -y \
    llvm-dev \
    libclang-dev \
    clang \
    pkg-config \
    libelf-dev \
    wget \
    && rm -rf /var/lib/apt/lists/*

RUN rustup component add rust-src

RUN cargo install bpf-linker

COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

COPY . .
RUN cargo build --release


FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    iptables \
    libelf1 \
    ca-certificates \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/configuration /configuration
COPY --from=builder /app/target/release/xdp-natd /usr/local/bin/xdp-natd

ENV RUST_LOG=info
ENV APP_ENVIRONMENT=local

ENTRYPOINT ["/usr/local/bin/xdp-natd"]

LABEL description="docker run -d --name xdp-natd --privileged --network host --pid host -v /var/run/docker.sock:/var/run/docker.sock -v /sys/fs/bpf:/sys/fs/bpf -v /lib/modules:/lib/modules:ro xdp-natd:latest"
