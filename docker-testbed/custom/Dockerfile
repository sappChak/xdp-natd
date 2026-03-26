FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    # Core Networking
    iproute2 \
    net-tools \
    iputils-ping \
    ethtool \
    # dnsutils for UDP testing
    dnsutils \
    # Traffic Generation & Data Parsing
    iperf3 \
    hping3 \
    jq \
    # Latency & Bufferbloat Analysis
    sockperf \
    flent \
    # Packet Capture
    tcpdump \
    tshark \
    # XDP / eBPF Development Tools
    bpftool \
    linux-perf \
    clang \
    llvm \
    libelf-dev \
    # System Stress
    stress-ng \
    # Python support for Flent/Plotting
    python3 \
    python3-pip \
    python3-matplotlib \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /data

COPY evaluate_network.sh .
COPY evaluate_latency.sh .
COPY evaluate_throughput.sh .

RUN chmod +x evaluate_network.sh
RUN chmod +x evaluate_latency.sh
RUN chmod +x evaluate_throughput.sh


CMD ["bash"]
