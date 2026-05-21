FROM debian:bookworm-slim

WORKDIR /data

COPY evaluate_tcp_throughput.sh evaluate_udp_throughput.sh \
evaluate_latency.sh exec_order.txt  ./
RUN chmod +x evaluate_latency.sh evaluate_tcp_throughput.sh \
evaluate_udp_throughput.sh

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      ca-certificates git cmake build-essential pkg-config \
      libfftw3-dev libmbedtls-dev libboost-program-options-dev \
      libconfig++-dev libsctp-dev libyaml-cpp-dev libgtest-dev \
      iproute2 iputils-ping libzmq3-dev jq wget ethtool \
      autoconf automake libtool && \
    rm -rf /var/lib/apt/lists/*

RUN wget https://github.com/esnet/iperf/releases/download/3.21/iperf-3.21.tar.gz && \
    tar -xzf iperf-3.21.tar.gz -C /opt && \
    cd /opt/iperf-3.21 && \
    ./configure && \
    make -j$(nproc) && \
    make install && \
    ldconfig && \
    cd /opt && rm -rf iperf-3.21*

RUN git clone https://github.com/mellanox/sockperf.git /opt/sockperf && \
    cd /opt/sockperf && \
    git checkout 3c65ad99cd38 && \
    ./autogen.sh && \
    ./configure && \
    make -j$(nproc) && \
    make install && \
    ldconfig && \
    cd /opt && rm -rf sockperf

CMD ["bash"]
