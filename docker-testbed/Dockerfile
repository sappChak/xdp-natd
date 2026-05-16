FROM debian:bookworm-slim

WORKDIR /data

COPY evaluate_throughput.sh evaluate_latency.sh exec_order.txt  ./
RUN chmod +x evaluate_latency.sh evaluate_throughput.sh 

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        iproute2 \
        net-tools \
        iputils-ping \
        ethtool \
        dnsutils \
        iperf3 \
        hping3 \
        jq \
        sockperf \
        flent \
        tcpdump \
        tshark \
        bpftool \
        linux-perf \
        stress-ng \
        python3 \
        jq \
    && apt-get autoremove -y \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
              /var/cache/apt/archives/* \
              /tmp/* \
              /var/tmp/* \
              /usr/share/doc/* \
              /usr/share/man/* \
              /usr/share/locale/*

CMD ["bash"]
