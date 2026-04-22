#!/bin/bash

# 5G MEC DOWNLINK Performance Evaluation Script.
# Executed inside the MEC HOST VM (192.168.6.10) against the UPF VM (192.168.6.50).

# "baseline" or "ebpf_xdp_enabled"
TEST_MODE="baseline"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

TARGET_IP="192.168.6.50"
IPERF_SERVER_PORT="8088" 
IPERF_CLIENT_PORT="13999"
SOCKPERF_SERVER_PORT="8089" 
SOCKPERF_CLIENT_PORT="14000"
DURATION=30
ITERATIONS=20
PACKET_SIZES=(64 1000 1400)

RAW_DIR="raw_results_downlink_${TEST_MODE}_${TIMESTAMP}"
mkdir -p "$RAW_DIR"

calculate_median() {
    local sorted=($(printf '%s\n' "$@" | sort -n))
    local count=${#sorted[@]}
    if [ "$count" -eq 0 ]; then
        echo "N/A"
        return
    fi
    local mid=$((count / 2))

    if ((count % 2 == 0)); then
        echo | awk -v a="${sorted[mid - 1]}" -v b="${sorted[mid]}" '{printf "%.3f", (a+b)/2}'
    else
        echo "${sorted[mid]}"
    fi
}

echo "==========================================================================="
echo "Starting 5G MEC Network Evaluation against $TARGET_IP in DOWNLINK direction"
echo "Test Mode: $TEST_MODE"
echo "iperf3 Port: $IPERF_SERVER_PORT | sockperf Port: $SOCKPERF_SERVER_PORT"
echo "Iterations: $ITERATIONS | Duration: ${DURATION}s per run"
echo "Testing Payload Sizes: ${PACKET_SIZES[*]} bytes"
echo "Raw data will be saved to: ./$RAW_DIR/"
echo "==========================================================================="

for SIZE in "${PACKET_SIZES[@]}"; do
    echo ""
    echo "############################################################"
    echo "  EVALUATING PACKET SIZE: $SIZE Bytes"
    echo "############################################################"

    iperf_throughput_sent=()
    iperf_throughput_recv=()
    iperf_pps_sent=()
    iperf_pps_recv=()
    iperf_jitter=()
    iperf_loss=()
    iperf_cpu_host=()
    iperf_cpu_remote=()
    sockperf_latency_avg=()
    sockperf_latency_p99=()
    sockperf_latency_p999=()
    sockperf_latency_p9999=()

    echo "-> Phase 0: Warming up eBPF UDP_CONNTRACK state..."
    sockperf ping-pong -i "$TARGET_IP" -p "$SOCKPERF_SERVER_PORT" -m "$SIZE" -t 5 >/dev/null 2>&1

    # warm-up 
    iperf3 -c "$TARGET_IP" -p "$IPERF_SERVER_PORT" --cport "$IPERF_CLIENT_PORT" -u -b 0 -l "$SIZE" -t 1 >/dev/null 2>&1
    sleep 1

    echo "-> Phase 1: Running iperf3 (UDP Throughput & PPS) in DOWNLINK direction..."
    for ((i = 1; i <= ITERATIONS; i++)); do
        echo -n "   Run $i/$ITERATIONS: "

        RAW_JSON=$(iperf3 -c "$TARGET_IP" -p "$IPERF_SERVER_PORT" --cport "$IPERF_CLIENT_PORT" -u -b 0 -l "$SIZE" -t "$DURATION" -J)

        if [ $? -ne 0 ] || [ -z "$RAW_JSON" ]; then
            echo "FAILED (iperf3 execution error)"
            continue
        fi

        echo "$RAW_JSON" > "$RAW_DIR/iperf_downlink_${SIZE}B_run${i}.json"

        THROUGHPUT_SENT=$(echo "$RAW_JSON" | jq -r '.end.sum_sent.bits_per_second / 1000000000' 2>/dev/null)
        THROUGHPUT_RECV=$(echo "$RAW_JSON" | jq -r '.end.sum_received.bits_per_second / 1000000000' 2>/dev/null)
        JITTER=$(echo "$RAW_JSON" | jq -r '.end.sum.jitter_ms' 2>/dev/null)
        LOSS=$(echo "$RAW_JSON" | jq -r '.end.sum.lost_percent' 2>/dev/null)
        
        PACKETS_SENT=$(echo "$RAW_JSON" | jq -r '.end.sum_sent.packets' 2>/dev/null)
        PACKETS_LOST=$(echo "$RAW_JSON" | jq -r '.end.sum_received.lost_packets' 2>/dev/null)
        RUN_DURATION=$(echo "$RAW_JSON" | jq -r '.end.sum_received.seconds' 2>/dev/null)
        
        if [ -z "$PACKETS_LOST" ] || [ "$PACKETS_LOST" == "null" ]; then PACKETS_LOST=0; fi
        if [ -z "$PACKETS_SENT" ] || [ "$PACKETS_SENT" == "null" ]; then PACKETS_SENT=0; fi
        PACKETS_RECV=$((PACKETS_SENT - PACKETS_LOST))

        PPS_SENT=$(echo | awk -v p="$PACKETS_SENT" -v s="$RUN_DURATION" '{if(s>0) printf "%.0f", p/s; else print 0}')
        PPS_RECV=$(echo | awk -v p="$PACKETS_RECV" -v s="$RUN_DURATION" '{if(s>0) printf "%.0f", p/s; else print 0}')

        CPU_HOST=$(echo "$RAW_JSON" | jq -r '.end.cpu_utilization_percent.host_total' 2>/dev/null)
        CPU_REMOTE=$(echo "$RAW_JSON" | jq -r '.end.cpu_utilization_percent.remote_total' 2>/dev/null)

        if [ -z "$THROUGHPUT_SENT" ] || [ "$THROUGHPUT_SENT" == "null" ]; then
            echo "FAILED (Could not parse JSON output)"
            continue
        fi

        iperf_throughput_sent+=("$THROUGHPUT_SENT")
        iperf_throughput_recv+=("$THROUGHPUT_RECV")
        iperf_pps_sent+=("$PPS_SENT")
        iperf_pps_recv+=("$PPS_RECV")
        iperf_jitter+=("$JITTER")
        iperf_loss+=("$LOSS")
        iperf_cpu_host+=("$CPU_HOST")
        iperf_cpu_remote+=("$CPU_REMOTE")

        printf "Tx: %.3f Gbps | Rx: %.3f Gbps | PPS(Tx): %d | PPS(Rx): %d | Jitter: %.3f ms | Loss: %.2f%% | CPU Host: %.1f%% | CPU Remote: %.1f%%\n" \
            "$THROUGHPUT_SENT" "$THROUGHPUT_RECV" "$PPS_SENT" "$PPS_RECV" "$JITTER" "$LOSS" "$CPU_HOST" "$CPU_REMOTE"

        sleep 1
    done

    echo "-> Phase 2: Running sockperf (UDP Latency under load) in DOWNLINK direction..."
    for ((i = 1; i <= ITERATIONS; i++)); do
        echo -n "   Run $i/$ITERATIONS: "

        RAW_OUTPUT=$(
            sockperf under-load -i "$TARGET_IP" -p "$SOCKPERF_SERVER_PORT" --client_port "$SOCKPERF_CLIENT_PORT" \
            -m "$SIZE" -t "$DURATION" --full-log "$RAW_DIR/sockperf_downlink_${SIZE}B_run${i}_full.log" 2>&1
        )

        if [ $? -ne 0 ]; then
            echo "FAILED (sockperf execution error)"
            continue
        fi

        echo "$RAW_OUTPUT" > "$RAW_DIR/sockperf_downlink_${SIZE}B_run${i}_summary.txt"

        AVG_LAT=$(echo "$RAW_OUTPUT" | grep "avg-latency=" | awk -F "avg-latency=" '{print $2}' | awk '{print $1}')
        P99_LAT=$(echo "$RAW_OUTPUT" | grep "percentile 99.000" | awk '{print $6}')
        P999_LAT=$(echo "$RAW_OUTPUT" | grep "percentile 99.900" | awk '{print $6}')
        P9999_LAT=$(echo "$RAW_OUTPUT" | grep "percentile 99.990" | awk '{print $6}')

        if [ -z "$AVG_LAT" ] || [ -z "$P99_LAT" ]; then
            echo "FAILED (Could not parse latency)"
            continue
        fi

        sockperf_latency_avg+=("$AVG_LAT")
        sockperf_latency_p99+=("$P99_LAT")
        sockperf_latency_p999+=("$P999_LAT")
        sockperf_latency_p9999+=("$P9999_LAT")

        printf "Avg: %.3f usec | p99: %.3f usec | p99.9: %.3f usec | p99.99: %.3f usec\n" \
            "$AVG_LAT" "$P99_LAT" "$P999_LAT" "$P9999_LAT"
        sleep 1
    done

    echo "-------------------------------------------------------------"
    echo "DOWNLINK RESULTS FOR $SIZE BYTES (Median of $ITERATIONS runs)"
    echo "-------------------------------------------------------------"
    echo "UDP Throughput (Sent):     $(calculate_median "${iperf_throughput_sent[@]}") Gbps"
    echo "UDP Throughput (Received): $(calculate_median "${iperf_throughput_recv[@]}") Gbps"
    echo "UDP PPS (Sent):            $(calculate_median "${iperf_pps_sent[@]}") packets/sec"
    echo "UDP PPS (Received):        $(calculate_median "${iperf_pps_recv[@]}") packets/sec"
    echo "UDP Jitter:                $(calculate_median "${iperf_jitter[@]}") ms"
    echo "UDP CPU (Host):            $(calculate_median "${iperf_cpu_host[@]}") %"
    echo "UDP CPU (Remote):          $(calculate_median "${iperf_cpu_remote[@]}") %"
    echo "UDP Packet Loss:           $(calculate_median "${iperf_loss[@]}") %"
    echo "UDP Latency (Avg):         $(calculate_median "${sockperf_latency_avg[@]}") usec"
    echo "UDP Latency (p99):         $(calculate_median "${sockperf_latency_p99[@]}") usec"
    echo "UDP Latency (p99.9):       $(calculate_median "${sockperf_latency_p999[@]}") usec"
    echo "UDP Latency (p99.99):      $(calculate_median "${sockperf_latency_p9999[@]}") usec"
    echo "------------------------------------------------------------"
done
