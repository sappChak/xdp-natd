#!/bin/bash

# EVALUATION SCRIPT: LATENCY MICRO-BENCHMARKING
# Executed inside the UPF VM (192.168.6.50) against MEC HOST VM
# Assumes: sudo ip route add 192.168.6.0/24 dev tun_srsue

TEST_MODE="$1"
TARGET_IP="$2"
SOCKPERF_SERVER_PORT="$3"
DURATION=60
ITERATIONS=10
PACKET_SIZES=(64 1000 1400)

for cmd in sockperf awk; do
    command -v "$cmd" >/dev/null || {
        echo "Missing dependency: $cmd"
        exit 1
    }
done

calculate_median() {
    local sorted=($(printf '%s\n' "$@" | sort -g))
    local count=${#sorted[@]}
    if [[ "$count" -eq 0 ]]; then
        echo "N/A"
        return
    fi
    local mid=$((count / 2))

    if ((count % 2 == 0)); then
        echo | awk -v a="${sorted[mid - 1]}" -v b="${sorted[mid]}" \
            '{printf "%.3f", (a+b)/2}'
    else
        echo "${sorted[mid]}"
    fi
}

echo "========================================================================"
echo "Starting 5G MEC Network Eval against $TARGET_IP (LATENCY)"
echo "Test Mode: $TEST_MODE | sockperf Port: $SOCKPERF_SERVER_PORT"
echo "Iterations: $ITERATIONS | Duration: ${DURATION}s per run"
echo "Payload Sizes: ${PACKET_SIZES[*]} bytes"
echo "========================================================================"

for SIZE in "${PACKET_SIZES[@]}"; do
    echo ""
    echo "############################################################"
    echo "  EVALUATING PACKET SIZE: $SIZE Bytes"
    echo "############################################################"

    sockperf_lat_min=()
    sockperf_lat_p25=()
    sockperf_lat_p50=()
    sockperf_lat_p75=()
    sockperf_lat_p90=()
    sockperf_lat_avg=()
    sockperf_lat_p99=()
    sockperf_lat_p999=()
    sockperf_lat_p9999=()
    sockperf_lat_p99999=()
    sockperf_lat_max=()
    sockperf_std_dev=()

    sockperf_msg_sent=()
    sockperf_msg_recv=()
    sockperf_msg_drop=()
    sockperf_msg_dup=()
    sockperf_msg_ooo=()

    echo "-> Phase 0: Warmup..."
    sockperf pp -i "$TARGET_IP" -p "$SOCKPERF_SERVER_PORT" \
        -m "$SIZE" -t 5 >/dev/null 2>&1
    sleep 1

    echo "-> Phase 1: Running sockperf (UDP Latency in ping-pong mode)..."
    for ((i = 1; i <= ITERATIONS; i++)); do
        echo -n "   Run $i/$ITERATIONS: "

        RAW_OUTPUT=$(
            sockperf pp -i "$TARGET_IP" -p "$SOCKPERF_SERVER_PORT" \
                -m "$SIZE" -t "$DURATION" 2>&1
        )

        if [[ $? -ne 0 ]]; then
            echo "FAILED (sockperf execution error)"
            continue
        fi

        MIN_LAT=$(echo "$RAW_OUTPUT" | awk '/<MIN> observation/ {print $NF}')
        P25_LAT=$(echo "$RAW_OUTPUT" | awk '/percentile 25.000/ {print $NF}')
        P50_LAT=$(echo "$RAW_OUTPUT" | awk '/percentile 50.000/ {print $NF}')
        P75_LAT=$(echo "$RAW_OUTPUT" | awk '/percentile 75.000/ {print $NF}')
        P90_LAT=$(echo "$RAW_OUTPUT" | awk '/percentile 90.000/ {print $NF}')
        P99_LAT=$(echo "$RAW_OUTPUT" | awk '/percentile 99.000/ {print $NF}')
        P999_LAT=$(echo "$RAW_OUTPUT" | awk '/percentile 99.900/ {print $NF}')
        P9999_LAT=$(echo "$RAW_OUTPUT" | awk '/percentile 99.990/ {print $NF}')
        P99999_LAT=$(echo "$RAW_OUTPUT" | awk '/percentile 99.999/ {print $NF}')
        MAX_LAT=$(echo "$RAW_OUTPUT" | awk '/<MAX> observation/ {print $NF}')

        AVG_LAT=$(echo "$RAW_OUTPUT" | awk -F "avg-latency=" \
            '/avg-latency/ {print $2}' | awk '{print $1}')
        STD_DEV=$(echo "$RAW_OUTPUT" | awk -F "std-dev=" \
            '/std-dev/ {print $2}' | tr -d ')')

        SENT_MSG=$(echo "$RAW_OUTPUT" | awk -F "SentMessages=" \
            '/\[Valid Duration\]/ {print $2}' | awk -F ";" '{print $1}')
        RECV_MSG=$(echo "$RAW_OUTPUT" | awk -F "ReceivedMessages=" \
            '/\[Valid Duration\]/ {print $2}' | awk '{print $1}')

        DROP_MSG=$(echo "$RAW_OUTPUT" | awk -F "dropped messages =" \
            '/dropped/ {print $2}' | awk '{print $1}' | tr -d ';')
        DUP_MSG=$(echo "$RAW_OUTPUT" | awk -F "duplicated messages =" \
            '/duplicated/ {print $2}' | awk '{print $1}' | tr -d ';')
        OOO_MSG=$(echo "$RAW_OUTPUT" | awk -F "out-of-order messages =" \
            '/out-of-order/ {print $2}' | awk '{print $1}')

        if [[ -z "$AVG_LAT" ]] || [[ -z "$P50_LAT" ]] || [[ -z "$DROP_MSG" ]]; then
            echo "FAILED (Could not parse sockperf output)"
            continue
        fi

        sockperf_lat_min+=("$MIN_LAT")
        sockperf_lat_p25+=("$P25_LAT")
        sockperf_lat_p50+=("$P50_LAT")
        sockperf_lat_p75+=("$P75_LAT")
        sockperf_lat_p90+=("$P90_LAT")
        sockperf_lat_avg+=("$AVG_LAT")
        sockperf_lat_p99+=("$P99_LAT")
        sockperf_lat_p999+=("$P999_LAT")
        sockperf_lat_p9999+=("$P9999_LAT")
        sockperf_lat_p99999+=("$P99999_LAT")
        sockperf_lat_max+=("$MAX_LAT")
        sockperf_std_dev+=("$STD_DEV")

        sockperf_msg_sent+=("${SENT_MSG:-0}")
        sockperf_msg_recv+=("${RECV_MSG:-0}")
        sockperf_msg_drop+=("$DROP_MSG")
        sockperf_msg_dup+=("$DUP_MSG")
        sockperf_msg_ooo+=("$OOO_MSG")

        printf "Avg: %.3f | p50: %.3f | p99: %.3f | p99.99: %.3f | Drop: %d\n" \
            "$AVG_LAT" "$P50_LAT" "$P99_LAT" "$P9999_LAT" "$DROP_MSG"

        sleep 2
    done

    echo "------------------------------------------------------------"
    echo "LATENCY RESULTS FOR $SIZE BYTES (Median of $ITERATIONS runs)"
    echo "------------------------------------------------------------"

    echo "--- Distribution (usec) ---"
    echo "Minimum:             $(calculate_median "${sockperf_lat_min[@]}")"
    echo "25th Percentile:     $(calculate_median "${sockperf_lat_p25[@]}")"
    echo "50th Percentile:     $(calculate_median "${sockperf_lat_p50[@]}")"
    echo "75th Percentile:     $(calculate_median "${sockperf_lat_p75[@]}")"
    echo "90th Percentile:     $(calculate_median "${sockperf_lat_p90[@]}")"
    echo "Average (Mean):      $(calculate_median "${sockperf_lat_avg[@]}")"
    echo "99th Percentile:     $(calculate_median "${sockperf_lat_p99[@]}")"
    echo "99.9th Percentile:   $(calculate_median "${sockperf_lat_p999[@]}")"
    echo "99.99th Percentile:  $(calculate_median "${sockperf_lat_p9999[@]}")"
    echo "99.999th Percentile: $(calculate_median "${sockperf_lat_p99999[@]}")"
    echo "Maximum:             $(calculate_median "${sockperf_lat_max[@]}")"
    echo "Std. Deviation:      $(calculate_median "${sockperf_std_dev[@]}")"

    echo "--- Reliability Metrics ---"
    echo "Sent Messages:       $(calculate_median "${sockperf_msg_sent[@]}")"
    echo "Received Messages:   $(calculate_median "${sockperf_msg_recv[@]}")"
    echo "Dropped Messages:    $(calculate_median "${sockperf_msg_drop[@]}")"
    echo "Duplicated Messages: $(calculate_median "${sockperf_msg_dup[@]}")"
    echo "Out-of-Order Msgs:   $(calculate_median "${sockperf_msg_ooo[@]}")"
    echo "------------------------------------------------------------"
done
