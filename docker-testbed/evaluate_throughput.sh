#!/bin/bash

# TCP Throughput Evaluation Script (iperf3)
# Methodology: 20 iterations, 30-second duration, Median calculation

TARGET_IP="172.20.0.20"
DURATION=30
ITERATIONS=20

iperf_throughput=()

calculate_median() {
    local sorted=($(printf '%s\n' "$@" | sort -n))
    local count=${#sorted[@]}
    local mid=$((count / 2))

    if ((count % 2 == 0)); then
        echo | awk -v a="${sorted[mid - 1]}" -v b="${sorted[mid]}" '{printf "%.3f", (a+b)/2}'
    else
        echo "${sorted[mid]}"
    fi
}

echo "Starting TCP Throughput evaluation against $TARGET_IP..."
echo "Executing $ITERATIONS iterations of $DURATION seconds each."
echo "------------------------------------------------------------"

for ((i = 1; i <= ITERATIONS; i++)); do
    echo -n "  Run $i/$ITERATIONS: "

    RAW_JSON=$(iperf3 -c "$TARGET_IP" -t "$DURATION" -J 2>/dev/null)

    if [ $? -ne 0 ]; then
        echo "FAILED (iperf3 execution error or server unreachable)"
        continue
    fi

    THROUGHPUT=$(echo "$RAW_JSON" | jq -r '.end.sum_sent.bits_per_second / 1000000000' 2>/dev/null)

    if [ -z "$THROUGHPUT" ] || [ "$THROUGHPUT" == "null" ]; then
        echo "FAILED (Could not parse throughput from JSON)"
        continue
    fi

    iperf_throughput+=("$THROUGHPUT")

    printf "%.3f Gbps\n" "$THROUGHPUT"

    sleep 1
done

echo "============================================================"
echo "EVALUATION RESULTS (Median of $ITERATIONS runs)"
echo "============================================================"

if [ ${#iperf_throughput[@]} -gt 0 ]; then
    MEDIAN_THROUGHPUT=$(calculate_median "${iperf_throughput[@]}")
    echo "Median TCP Throughput: $MEDIAN_THROUGHPUT Gbps"
else
    echo "Median TCP Throughput: N/A (No successful runs)"
fi
echo "============================================================"
