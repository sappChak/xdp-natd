#!/bin/bash

# Methodology: 20 iterations, 30-second duration, Median calculation across percentiles

TARGET_IP="172.20.0.20"
DURATION=30
ITERATIONS=20
MSG_SIZE=64

lat_avg=()
lat_50=()
lat_99=()
lat_99_9=()
lat_99_99=()
lat_max=()

calculate_median() {
    local sorted=($(printf '%s\n' "$@" | sort -n))
    local count=${#sorted[@]}
    local mid=$((count / 2))

    if ((count == 0)); then
        echo "N/A"
        return
    fi

    if ((count % 2 == 0)); then
        echo | awk -v a="${sorted[mid - 1]}" -v b="${sorted[mid]}" '{printf "%.3f", (a+b)/2}'
    else
        echo "${sorted[mid]}"
    fi
}

echo "Starting UDP URLLC Latency evaluation against $TARGET_IP..."
echo "Executing $ITERATIONS iterations of $DURATION seconds each."
echo "------------------------------------------------------------"

for ((i = 1; i <= ITERATIONS; i++)); do
    echo -n "  Run $i/$ITERATIONS: "

    RAW_OUTPUT=$(sockperf under-load -i "$TARGET_IP" -t "$DURATION" --msg-size "$MSG_SIZE" 2>&1)

    if [ $? -ne 0 ]; then
        echo "FAILED (sockperf execution error or server unreachable)"
        continue
    fi

    AVG=$(echo "$RAW_OUTPUT" | grep "Summary: Latency is" | awk -F " is " '{print $2}' | awk '{print $1}')
    P50=$(echo "$RAW_OUTPUT" | grep "percentile 50.000 =" | awk -F "=" '{print $2}' | awk '{print $1}')
    P99=$(echo "$RAW_OUTPUT" | grep "percentile 99.000 =" | awk -F "=" '{print $2}' | awk '{print $1}')
    P99_9=$(echo "$RAW_OUTPUT" | grep "percentile 99.900 =" | awk -F "=" '{print $2}' | awk '{print $1}')
    P99_99=$(echo "$RAW_OUTPUT" | grep "percentile 99.990 =" | awk -F "=" '{print $2}' | awk '{print $1}')
    MAX=$(echo "$RAW_OUTPUT" | grep "<MAX> observation =" | awk -F "=" '{print $2}' | awk '{print $1}')

    if [ -z "$AVG" ] || [ -z "$P99" ]; then
        echo "FAILED (Could not parse percentiles from output)"
        continue
    fi

    lat_avg+=("$AVG")
    lat_50+=("$P50")
    lat_99+=("$P99")
    lat_99_9+=("$P99_9")
    lat_99_99+=("$P99_99")
    lat_max+=("$MAX")

    printf "Avg: %.3f us | 99th: %.3f us\n" "$AVG" "$P99"

    sleep 1
done

echo "========================================================"
echo "LATENCY EVALUATION RESULTS (Median of $ITERATIONS runs)"
echo "========================================================"

if [ ${#lat_avg[@]} -gt 0 ]; then
    echo "Average Latency:      $(calculate_median "${lat_avg[@]}") usec"
    echo "50th Percentile:      $(calculate_median "${lat_50[@]}") usec"
    echo "99th Percentile:      $(calculate_median "${lat_99[@]}") usec"
    echo "99.9th Percentile:    $(calculate_median "${lat_99_9[@]}") usec"
    echo "99.99th Percentile:   $(calculate_median "${lat_99_99[@]}") usec"
    echo "Maximum Latency:      $(calculate_median "${lat_max[@]}") usec"
else
    echo "No successful runs to calculate statistics."
fi
echo "========================================================"
