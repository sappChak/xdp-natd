#!/bin/bash

# EVALUATION SCRIPT: THROUGHPUT MICRO-BENCHMARKING (UDP & TCP)
# Executed inside the UPF VM (192.168.6.50) against MEC HOST VM
# Assumes: sudo ip route add 192.168.6.0/24 dev tun_srsue

TEST_MODE="$1"
TARGET_IP="$2"
IPERF_SERVER_PORT="$3"
IPERF_BITRATE="$4"
DURATION=30
ITERATIONS=10
PACKET_SIZES=(64 1000 1400)

for cmd in iperf3 jq awk; do
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
echo "Starting 5G MEC Network Eval against $TARGET_IP (THROUGHPUT)"
echo "Test Mode: $TEST_MODE"
echo "iperf3 Port: $IPERF_SERVER_PORT | Target Bitrate limit: $IPERF_BITRATE"
echo "Iterations: $ITERATIONS | Duration: ${DURATION}s per run"
echo "Testing Payload Sizes: ${PACKET_SIZES[*]} bytes"
echo "========================================================================"

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

  tcp_throughput_sent=()
  tcp_throughput_recv=()
  tcp_retransmits=()
  tcp_cpu_host=()
  tcp_cpu_remote=()

  echo "-> Phase 1: Running iperf3 (UDP Throughput & Limit)..."
  for ((i = 1; i <= ITERATIONS; i++)); do
    echo -n "   Run $i/$ITERATIONS: "

    RAW_JSON=$(iperf3 -c "$TARGET_IP" -p "$IPERF_SERVER_PORT" -u \
      -b "$IPERF_BITRATE" -l "$SIZE" -t "$DURATION" -J --get-server-output)

    if [[ $? -ne 0 ]] || [[ -z "$RAW_JSON" ]]; then
      echo "FAILED (iperf3 execution error)"
      continue
    fi

    # Switched to Mbps scaling (/ 1e6)
    THROUGHPUT_SENT=$(echo "$RAW_JSON" |
      jq -r '.end.sum_sent.bits_per_second / 1e6')
    THROUGHPUT_RECV=$(echo "$RAW_JSON" |
      jq -r '.server_output_json.end.sum_received.bits_per_second / 1e6')
    JITTER=$(echo "$RAW_JSON" |
      jq -r '.server_output_json.end.sum.jitter_ms')
    LOSS=$(echo "$RAW_JSON" |
      jq -r '.server_output_json.end.sum.lost_percent')

    PACKETS_SENT=$(echo "$RAW_JSON" |
      jq -r '.end.sum_sent.packets')
    PACKETS_LOST=$(echo "$RAW_JSON" |
      jq -r '.server_output_json.end.sum.lost_packets')
    RUN_DURATION=$(echo "$RAW_JSON" |
      jq -r '.end.sum_received.seconds')

    if [[ -z "$PACKETS_LOST" ]] || [[ "$PACKETS_LOST" == "null" ]]; then
      PACKETS_LOST=0
    fi
    if [[ -z "$PACKETS_SENT" ]] || [[ "$PACKETS_SENT" == "null" ]]; then
      PACKETS_SENT=0
    fi

    PACKETS_RECV=$((PACKETS_SENT - PACKETS_LOST))

    PPS_SENT=$(echo | awk -v p="$PACKETS_SENT" -v s="$RUN_DURATION" \
      '{if(s>0) printf "%.0f", p/s; else print 0}')
    PPS_RECV=$(echo | awk -v p="$PACKETS_RECV" -v s="$RUN_DURATION" \
      '{if(s>0) printf "%.0f", p/s; else print 0}')

    CPU_HOST=$(echo "$RAW_JSON" |
      jq -r '.end.cpu_utilization_percent.host_total')
    CPU_REMOTE=$(echo "$RAW_JSON" |
      jq -r '.end.cpu_utilization_percent.remote_total')

    if [[ -z "$THROUGHPUT_SENT" ]] || [[ "$THROUGHPUT_SENT" == "null" ]]; then
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

    printf "Tx: %.3f Mbps | Rx: %.3f Mbps | PPS(Tx): %d | PPS(Rx): %d | " \
      "$THROUGHPUT_SENT" "$THROUGHPUT_RECV" "$PPS_SENT" "$PPS_RECV"
    printf "Jitter: %.3f ms | Loss: %.2f%% | CPU Host: %.1f%% | " \
      "$JITTER" "$LOSS" "$CPU_HOST"
    printf "CPU Remote: %.1f%%\n" "$CPU_REMOTE"
    sleep 2
  done

  echo "-> Phase 2: Running iperf3 (TCP Throughput)..."
  for ((i = 1; i <= ITERATIONS; i++)); do
    echo -n "   Run $i/$ITERATIONS: "

    RAW_JSON_TCP=$(iperf3 -c "$TARGET_IP" -p "$IPERF_SERVER_PORT" \
      -l "$SIZE" -t "$DURATION" -J --get-server-output)

    if [[ $? -ne 0 ]] || [[ -z "$RAW_JSON_TCP" ]]; then
      echo "FAILED (iperf3 TCP execution error)"
      continue
    fi

    TCP_SENT=$(echo "$RAW_JSON_TCP" |
      jq -r '.end.sum_sent.bits_per_second / 1e6')
    TCP_RECV=$(echo "$RAW_JSON_TCP" |
      jq -r '.end.sum_received.bits_per_second / 1e6')
    TCP_RETRANS=$(echo "$RAW_JSON_TCP" |
      jq -r '.end.sum_sent.retransmits')

    TCP_CPU_HOST=$(echo "$RAW_JSON_TCP" |
      jq -r '.end.cpu_utilization_percent.host_total')
    TCP_CPU_REMOTE=$(echo "$RAW_JSON_TCP" |
      jq -r '.end.cpu_utilization_percent.remote_total')

    if [[ -z "$TCP_RETRANS" ]] || [[ "$TCP_RETRANS" == "null" ]]; then
      TCP_RETRANS=0
    fi

    if [[ -z "$TCP_SENT" ]] || [[ "$TCP_SENT" == "null" ]]; then
      echo "FAILED (Could not parse JSON output)"
      continue
    fi

    tcp_throughput_sent+=("$TCP_SENT")
    tcp_throughput_recv+=("$TCP_RECV")
    tcp_retransmits+=("$TCP_RETRANS")
    tcp_cpu_host+=("$TCP_CPU_HOST")
    tcp_cpu_remote+=("$TCP_CPU_REMOTE")

    printf "Tx: %.3f Mbps | Rx: %.3f Mbps | Retrans: %d | " \
      "$TCP_SENT" "$TCP_RECV" "$TCP_RETRANS"
    printf "CPU Host: %.1f%% | CPU Remote: %.1f%%\n" \
      "$TCP_CPU_HOST" "$TCP_CPU_REMOTE"
    sleep 2
  done

  echo "------------------------------------------------------------"
  echo "UDP THROUGHPUT RESULTS FOR $SIZE BYTES (Median of $ITERATIONS runs)"
  echo "------------------------------------------------------------"

  MED_TX=$(calculate_median "${iperf_throughput_sent[@]}")
  MED_RX=$(calculate_median "${iperf_throughput_recv[@]}")
  MED_PPS_TX=$(calculate_median "${iperf_pps_sent[@]}")
  MED_PPS_RX=$(calculate_median "${iperf_pps_recv[@]}")
  MED_JITTER=$(calculate_median "${iperf_jitter[@]}")
  MED_HOST_CPU=$(calculate_median "${iperf_cpu_host[@]}")
  MED_REM_CPU=$(calculate_median "${iperf_cpu_remote[@]}")
  MED_LOSS=$(calculate_median "${iperf_loss[@]}")

  echo "UDP Throughput (Sent):     $MED_TX Mbps"
  echo "UDP Throughput (Received): $MED_RX Mbps"
  echo "UDP PPS (Sent):            $MED_PPS_TX pps"
  echo "UDP PPS (Received):        $MED_PPS_RX pps"
  echo "UDP Jitter:                $MED_JITTER ms"
  echo "UDP CPU (Host):            $MED_HOST_CPU %"
  echo "UDP CPU (Remote):          $MED_REM_CPU %"
  echo "UDP Packet Loss:           $MED_LOSS %"

  echo "------------------------------------------------------------"
  echo "TCP THROUGHPUT RESULTS FOR $SIZE BYTES (Median of $ITERATIONS runs)"
  echo "------------------------------------------------------------"

  MED_TCP_TX=$(calculate_median "${tcp_throughput_sent[@]}")
  MED_TCP_RX=$(calculate_median "${tcp_throughput_recv[@]}")
  MED_TCP_RET=$(calculate_median "${tcp_retransmits[@]}")
  MED_TCP_HOST_CPU=$(calculate_median "${tcp_cpu_host[@]}")
  MED_TCP_REM_CPU=$(calculate_median "${tcp_cpu_remote[@]}")

  echo "TCP Throughput (Sent):     $MED_TCP_TX Mbps"
  echo "TCP Throughput (Received): $MED_TCP_RX Mbps"
  echo "TCP Retransmits:           $MED_TCP_RET"
  echo "TCP CPU (Host):            $MED_TCP_HOST_CPU %"
  echo "TCP CPU (Remote):          $MED_TCP_REM_CPU %"
  echo "------------------------------------------------------------"
done
