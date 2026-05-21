#!/bin/bash

# EVALUATION SCRIPT: THROUGHPUT MICRO-BENCHMARKING (TCP)
# Executed inside the UPF VM (192.168.6.50) against MEC HOST VM

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

for SIZE in "${PACKET_SIZES[@]}"; do
  echo ""
  echo "############################################################"
  echo "  EVALUATING PACKET SIZE: $SIZE Bytes"
  echo "############################################################"

  tcp_throughput_sent=()
  tcp_throughput_recv=()
  tcp_retransmits=()
  tcp_cpu_host=()
  tcp_cpu_remote=()

  echo "-> Running iperf3 (TCP Throughput)..."
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
