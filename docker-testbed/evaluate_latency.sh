#!/bin/bash

# EVALUATION SCRIPT: ITERATIVE LATENCY MICRO-BENCHMARKING
# Executed inside the UPF VM against MEC HOST VM
# Assumes: sudo ip route add 192.168.6.0/24 dev tun_srsue

TEST_MODE="$1"
TARGET_IP="$2"
SOCKPERF_SERVER_PORT="$3"
DURATION=${4:-30}
ITERATIONS=${5:-10}
PACKET_SIZES=(64 1000 1400)

for cmd in sockperf awk sed; do
    command -v "$cmd" >/dev/null || {
        echo "Missing dependency: $cmd"
        exit 1
    }
done

echo "========================================================================"
echo "Starting 5G MEC Network Eval against $TARGET_IP (LATENCY)"
echo "Test Mode: $TEST_MODE | sockperf Port: $SOCKPERF_SERVER_PORT"
echo "Duration: ${DURATION}s per run | Iterations: $ITERATIONS"
echo "Payload Sizes: ${PACKET_SIZES[*]} B"
echo "========================================================================"

for SIZE in "${PACKET_SIZES[@]}"; do
    echo ""
    echo "############################################################"
    echo "  EVALUATING PACKET SIZE: $SIZE Bytes"
    echo "############################################################"

    lat_min=()
    lat_p25=()
    lat_p50=()
    lat_p75=()
    lat_p90=()
    lat_avg=()
    lat_p99=()
    lat_p999=()
    lat_p9999=()
    lat_p99999=()
    lat_max=()

    stat_std=()
    stat_mad=()
    stat_medad=()
    stat_siqr=()
    stat_cv=()
    stat_err=()
    stat_cil=()
    stat_cih=()

    run_tt=()
    run_wu=()
    run_ts=()
    run_tr=()
    run_vt=()
    run_vs=()
    run_vr=()
    run_obs=()

    rel_drop=()
    rel_dup=()
    rel_ooo=()

    echo "-> Phase 0: Warmup..."
    sockperf pp -i "$TARGET_IP" -p "$SOCKPERF_SERVER_PORT" \
        -m "$SIZE" -t 10 >/dev/null 2>&1
    sleep 2

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

        echo "$RAW_OUTPUT"

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

        AVG_LAT=$(echo "$RAW_OUTPUT" | sed -n 's/.*avg-latency=\([0-9.]*\).*/\1/p')
        STD_DEV=$(echo "$RAW_OUTPUT" | sed -n 's/.*std-dev=\([0-9.]*\).*/\1/p')
        MEAN_AD=$(echo "$RAW_OUTPUT" | sed -n 's/.*mean-ad=\([0-9.]*\).*/\1/p')
        MED_AD=$(echo "$RAW_OUTPUT" | sed -n 's/.*median-ad=\([0-9.]*\).*/\1/p')
        SIQR=$(echo "$RAW_OUTPUT" | sed -n 's/.*siqr=\([0-9.]*\).*/\1/p')
        CV=$(echo "$RAW_OUTPUT" | sed -n 's/.*cv=\([0-9.]*\).*/\1/p')
        STD_ERR=$(echo "$RAW_OUTPUT" | sed -n 's/.*std-error=\([0-9.]*\).*/\1/p')
        CI_L=$(echo "$RAW_OUTPUT" | sed -n 's/.*ci=\[\([0-9.]*\), \([0-9.]*\)\].*/\1/p')
        CI_H=$(echo "$RAW_OUTPUT" | sed -n 's/.*ci=\[\([0-9.]*\), \([0-9.]*\)\].*/\2/p')

        TOT_TIME=$(echo "$RAW_OUTPUT" |
            sed -n 's/.*\[Total Run\] RunTime=\([0-9.]*\).*/\1/p')
        WARMUP=$(echo "$RAW_OUTPUT" | sed -n 's/.*Warm up time=\([0-9]*\).*/\1/p')
        TOT_SENT=$(echo "$RAW_OUTPUT" |
            sed -n 's/.*\[Total Run\].*SentMessages=\([0-9]*\).*/\1/p')
        TOT_RECV=$(echo "$RAW_OUTPUT" |
            sed -n 's/.*\[Total Run\].*ReceivedMessages=\([0-9]*\).*/\1/p')

        VAL_TIME=$(echo "$RAW_OUTPUT" |
            sed -n 's/.*\[Valid Duration\] RunTime=\([0-9.]*\).*/\1/p')
        VAL_SENT=$(echo "$RAW_OUTPUT" |
            sed -n 's/.*\[Valid Duration\].*SentMessages=\([0-9]*\).*/\1/p')
        VAL_RECV=$(echo "$RAW_OUTPUT" |
            sed -n 's/.*\[Valid Duration\].*ReceivedMessages=\([0-9]*\).*/\1/p')
        TOT_OBS=$(echo "$RAW_OUTPUT" |
            grep -oE 'Total [0-9]+ observations' | grep -oE '[0-9]+')
        DROP_MSG=$(echo "$RAW_OUTPUT" |
            sed -n 's/.*dropped messages = \([0-9]*\).*/\1/p')
        DUP_MSG=$(echo "$RAW_OUTPUT" |
            sed -n 's/.*duplicated messages = \([0-9]*\).*/\1/p')
        OOO_MSG=$(echo "$RAW_OUTPUT" |
            sed -n 's/.*out-of-order messages = \([0-9]*\).*/\1/p')

        if [[ -z "$AVG_LAT" ]] || [[ -z "$P50_LAT" ]] || [[ -z "$DROP_MSG" ]]; then
            echo "FAILED (Parse error)"
            continue
        else
            echo "SUCCESS (Avg: ${AVG_LAT} usec, Drop: ${DROP_MSG})"
        fi

        lat_min+=("${MIN_LAT:-N/A}")
        lat_p25+=("${P25_LAT:-N/A}")
        lat_p50+=("${P50_LAT:-N/A}")
        lat_p75+=("${P75_LAT:-N/A}")
        lat_p90+=("${P90_LAT:-N/A}")
        lat_avg+=("${AVG_LAT:-N/A}")
        lat_p99+=("${P99_LAT:-N/A}")
        lat_p999+=("${P999_LAT:-N/A}")
        lat_p9999+=("${P9999_LAT:-N/A}")
        lat_p99999+=("${P99999_LAT:-N/A}")
        lat_max+=("${MAX_LAT:-N/A}")

        stat_std+=("${STD_DEV:-N/A}")
        stat_mad+=("${MEAN_AD:-N/A}")
        stat_medad+=("${MED_AD:-N/A}")
        stat_siqr+=("${SIQR:-N/A}")
        stat_cv+=("${CV:-N/A}")
        stat_err+=("${STD_ERR:-N/A}")
        stat_cil+=("${CI_L:-N/A}")
        stat_cih+=("${CI_H:-N/A}")

        run_tt+=("${TOT_TIME:-N/A}")
        run_wu+=("${WARMUP:-N/A}")
        run_ts+=("${TOT_SENT:-N/A}")
        run_tr+=("${TOT_RECV:-N/A}")
        run_vt+=("${VAL_TIME:-N/A}")
        run_vs+=("${VAL_SENT:-N/A}")
        run_vr+=("${VAL_RECV:-N/A}")
        run_obs+=("${TOT_OBS:-N/A}")

        rel_drop+=("${DROP_MSG:-N/A}")
        rel_dup+=("${DUP_MSG:-N/A}")
        rel_ooo+=("${OOO_MSG:-N/A}")

        sleep 2
    done

    echo "------------------------------------------------------------"
    echo "LATENCY ARRAY RESULTS FOR $SIZE BYTES (Runs: $ITERATIONS)"
    echo "------------------------------------------------------------"

    echo "--- Distribution (usec) ---"
    echo "Minimum:             ${lat_min[*]}"
    echo "25th Percentile:     ${lat_p25[*]}"
    echo "50th Percentile:     ${lat_p50[*]}"
    echo "75th Percentile:     ${lat_p75[*]}"
    echo "90th Percentile:     ${lat_p90[*]}"
    echo "Average (Mean):      ${lat_avg[*]}"
    echo "99th Percentile:     ${lat_p99[*]}"
    echo "99.9th Percentile:   ${lat_p999[*]}"
    echo "99.99th Percentile:  ${lat_p9999[*]}"
    echo "99.999th Percentile: ${lat_p99999[*]}"
    echo "Maximum:             ${lat_max[*]}"

    echo "--- Advanced Statistics ---"
    echo "Std. Deviation:      ${stat_std[*]}"
    echo "Mean Abs Dev:        ${stat_mad[*]}"
    echo "Median Abs Dev:      ${stat_medad[*]}"
    echo "SIQR:                ${stat_siqr[*]}"
    echo "Coef Variation (CV): ${stat_cv[*]}"
    echo "Standard Error:      ${stat_err[*]}"
    echo "99% CI Lower Bound:  ${stat_cil[*]}"
    echo "99% CI Upper Bound:  ${stat_cih[*]}"

    echo "--- Runtime & Observational Metrics ---"
    echo "Total Runtime (s):   ${run_tt[*]}"
    echo "Warmup Time (ms):    ${run_wu[*]}"
    echo "Total Sent Msgs:     ${run_ts[*]}"
    echo "Total Recv Msgs:     ${run_tr[*]}"
    echo "Valid Runtime (s):   ${run_vt[*]}"
    echo "Valid Sent Msgs:     ${run_vs[*]}"
    echo "Valid Recv Msgs:     ${run_vr[*]}"
    echo "Total Observations:  ${run_obs[*]}"

    echo "--- Reliability Metrics ---"
    echo "Dropped Messages:    ${rel_drop[*]}"
    echo "Duplicated Messages: ${rel_dup[*]}"
    echo "Out-of-Order Msgs:   ${rel_ooo[*]}"
    echo "------------------------------------------------------------"

    sleep 5
done
