#!/bin/bash

set -xe

# Usage: ./bench-fpga-offload.sh <path_to_pcap_file>
#
# This script benchmarks two variants of Suricata:
#   - FPGA-offloaded Variant: uses suricata-pcap-patternmatch-evaluate.yaml with key check "non"
#   - Baseline Variant: uses suricata-pcap-patternmatch-evaluate-raw.yaml with key check "none"

# Check parameter
if [ $# -ne 1 ]; then
  echo "Usage: $0 <path_to_pcap_file>"
  exit 1
fi

PCAP_FILE=$1
if [ ! -f "$PCAP_FILE" ]; then
  echo "PCAP file $PCAP_FILE does not exist."
  exit 1
fi

# # Set compilation flag for -O3 optimization for both instances.
# export CFLAGS="-O3"

# #########################
# # PCAP Conversion Phase #
# #########################

# # Update the savepcap configuration with the provided PCAP file.
# SAVEPCAP_CONFIG="suricata-pcap-patternmatch-big-save.yaml"
# TEMP_SAVEPCAP_CONFIG="temp-$SAVEPCAP_CONFIG"
# cp $SAVEPCAP_CONFIG $TEMP_SAVEPCAP_CONFIG
# # Assumes the config file contains a line: input_file: <some_default_value>
# sed -i "s|input_file: .*|input_file: $PCAP_FILE|g" $TEMP_SAVEPCAP_CONFIG

# # Compile the savepcap instance.
# echo "Compiling savepcap instance..."
# make -j2

# # Run PCAP conversion with FPGA Offload.
# echo "Running PCAP conversion..."
# sudo ./src/suricata -c $TEMP_SAVEPCAP_CONFIG --dpdk -l /tmp/ -S emerging-all.rules -vvvv -k none
# if [ $? -ne 0 ]; then
#   echo "PCAP conversion failed."
#   exit 1
# fi

# # Clean up temporary savepcap config.
# rm $TEMP_SAVEPCAP_CONFIG

####################################
# Evaluation Phase & CSV Generation#
####################################

# Define evaluation variants and their respective configuration files and key checks.
declare -A VARIANT_CONFIGS
VARIANT_CONFIGS["eval"]="suricata-pcap-patternmatch-evaluate-fpga.yaml"
VARIANT_CONFIGS["baseline"]="suricata-pcap-patternmatch-evaluate-baseline.yaml"

# OFFLOAD_OPTIONS=("pktpayload" "pktpayload-stream")
# HS_IDS_LIST=("1" "2" "3")
OFFLOAD_OPTIONS=("pktpayload-stream")
HS_IDS_LIST=("3")

EXP_ITERS=10

# Loop over offload and HS pattern ID settings.
for offload in "${OFFLOAD_OPTIONS[@]}"; do
  for hs in "${HS_IDS_LIST[@]}"; do
    # Construct CSV filename that reflects the variant settings.
    PCAP_FILE_NAME=$(basename $PCAP_FILE)
    TIMESTAMP=$(date +"%Y-%m-%d-%H-%M")
    CSV_FILENAME="${PCAP_FILE_NAME}-${offload}-${hs}ids-${TIMESTAMP}.csv"
    echo "$PCAP_FILE_NAME: Benchmarking variant: Offload = $offload, Max HS Pattern IDs = $hs"
    
    # Create CSV file with header if it doesn't exist.
    if [ ! -f "$CSV_FILENAME" ]; then
      echo "Variant,Iteration,Elapsed_Time,Alerts,Flows,Offload,HS_Pattern_IDs" > "$CSV_FILENAME"
    fi
    
    # Run both evaluation variants.
    for variant in "${!VARIANT_CONFIGS[@]}"; do
      BASE_CONFIG="${VARIANT_CONFIGS[$variant]}"
      
      for iter in $(seq 1 $EXP_ITERS); do
        sudo rm -f /tmp/suricata.log
        echo "Running $variant iteration $iter..."
        sudo ./src/suricata -c $BASE_CONFIG --dpdk -l /tmp/ -S emerging-all.rules -vvvv -k none --set "dpdk.eal-params.vdev=net_pcap0,rx_pcap=${PCAP_FILE}"
        if [ $? -ne 0 ]; then
          echo "$variant run iteration $iter failed."
          continue
        fi
        
        LOG_FILE="/tmp/suricata.log"
        elapsed=$(grep -Eo "time elapsed [0-9\.]*" $LOG_FILE | awk '{print $3}')
        alerts=$(grep -Eo "Alerts: [0-9]*" $LOG_FILE | awk '{print $2}')
        flows=$(grep -Eo "flow-manager: [0-9]* flows processed" $LOG_FILE | awk '{print $2}')
        
        # If parsing fails, default to 0.
        elapsed=${elapsed:-0}
        alerts=${alerts:-0}
        flows=${flows:-0}
        
        # Append the results to the CSV file.
        echo "$variant,$iter,$elapsed,$alerts,$flows,$offload,$hs" >> "$CSV_FILENAME"
        
        # # For basic validation: if this is the baseline run, check if matching eval iteration exists and compare.
        # if [ "$variant" == "baseline" ]; then
        #   eval_line=$(grep "^eval,$iter," "$CSV_FILENAME")
        #   if [ ! -z "$eval_line" ]; then
        #     eval_alerts=$(echo $eval_line | cut -d',' -f4)
        #     eval_flows=$(echo $eval_line | cut -d',' -f5)
        #     if [ "$alerts" -ne "$eval_alerts" ] || [ "$flows" -ne "$eval_flows" ]; then
        #       echo "Validation Warning: Metrics mismatch in iteration $iter for offload=$offload, hs_ids=$hs."
        #     fi
        #   fi
        # fi
        
        # Sleep briefly between iterations if needed.
        sleep 2
      done
    done
  done
done

echo "Benchmarking complete. CSV files have been generated for each variant configuration."
