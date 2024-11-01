#!/bin/bash

readarray -t BPFTRACE_FILES < <(find . -maxdepth 1 -type f -name "*.bt")

OUTPUT_FILE="bpftrace_output.log"

for file in "${BPFTRACE_FILES[@]}"; do
    pkill bpftrace

    random_number=$(( ( RANDOM % 10 ) + 1 ))
    if (( random_number < 5 )); then
        echo "Disable bpftrace scripts."
        bash ../run-pts.sh
        echo "----------------------------"
    fi
    echo "Running bpftrace script: $file"
    nohup bpftrace "$file" >> "$OUTPUT_FILE" 2>&1 &
    sleep 5
    echo "Running option: high"
    bash ../run-pts.sh
    echo "----------------------------"

    pkill bpftrace
done
