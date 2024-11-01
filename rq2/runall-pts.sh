#!/bin/bash

# ps -C bpftrace -o pid,comm
# pkill bpftrace

readarray -t BPFTRACE_FILES < <(find . -maxdepth 1 -type f -name "*.bt")

OUTPUT_FILE="bpftrace_output.log"

for file in "${BPFTRACE_FILES[@]}"; do
    echo "Running bpftrace script: $file"
    #nohup bpftrace "$file" 2>&1 | tee -a "$OUTPUT_FILE" &
    nohup bpftrace "$file" >> "$OUTPUT_FILE" 2>&1 &
done

echo "All bpftrace scripts have been started in the background."
