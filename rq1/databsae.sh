#!/bin/bash

PGSQL_IP="172.17.0.6"
export PGPASSWORD=mysecretpassword

# Default values
DEFAULT_PGSQL_DURATION=120

# Set the duration to the second argument, or use the default if not provided
PGSQL_DURATION="${2:-$DEFAULT_PGSQL_DURATION}"

echo "Duration: $PGSQL_DURATION seconds"

pgbench -h $PGSQL_IP -U postgres -d postgres -c 32 -j 8 -T $PGSQL_DURATION 2>&1 | tail -n 11
