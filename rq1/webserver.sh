#!/bin/bash

NGINX_ADDR="http://172.17.0.3/"
DEFAULT_DURATION="120s"

# Set the duration to the second argument, or use the default if not provided
DURATION="${2:-$DEFAULT_DURATION}"

# https://github.com/rakyll/hey
hey -cpus 8 -n 200 -c 50 -q 500000 -z $DURATION $NGINX_ADDR
