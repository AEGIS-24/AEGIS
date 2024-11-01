#!/bin/bash


su - anonym -c "echo 'Switched to user'; whoami; which phoronix-test-suite; phoronix-test-suite batch-benchmark highsuite"
