#!/bin/bash



####################
# SETUP SECOPS VM ##
###################

## ANCHORE
./anchore


## DOCKER-BENCH

./docker-bench
cd docker-bench-security && docker build --no-cache -t docker-bench-security .

