#!/bin/bash



####################
# SETUP SECOPS VM ##
###################


###### INIT #####
chmod +x ./*
rm -rf ../build/*



## ANCHORE
./anchore

## DOCKER-BENCH

./docker-bench

# START PHASE
#cd docker-bench-security && docker build --no-cache -t docker-bench-security .

# Hadolint
./hadolint
