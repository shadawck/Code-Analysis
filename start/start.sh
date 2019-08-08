#!/bin/bash

####################################
# Start Docker for static analysis #
####################################

# Build&Start tool from docker in /Docker/static

# get all static Dockerfiles
DOCKERFILES_S_R=../docker/static/release/*
DOCKERFILES_S_DEV=../docker/static/dev/*
DOCKERFILES_S_ALL=../docker/static/all/Dockerfile.static_release

DOCKERFILES_D_R=../docker/dynamic/release/*
DOCKERILES_D_DEV=../docker/dynamic/dev/*
DOCKERFILES_D_ALL=../docker/dynamic/all/Dockerfile.dynamic_release


#NAME_VERSION=${f#*.}
#DOCKER_TAG=${NAME_VERSION%_*}



for f in $DOCKERFILES_S_R
do
   NAME_VERSION=${f#*Dockerfile.}
   DOCKER_TAG=${NAME_VERSION%_*}

   echo "LAUNCH STATIC DOCKER TOOLS"
   docker build -t $DOCKER_TAG -f $f . 
done


#####################################
# Start docker for dynamic analysis #
#####################################


for f in $DOCKERFILES_D_R
do
   echo "LAUCH DYNAMIC DOCKER TOOLS"
   NAME_VERSION=${f#*Dockerfile.}
   DOCKER_TAG=${NAME_VERSION%_*}

   echo "Processing $f file..."
done
