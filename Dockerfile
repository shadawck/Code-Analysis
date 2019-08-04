FROM debian:latest
MAINTAINER remi.huguet@ensiie.fr

ENV REVISION 0.1


##############################################
## Install and build everything from source ##
##############################################

########################################
## For release see Dockerfile.release ##
########################################

# Add apt repo 

RUN apt-get update
RUN apt-get -y install software-properties-common 


# dependencies
RUN apt-get -y update && \
      apt-get -y install python python-pip python3 python3-pip git wget \
      autoconf \
      opam pkg-config ocaml-native-compilers ocaml-findlib menhir libmenhir-ocaml-dev libpcre-ocaml-dev libparmap-ocaml-dev texlive-fonts-extra  \
      openjdk-11-jre openjdk-11-jdk \
      libgmp-dev libsqlite3-dev zlib1g-dev  libmpfr-dev \
      gcc clang


# get Source and Build 

## Graudit 
RUN  git clone https://github.com/wireghoul/graudit/

## Mosca 
RUN git clone https://github.com/CoolerVoid/Mosca && \
      cd Mosca && \
      make

## RATS 
RUN wget http://downloads.sourceforge.net/project/expat/expat/2.0.1/expat-2.0.1.tar.gz && \
      tar -xvf expat-2.0.1.tar.gz && \
      cd expat-2.0.1 && \
      ./configure && make && make install && cd .. && \
      rm expat-2.0.1.tar.gz

RUN wget https://storage.googleapis.com/google-code-archive-downloads/v2/code.google.com/rough-auditing-tool-for-security/rats-2.4.tgz && \
      tar -xzvf rats-2.4.tgz && \
      cd rats-2.4 && \
      ./configure && \
      make && make install && \
      cd .. && rm rats-2.4.tgz 

## FlawFinder
RUN pip install flawfinder

## Coccinelle 
RUN git clone https://github.com/coccinelle/coccinelle && \ 
      cd coccinelle && \
      ./autogen && \
      ./configure && \
      make && \
      make install

## infer

RUN opam init --reinit --bare --disable-sandboxing --yes --auto-setup   

RUN git clone https://github.com/facebook/infer.git && cd infer && \
      eval $(opam env) && \ 
      ./build-infer.sh java && \ 
      make install




# Linking 
RUN ln -s /graudit/graudit /usr/bin/graudit && \
      ln -s /Mosca/mosca /usr/bin/mosca


# TESTING 
RUN echo -e "\033[33m---------- TESTING ---------------"

## Graudit
RUN echo "\033[33m---------- GRAUDIT ---------------"
RUN tput setaf 1; graudit -v


## Mosca
RUN echo "\033[33m---------- MOSCA ---------------"
RUN tput setaf 1; mosca 

## FlawFinder
RUN echo "\033[33m---------- FLAWFINDER ---------------"
RUN tput setaf 1; flawfinder --version

## Coccinelle
RUN echo "\033[33m---------- COCCINELLE ---------------"
RUN tput setaf 1; spatch --version

## Infer 
RUN echo "\033[33m---------- INFER ---------------"
RUN tput setaf 1; infer
