FROM debian:stretch 

RUN apt-get update 
RUN apt-get install -y \
      git curl tar wget xz-utils

RUN wget https://github.com/facebook/infer/releases/download/v0.17.0/infer-linux64-v0.17.0.tar.xz && \
   tar -xf infer-linux64-v0.17.0.tar.xz -C /opt/ && \
   ln -s "/opt/infer-linux64-v$VERSION/bin/infer" /usr/local/bin/infer
