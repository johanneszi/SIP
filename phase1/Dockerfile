FROM ubuntu
RUN apt-get update
RUN apt-get install -y git vim

WORKDIR /home
RUN git clone https://github.com/dyninst/dyninst.git

RUN apt-get install -y build-essential cmake libelf-dev libboost-all-dev zlib1g-dev gcc-multilib

WORKDIR /home/dyninst/build
RUN cmake /home/dyninst -DBUILD_RTLIB_32="ON"
RUN make
RUN make install

ENV LD_LIBRARY_PATH=/usr/local/lib/
ENV DYNINSTAPI_RT_LIB=/usr/local/lib/libdyninstAPI_RT_m32.so

WORKDIR /home/playground
RUN git clone https://github.com/johanneszi/SIP.git

WORKDIR /home/playground/SIP/phase1/dyninsttool
RUN make
