FROM ubuntu
RUN apt-get update
RUN apt-get install -y git vim

WORKDIR /home
RUN git clone https://github.com/dyninst/dyninst.git

RUN apt-get install -y build-essential cmake libelf-dev libboost-all-dev zlib1g-dev gcc-multilib

COPY ./ast.C /home/dyninst/dyninstAPI/src

WORKDIR /home/dyninst/build
RUN cmake /home/dyninst -DBUILD_RTLIB_32="ON"
RUN make
RUN make install

ENV LD_LIBRARY_PATH=/usr/local/lib/:$LD_LIBRARY_PATH
ENV DYNINSTAPI_RT_LIB=/usr/local/lib/libdyninstAPI_RT.so

WORKDIR /home
RUN git clone https://github.com/radare/radare2
WORKDIR /home/radare2
RUN sys/install.sh

RUN apt-get install -y python3 python3-pip
RUN pip3 install r2pipe

WORKDIR /home/playground
RUN git clone https://github.com/johanneszi/SIP.git

WORKDIR /home/playground/SIP/phase1/dyninsttool
RUN make

WORKDIR /home
