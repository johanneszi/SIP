FROM ubuntu:16.04

RUN echo "deb http://apt.llvm.org/trusty/ llvm-toolchain-trusty-3.9 main\ndeb-src http://apt.llvm.org/trusty/ llvm-toolchain-trusty-3.9 main\ndeb http://cz.archive.ubuntu.com/ubuntu trusty main universe" >> /etc/apt/sources.list

RUN apt-get update 

# Install llvm
RUN apt-get -y --allow-unauthenticated install clang-3.9 clang-3.9-doc libclang-common-3.9-dev libclang-3.9-dev libclang1-3.9 libclang1-3.9-dbg libllvm-3.9-ocaml-dev libllvm3.9 libllvm3.9-dbg lldb-3.9 llvm-3.9 llvm-3.9-dev llvm-3.9-doc llvm-3.9-examples llvm-3.9-runtime clang-format-3.9 python-clang-3.9 libfuzzer-3.9-dev

RUN apt-get -y install cmake build-essential git vim

WORKDIR /home/playground
RUN git clone https://github.com/johanneszi/SIP.git

WORKDIR /home/playground/SIP/phase2/llvm-pass-skeleton/build
RUN cmake ..
RUN make
 
