FROM ubuntu:16.04
# Install
RUN echo "deb http://apt.llvm.org/xenial/ llvm-toolchain-xenial-3.9 main\ndeb-src http://apt.llvm.org/xenial/ llvm-toolchain-xenial-3.9 main" >> /etc/apt/sources.list
RUN apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 15CF4D18AF4F7421 && apt-get update && apt-get -y --allow-unauthenticated install clang-3.9 clang-3.9-doc libclang-common-3.9-dev libclang-3.9-dev libclang1-3.9 libclang1-3.9-dbg libllvm-3.9-ocaml-dev libllvm3.9 libllvm3.9-dbg lldb-3.9 llvm-3.9 llvm-3.9-dev llvm-3.9-doc llvm-3.9-examples llvm-3.9-runtime clang-format-3.9 python-clang-3.9 libfuzzer-3.9-dev cmake build-essential git vim


#Modify the following lines as described in the guideline
WORKDIR "/home"
RUN git clone -b llvm-3.9 https://github.com/johanneszi/SIP.git
WORKDIR "/home/SIP/phase2/llvm-callpath-pass”

RUN apt-get install -y libssl-dev

#Build your library
RUN mkdir build
WORKDIR "/home/SIP/phase2/llvm-callpath-pass"
RUN make
