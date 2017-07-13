FROM ubuntu:16.04

# Add llvm 3.9 sources (based on http://apt.llvm.org/)
RUN echo "deb http://apt.llvm.org/xenial/ llvm-toolchain-xenial-3.9 main" >> /etc/apt/sources.list && \
    echo "deb-src http://apt.llvm.org/xenial/ llvm-toolchain-xenial-3.9 main" >> /etc/apt/sources.list && \
    apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 15CF4D18AF4F7421

# Install dependencies and llvm 3.9
RUN apt-get update && apt-get install -y \
    bc bison \
    build-essential \
    cmake \
    curl flex \
    git \
    gcc-multilib \
    jq \
    libelf-dev \
    libboost-all-dev libcap-dev libncurses5-dev \
    libffi-dev libssl-dev \
    locales \
    nano \
    python-minimal python3 python3.5-dev python3-pip \
    python2.7 python-pip python-dev \
    subversion \
    sudo \
    vim \
    unzip \
    zlib1g-dev \
    clang-3.9 clang-3.9-doc clang-format-3.9 \
    libclang-common-3.9-dev libclang-3.9-dev libclang1-3.9 libclang1-3.9-dbg \
    libllvm-3.9-ocaml-dev libllvm3.9 libllvm3.9-dbg \
    lldb-3.9 llvm-3.9 llvm-3.9-dev llvm-3.9-doc llvm-3.9-examples llvm-3.9-runtime \
    python-clang-3.9 libfuzzer-3.9-dev && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Specify locales
RUN locale-gen en_US.UTF-8
ENV LANG en_US.UTF-8
ENV LANGUAGE en_US:en
ENV LC_ALL en_US.UTF-8

WORKDIR /home/sip

# Install DynInst
RUN git clone --depth 1 --branch v9.3.2 https://github.com/dyninst/dyninst.git
COPY dyninst/dyninstAPI/src/ast.C  /home/sip/dyninst/dyninstAPI/src/ast.C
RUN mkdir -p /home/sip/dyninst/build && \
    cmake -H/home/sip/dyninst -B/home/sip/dyninst/build -DBUILD_RTLIB_32="ON" && \
    make -C /home/sip/dyninst/build -j 2 install

# Set runtime libraries
ENV LD_LIBRARY_PATH=/usr/local/lib/:$LD_LIBRARY_PATH
ENV DYNINSTAPI_RT_LIB=/usr/local/lib/libdyninstAPI_RT.so

# Add a non-root user
RUN useradd --create-home --shell /bin/bash sip && adduser sip sudo
RUN echo 'sip:sip' | chpasswd

# Build KLEE
RUN git clone --depth 1 https://github.com/tum-i22/klee-install.git && \
    mkdir -p build && \
    sh ./klee-install/ubuntu.sh /home/sip/build/

RUN git clone -b ktest-result --depth 1 https://github.com/tum-i22/macke-opt-llvm.git /home/sip/build/macke-opt-llvm && \
    make -C /home/sip/build/macke-opt-llvm -j 2 \
	LLVM_SRC_PATH=/home/sip/build/llvm \
	KLEE_BUILDDIR=/home/sip/build/klee/Release+Asserts \
	KLEE_INCLUDES=/home/sip/build/klee/include

# Install jsoncpp
RUN git clone --depth 1 --branch 1.8.1  https://github.com/open-source-parsers/jsoncpp.git && \
    mkdir -p /home/sip/jsoncpp/build && \
    cmake -H/home/sip/jsoncpp -B/home/sip/jsoncpp/build && \
    make -C /home/sip/jsoncpp/build -j 2 install

# Install radare2
RUN git clone --depth 1 https://github.com/radare/radare2.git && \
    sh /home/sip/radare2/sys/install.sh

# Install r2pipe and psutil
RUN pip3 install --upgrade pip && \
    pip3 install --upgrade r2pipe && \
    pip3 install --upgrade psutil

# Install pwntools
RUN pip install --upgrade pip && \
    pip install --upgrade pwntools

# Copy input-dependency pass files
COPY input-dependency-pass/include/ /usr/local/include/
COPY input-dependency-pass/lib/ /usr/local/lib/

# Copy dataset files
COPY dataset/ /home/sip/dataset

# Copy cfi default protection and install
COPY defaultProtection /home/sip/defaultProtection
RUN mkdir -p /home/sip/defaultProtection/cfi/build && \
    cmake -H/home/sip/defaultProtection/cfi -B/home/sip/defaultProtection/cfi/build && \
    make -C /home/sip/defaultProtection/cfi/build -j 2

# Install self-checking default protection
RUN git clone --depth 1 https://github.com/anahitH/self-checksumming.git /home/sip/defaultProtection/self-checksumming && \
    mkdir -p /home/sip/defaultProtection/self-checksumming/build && \
    cmake -H/home/sip/defaultProtection/self-checksumming -B/home/sip/defaultProtection/self-checksumming/build && \
    make -C /home/sip/defaultProtection/self-checksumming/build -j 2

# Install oblivious hashing default protection
RUN git clone --depth 1 https://github.com/djwessel/introspection-oblivious-hashing.git /home/sip/defaultProtection/introspection-oblivious-hashing && \
    mkdir -p /home/sip/defaultProtection/introspection-oblivious-hashing/build && \
    cmake -H/home/sip/defaultProtection/introspection-oblivious-hashing -B/home/sip/defaultProtection/introspection-oblivious-hashing/build && \
    make -C /home/sip/defaultProtection/introspection-oblivious-hashing/build -j 2

# Switch to user
RUN chown -R sip:sip /home/sip
USER sip

# Set up project repo
RUN git clone https://github.com/johanneszi/SIP.git && \
    make -C /home/sip/SIP/phase1/dyninsttool -j 2 && \
    make -C /home/sip/SIP/phase2/llvm-callpath-pass -j 2 && \
    make -C /home/sip/SIP/phase3/stins4llvm -j 2 && \
    make -C /home/sip/SIP/phase4/ohprottool -j 2
