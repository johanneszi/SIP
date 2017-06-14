FROM ubuntu:16.04

# Install some dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    jq \
    nano \
    python3 python3-pip \
    sudo \
    vim \
    wget && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Install llvm 3.9 (based on http://apt.llvm.org/)
RUN echo "deb http://apt.llvm.org/xenial/ llvm-toolchain-xenial-3.9 main" >> /etc/apt/sources.list && \
    echo "deb-src http://apt.llvm.org/xenial/ llvm-toolchain-xenial-3.9 main" >> /etc/apt/sources.list && \
    apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 15CF4D18AF4F7421

RUN apt-get update && apt-get install -y \
    clang-3.9 clang-3.9-doc clang-format-3.9 \
    libclang-common-3.9-dev libclang-3.9-dev libclang1-3.9 libclang1-3.9-dbg \
    libllvm-3.9-ocaml-dev libllvm3.9 libllvm3.9-dbg \
    lldb-3.9 llvm-3.9 llvm-3.9-dev llvm-3.9-doc llvm-3.9-examples llvm-3.9-runtime \
    python-clang-3.9 libfuzzer-3.9-dev && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Add a non-root user
RUN useradd --create-home --shell /bin/bash sip && adduser sip sudo
RUN echo 'sip:sip' | chpasswd
WORKDIR /home/sip

# Install radare2
RUN git clone --depth 1 https://github.com/radare/radare2.git && \
    sh /home/sip/radare2/sys/install.sh && \
    pip3 install r2pipe

# Install project dependencies
RUN git clone --depth 1 https://github.com/open-source-parsers/jsoncpp.git && \
    mkdir -p /home/sip/jsoncpp/build && \
    cmake -H/home/sip/jsoncpp -B/home/sip/jsoncpp/build && \
    make -C /home/sip/jsoncpp/build -j 2 install

# Copy input-dependency pass files
COPY input-dependency-pass/include/ /usr/local/include/
COPY input-dependency-pass/lib/ /usr/local/lib/

# Switch to user
RUN chown -R sip:sip .
USER sip

# Set up project repo
RUN git clone https://github.com/johanneszi/SIP.git
WORKDIR /home/sip/SIP/phase4/ohprottool
RUN make
