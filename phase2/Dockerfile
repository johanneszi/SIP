FROM ubuntu:16.04

RUN apt-get update && apt-get install -y \
	build-essential \
	cmake \
	git \
	libffi-dev \
	libssl-dev \
	nano \
	python \
	vim \
	wget \
 && rm -rf /var/lib/apt/lists/*

# Download and set up of LLVM 
WORKDIR /home/llvm
RUN wget http://llvm.org/releases/4.0.0/llvm-4.0.0.src.tar.xz && \
	wget http://llvm.org/releases/4.0.0/cfe-4.0.0.src.tar.xz && \
	wget http://llvm.org/releases/4.0.0/compiler-rt-4.0.0.src.tar.xz && \
	tar -xf llvm-4.0.0.src.tar.xz && \
	tar -xf cfe-4.0.0.src.tar.xz -C llvm-4.0.0.src/tools && \
	tar -xf compiler-rt-4.0.0.src.tar.xz -C llvm-4.0.0.src/projects && \
	mv llvm-4.0.0.src/tools/cfe-4.0.0.src llvm-4.0.0.src/tools/clang && \
	mv llvm-4.0.0.src/projects/compiler-rt-4.0.0.src llvm-4.0.0.src/projects/compiler-rt && \
	rm -f llvm-4.0.0.src.tar.xz cfe-4.0.0.src.tar.xz compiler-rt-4.0.0.src.tar.xz

# Build LLVM
WORKDIR /home/llvm/llvm-4.0.0.src/build
RUN CC=gcc CXX=g++ \
	cmake -DCMAKE_INSTALL_PREFIX=/usr \
      -DLLVM_ENABLE_FFI=ON  \
      -DCMAKE_BUILD_TYPE=Release \
      -DLLVM_BUILD_LLVM_DYLIB=ON \
      -DLLVM_TARGETS_TO_BUILD="host;AMDGPU" \
      -Wno-dev .. && \
	make -j 2 && make install

# Set up project repo
#WORKDIR /home
#RUN git clone https://github.com/johanneszi/SIP.git

#WORKDIR /home/SIP/phase2/llvm-callpath-pass
#RUN make	

