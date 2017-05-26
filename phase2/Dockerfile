FROM ubuntu:16.04

RUN apt-get update && apt-get -y install wget cmake build-essential git vim nano libffi-dev python

WORKDIR /home/llvm
COPY ./llvm-4.0.0.src.tar.xz /home/llvm
COPY ./cfe-4.0.0.src.tar.xz /home/llvm
COPY ./compiler-rt-4.0.0.src.tar.xz /home/llvm
RUN tar -xf llvm-4.0.0.src.tar.xz

WORKDIR /home/llvm/llvm-4.0.0.src
RUN tar -xf ../cfe-4.0.0.src.tar.xz -C tools && \
	tar -xf ../compiler-rt-4.0.0.src.tar.xz -C projects && \
	mv tools/cfe-4.0.0.src tools/clang && \
	mv projects/compiler-rt-4.0.0.src projects/compiler-rt

WORKDIR /home/llvm/llvm-4.0.0.src/build
RUN CC=gcc CXX=g++ \
	cmake -DCMAKE_INSTALL_PREFIX=/usr \
      -DLLVM_ENABLE_FFI=ON  \
      -DCMAKE_BUILD_TYPE=Release \
      -DLLVM_BUILD_LLVM_DYLIB=ON \
      -DLLVM_TARGETS_TO_BUILD="host;AMDGPU" \
      -Wno-dev .. && \
	make -j 2 && make install
