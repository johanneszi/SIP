FROM ubuntu
RUN apt-get update
RUN apt-get install -y git
RUN cd /home/
RUN git clone https://github.com/dyninst/dyninst.git
RUN apt-get install -y cmake
RUN apt-get install -y build-essential
RUN apt-get install -y libboost1.58-all-dev
RUN apt-get install -y zlib1g-dev
WORKDIR /dyninst
RUN cmake .
RUN make
RUN make install

