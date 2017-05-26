# Setting some variables and commands for compilaten
LLVM_INCLUDES = -I/usr/include/llvm

CXX = g++
CXXFLAGS_LLVM = -fno-rtti -O3 $(LLVM_INCLUDES)

LLVM_CONFIG_COMMAND = \
		`/usr/bin/llvm-config --cxxflags --libs` \
		`/usr/bin/llvm-config --ldflags`

all: libSkeleton.so

%.o: %.cpp
	$(CXX) -c -fPIC -std=c++11 $(CXXFLAGS_LLVM) $(LLVM_CONFIG_COMMAND) $^ -o $@

libSkeleton.so: Skeleton.o 
	$(CXX) -std=c++11 $(CXXFLAGS_LLVM) -shared $(LLVM_CONFIG_COMMAND) $^ -o $@

.PHONY: clean
clean:
	@ rm -f *.so
	@ rm -f *.o
