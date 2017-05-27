LLVM_INCLUDES = -I/usr/include/llvm

SOURCE = src/
BUILD = build/

CXX = g++

CXXFLAGS = -g -rdynamic -L/usr/lib/x86_64-linux-gnu/ -lssl -lcrypto
CXXFLAGS_LLVM = -fno-rtti -lssl -lcrypto -O3 $(LLVM_INCLUDES)

LLVM_CONFIG_COMMAND = \
		`/usr/bin/llvm-config --cxxflags --libs` \
		`/usr/bin/llvm-config --ldflags`

PROG = libCallPathAnalysisPass.so libcheck.o 
TARGETS = $(addprefix $(BUILD), $(PROG))

all: directories $(TARGETS)
	
.PHONY: directories
directories: 
	@ mkdir -p $(BUILD)

$(BUILD)%.o: $(SOURCE)%.C
	$(CXX) -c -std=c++11 $(CXXFLAGS) $^ -o $@

$(BUILD)%.o: $(SOURCE)%.cpp
	$(CXX) -c -fPIC -std=c++11 $(CXXFLAGS_LLVM) $(LLVM_CONFIG_COMMAND) $^ -o $@

$(BUILD)libCallPathAnalysisPass.so: $(BUILD)CallPathAnalysisPass.o 
	$(CXX) -std=c++11 $(CXXFLAGS_LLVM) -shared $(LLVM_CONFIG_COMMAND) $^ -o $@

.PHONY: clean
clean:
	@ rm -f $(BUILD)*.so
	@ rm -f $(BUILD)*.o
	@ rm -f $(BUILD)*.bc
	
