LLVM_INCLUDES = -I/usr/include/llvm-3.9

SOURCE = src/
BUILD = build/

CXX = g++
CXXFLAGS = -g -rdynamic
CXXFLAGS_LLVM = -fno-rtti -O3 $(LLVM_INCLUDES)

LLVM_CONFIG_COMMAND = \
		`/usr/bin/llvm-config-3.9 --cxxflags --libs` \
		`/usr/bin/llvm-config-3.9 --ldflags`

PROG = libOHProtectorPass.so
TARGETS = $(addprefix $(BUILD), $(PROG))

all: directories $(TARGETS)

.PHONY: directories
directories:
	@ mkdir -p $(BUILD)

$(BUILD)%.o: $(SOURCE)%.cpp
	$(CXX) -c -fPIC -std=c++11 $(CXXFLAGS) $(CXXFLAGS_LLVM) $(LLVM_CONFIG_COMMAND) $^ -o $@

$(BUILD)libOHProtectorPass.so: $(BUILD)OHProtectorPass.o
	$(CXX) $(CXXFLAGS) $(CXXFLAGS_LLVM) -shared $(LLVM_CONFIG_COMMAND) $^ -o $@

.PHONY: clean
clean:
	@ rm -f $(BUILD)*.so
	@ rm -f $(BUILD)*.o
	@ rm -f $(BUILD)*.bc
