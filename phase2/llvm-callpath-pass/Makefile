LLVM_INCLUDES = -I/usr/include/llvm

SOURCE = src/
BUILD = build/

CXX = g++

CXXFLAGS = -g -rdynamic
CXXFLAGS_LLVM = -fno-rtti -rdynamic -O3 $(LLVM_INCLUDES)

LLVM_CONFIG_COMMAND = \
		`/usr/bin/llvm-config --cxxflags --libs` \
		`/usr/bin/llvm-config --ldflags`

PROG = crypto.o libCallPathProtectorPass.so libcheck.o 
TARGETS = $(addprefix $(BUILD), $(PROG))

all: directories $(TARGETS)
	
.PHONY: directories
directories: 
	@ mkdir -p $(BUILD)

$(BUILD)%.o: $(SOURCE)%.cpp
	$(CXX) -c -fPIC -std=c++11 $(CXXFLAGS_LLVM) $(LLVM_CONFIG_COMMAND) $^ -o $@

$(BUILD)libCallPathProtectorPass.so: $(BUILD)CallPathProtectorPass.o 
	$(CXX) -std=c++11 $(BUILD)crypto.o $(CXXFLAGS_LLVM) -shared $(LLVM_CONFIG_COMMAND) $^ -o $@

.PHONY: clean
clean:
	@ rm -f $(BUILD)*.so
	@ rm -f $(BUILD)*.o
	@ rm -f $(BUILD)*.bc
	
