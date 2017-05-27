LLVM_INCLUDES = -I/usr/include/llvm

MERKLETREE_ROOT = /home/zhechev/Developer/SIP/phase2/merkle-tree/
MERKLETREE_INCLUDE = $(MERKLETREE_ROOT)src/

SOURCE = src/
BUILD = build/

MKDIR = 

CXX = g++

CXXFLAGS = -g -rdynamic
CXXFLAGS_LLVM = -fno-rtti -O3 $(LLVM_INCLUDES)

LLVM_CONFIG_COMMAND = \
		`/usr/bin/llvm-config --cxxflags --libs` \
		`/usr/bin/llvm-config --ldflags`

PROG = libCallPathAnalysisPass.so libcheck.o 
TARGETS = $(addprefix $(BUILD), $(PROG))

all: merkletree directories $(TARGETS)

.PHONY: merkletree
merkletree: 
	$(MAKE) -C $(MERKLETREE_ROOT) release
	
.PHONY: directories
directories: 
	@ mkdir -p $(BUILD)

$(BUILD)%.o: $(SOURCE)%.C
	$(CXX) -I$(MERKLETREE_INCLUDE) -c -std=c++11 $(CXXFLAGS) $^ -o $@

$(BUILD)%.o: $(SOURCE)%.cpp
	$(CXX) -c -fPIC -std=c++11 $(CXXFLAGS_LLVM) $(LLVM_CONFIG_COMMAND) $^ -o $@

$(BUILD)libCallPathAnalysisPass.so: $(BUILD)CallPathAnalysisPass.o 
	$(CXX) -std=c++11 $(CXXFLAGS_LLVM) -shared $(LLVM_CONFIG_COMMAND) $^ -o $@

.PHONY: clean
clean:
	@ rm -f $(BUILD)*.so
	@ rm -f $(BUILD)*.o
	@ rm -f $(BUILD)*.bc
	@ $(MAKE) -C $(MERKLETREE_ROOT) --no-print-directory clean
	
