DYNINST_ROOT = /usr/local
PLATFORM = x86_64-unknown-linux2.4

ifeq ($(DYNINST_ROOT),)
$(error DYNINST_ROOT is not set)
endif

ifeq ($(PLATFORM),)
$(error PLATFORM is not set)
endif

SOURCE = src/
BUILD = build/

# These should point to where libelf and libdwarf are installed
LIBELF = /home/dyninst/build/libelf/lib
LIBDWARF = /home/dyninst/build/libdwarf/lib

DYNINST_INCLUDE = $(DYNINST_ROOT)/include
DYNINST_LIB = $(DYNINST_ROOT)/lib

CC = gcc
CCFLAGS = -g -Wall -m32

CXX = g++
CXXFLAGS = -g -Wall -std=c++11

MKDIR = mkdir -p $@

PROG = instroProtect InterestingProgram
TARGETS = $(addprefix $(BUILD), $(PROG))

.PHONY: directories

all: directories $(TARGETS)
directories: $(BUILD)

DYNINST_LIBS = -L$(DYNINST_LIB) \
			   -L$(LIBELF) -L$(LIBDWARF) \
			   -lcommon \
			   -ldwarf -lelf \
			   -ldyninstAPI \
			   -linstructionAPI \
			   -ldl

$(BUILD)InterestingProgram: $(SOURCE)InterestingProgram.c
	$(CC) $(CCFLAGS) -o $@ $^


$(BUILD)instroProtect: $(BUILD)instroProtect.o
	$(CXX) $(CXXFLAGS) -o $@ $^ -I$(DYNINST_INCLUDE) $(DYNINST_LIBS) 

$(BUILD):
	$(MKDIR)
	
$(BUILD)%.o: $(SOURCE)%.C
	$(CXX) $(CXXFLAGS) -I$(DYNINST_INCLUDE) -I$(LIBELF) -I$(LIBDWARF) -c $< -o $@
	
.PHONY: clean

clean: 
	rm -rf $(BUILD)*

