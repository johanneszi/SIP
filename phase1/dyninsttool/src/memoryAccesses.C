#include <stdio.h>
#include <stdlib.h>

#include "BPatch.h"
#include "BPatch_addressSpace.h"
#include "BPatch_process.h"
#include "BPatch_binaryEdit.h"
#include "BPatch_point.h"
#include "BPatch_function.h"
#include "BPatch_flowGraph.h"
#include "Instruction.h"

#define BYTE 8

using namespace std;
using namespace Dyninst;

// Create an instance of class BPatch
BPatch bpatch;
std::vector<unsigned char (*)(std::vector<unsigned char>)> hashFunctions;


// Different ways to perform instrumentation
typedef enum {
    create,
    attach,
    open
} accessType_t; 

// Attach, create, or open a file for rewriting
BPatch_addressSpace* startInstrumenting(accessType_t accessType,
        const char* name,
        int pid,
        const char* argv[]) {
    BPatch_addressSpace* handle = NULL;

    switch(accessType) {
        case create:
            handle = bpatch.processCreate(name, argv);
            if (!handle) { fprintf(stderr, "processCreate failed\n"); }
            break;
        case attach:
            handle = bpatch.processAttach(name, pid);
            if (!handle) { fprintf(stderr, "processAttach failed\n"); }
            break;
        case open:
            // Open the binary file; do not open dependencies
            handle = bpatch.openBinary(name, false);
            if (!handle) { fprintf(stderr, "openBinary failed\n"); }
            break;
    }

    return handle;
}

std::set<BPatch_basicBlock *> getBasicBlocksForFunction(BPatch_function *function) {
	BPatch_flowGraph *fg = function->getCFG();
	std::set<BPatch_basicBlock *> blocks; 
	fg->getAllBasicBlocks(blocks);
	
	return blocks;
}

void checker(unsigned char (*hashFunction)(std::vector<unsigned char>), unsigned char correctHash, 
				unsigned long long startAddress, unsigned long long endAddress) {
	
	std::vector<unsigned char> instValues;
	for (unsigned long long i = startAddress; i < endAddress; i++) {
		instValues.push_back(*i);
	}
	
	unsigned char newHash = hashFunction(instValues);
	if (newHash != correctHash) {
		report();
	}					
} 

void report() {
	//Kill them all
	puts("Hash was incoreect!");
}

unsigned char hashAdd(std::vector<unsigned char> insts) {
	unsigned char hash = 0x2a;
	std::vector<unsigned charg>::iterator instr_iter;
	
	for (instr_iter = insts.begin(); instr_iter != insts.end(); ++instr_iter) {
		unsigned char current = *instr_iter;
		hash += current;
	}
	
	return hash;
}

unsigned char hashXor(std::vector<unsigned char> insts) {
	unsigned char hash = 0x45;
	std::vector<unsigned char>::iterator instr_iter;
	
	for (instr_iter = insts.begin(); instr_iter != insts.end(); ++instr_iter) {
		unsigned char current = *instr_iter;
		hash ^= current;
	}
	
	return hash;
}

unsigned char computeHash(BPatch_basicBlock *block, unsigned char (*hashFunction)(std::vector<unsigned char>)) {
	std::vector<Dyninst::InstructionAPI::Instruction::Ptr> insns; 
	block->getInstructions(insns);

	std::vector<Dyninst::InstructionAPI::Instruction::Ptr>::iterator instr_iter;
	std::vector<unsigned char> instValues;
	
	for (instr_iter = insns.begin(); instr_iter != insns.end(); ++instr_iter) {
		Dyninst::InstructionAPI::Instruction::Ptr inst = *instr_iter; 
		for (unsigned int i = 0; i < inst->size(); i++) {			
			instValues.push_back(inst->rawByte(i));
		}
	}
	
	return hashFunction(instValues);
}

bool insertChecker(BPatch_basicBlock *block) {
	int index = rand() % hashFunctions.size();
	
	
}

void finishInstrumenting(BPatch_addressSpace* app, const char* newName) {
    BPatch_process* appProc = dynamic_cast<BPatch_process*>(app);
    BPatch_binaryEdit* appBin = dynamic_cast<BPatch_binaryEdit*>(app);

    if (appProc) {
        if (!appProc->continueExecution()) {
            fprintf(stderr, "continueExecution failed\n");
        }
        while (!appProc->isTerminated()) {
            bpatch.waitForStatusChange();
        }
    } else if (appBin) {
        if (!appBin->writeFile(newName)) {
            fprintf(stderr, "writeFile failed\n");
        }
    }
}

int main() {
    // Set up information about the program to be instrumented
    const char* progName = "build/InterestingProgram";
    int progPID = 42;
    const char* progArgv[] = {"InterestingProgram", "-h", NULL};
    accessType_t mode = create;

    // Create/attach/open a binary
    BPatch_addressSpace* app = 
        startInstrumenting(mode, progName, progPID, progArgv);
    if (!app) {
        fprintf(stderr, "startInstrumenting failed\n");
        exit(1);
    }
    
    hashFunctions.push_back(*hashAdd, *hashXor);
    
    BPatch_image *appImage = app->getImage();
	std::vector<BPatch_function *> funcs; 
	appImage->findFunction("InterestingProcedure", funcs);
    std::set<BPatch_basicBlock *> blocks = getBasicBlocksForFunction(funcs[0]);
    
    std::set<BPatch_basicBlock *>::iterator block_iter;
	for (block_iter = blocks.begin(); block_iter != blocks.end(); ++block_iter) {
		BPatch_basicBlock *block = *block_iter; 
		cout<<hex<<computeHash(block, *hashAdd)<<endl;
	}

   	
    
    // Finish instrumentation 
    const char* progName2 = "InterestingProgram-rewritten";
    finishInstrumenting(app, progName2);
    
    return 0;
}

