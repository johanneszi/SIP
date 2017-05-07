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
            handle = bpatch.openBinary(name, true);
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

/*
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
} */


std::vector<BPatch_snippet *> checkerSnippet(BPatch_addressSpace* app, BPatch_basicBlock *block, int hashFunction, 
					unsigned long correctHash, unsigned long startAddress, unsigned long endAddress) {
	
	
	std::vector<BPatch_snippet *> checkerSnippet;
	
	BPatch_image* appImage = app->getImage();
	
	BPatch_variableExpr* counter = 
        app->malloc(*(appImage->findType("unsigned long")), "counter");
        
    BPatch_variableExpr* currentByte = 
        app->malloc(*(appImage->findType("unsigned char")), "currentByte");
    
    BPatch_variableExpr* result = 
        app->malloc(*(appImage->findType("unsigned long")), "result");
        	
        
    // couter = startAddress 
    BPatch_arithExpr *assignCounter = new BPatch_arithExpr(BPatch_assign,
    									*counter, BPatch_constExpr(startAddress));
    
    // result = 0									
    BPatch_arithExpr *assignResult = new BPatch_arithExpr (BPatch_assign,
    									*result, BPatch_constExpr(0));
    									
    // currentByte = 0									
    //BPatch_arithExpr *assignCurrentByte = new BPatch_arithExpr (BPatch_assign,
    //									*currentByte, BPatch_constExpr(0));
      
    int zero = 42;
    currentByte->writeValue(&zero);
   	checkerSnippet.push_back(assignCounter);
   	checkerSnippet.push_back(assignResult);
  	
  	std::vector<BPatch_snippet *> whileBody;
	
	// currentByte = (unsigned char) *counter
	BPatch_arithExpr *getCurrentByte = new BPatch_arithExpr(BPatch_assign, *currentByte, BPatch_arithExpr(BPatch_deref, *counter));
	
	// result + currentByte
	BPatch_arithExpr *addByte = new BPatch_arithExpr(BPatch_plus, *result, *currentByte);
	
	// result = result + currentByte
  	BPatch_arithExpr *hash = new BPatch_arithExpr(BPatch_assign, *result, *addByte);
  	
  	// count++
  	BPatch_arithExpr *countPlus = new BPatch_arithExpr(BPatch_plus, BPatch_constExpr(1), *counter);
  	
  	// count = count + 1
  	BPatch_arithExpr *count = new BPatch_arithExpr(BPatch_assign, *counter, *countPlus);
  	
  	whileBody.push_back(getCurrentByte);
  	whileBody.push_back(hash);
  	whileBody.push_back(count);
   
   	// counter < endAddress
   	BPatch_boolExpr *counterLEndAddress = new BPatch_boolExpr(BPatch_lt, *counter, BPatch_constExpr(endAddress));
   	
   	// while(counter < endAddress) { whileBody }
   	BPatch_whileExpr *whileHash = new BPatch_whileExpr(*counterLEndAddress, BPatch_sequence(whileBody));
    				
    checkerSnippet.push_back(whileHash);
    
    
    // Find the printf function
    std::vector<BPatch_function*> printfFuncs;
    appImage->findFunction("printf", printfFuncs);
    if (printfFuncs.size() == 0) {
        fprintf(stderr, "Could not find printf\n");
    }

	std::vector<BPatch_snippet*> printfArgs;
    BPatch_snippet* fmt = 
        new BPatch_constExpr("Hash corrupted!\n");
    printfArgs.push_back(fmt);
        
        
    // Construct a function call snippet
    BPatch_funcCallExpr printfCall(*(printfFuncs[0]), printfArgs);
    
    BPatch_ifExpr *checkHash = new BPatch_ifExpr(
					BPatch_boolExpr(BPatch_ne, *result, BPatch_constExpr(correctHash)), 
					printfCall);
 	
 	checkerSnippet.push_back(checkHash);
 	
 	
 	if (!app->insertSnippet(BPatch_sequence(checkerSnippet), *(block->findEntryPoint()))) {
      	  fprintf(stderr, "insertSnippet failed\n");
    }
      	
 	return checkerSnippet;
}

void report() {
	//Kill them all
	puts("Hash was incoreect!");
}

unsigned long hashAdd(std::vector<unsigned long> insts) {
	unsigned long hash = 0;
	std::vector<unsigned long>::iterator instr_iter;
	
	for (instr_iter = insts.begin(); instr_iter != insts.end(); ++instr_iter) {
		unsigned long current = *instr_iter;
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

unsigned long computeHash(BPatch_basicBlock *block, unsigned long (*hashFunction)(std::vector<unsigned long>)) {
	std::vector<Dyninst::InstructionAPI::Instruction::Ptr> insns; 
	block->getInstructions(insns);

	std::vector<Dyninst::InstructionAPI::Instruction::Ptr>::iterator instr_iter;
	std::vector<unsigned long> instValues;
	
	for (instr_iter = insns.begin(); instr_iter != insns.end(); ++instr_iter) {
		Dyninst::InstructionAPI::Instruction::Ptr inst = *instr_iter; 
		if (inst)
		for (unsigned int i = 0; i < inst->size(); i++) {			
			instValues.push_back(inst->rawByte(i));
		}
	}
	
	return hashFunction(instValues);
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
            fprintf(stderr,"writeFile failed\n");
        }
    }
}

int main() {
    // Set up information about the program to be instrumented
    const char* progName = "build/InterestingProgram";
    int progPID = 42;
    const char* progArgv[] = {"InterestingProgram", "-h", NULL};
    accessType_t mode = open;

    // Create/attach/open a binary
    BPatch_addressSpace* app = 
        startInstrumenting(mode, progName, progPID, progArgv);
    if (!app) {
        fprintf(stderr, "startInstrumenting failed\n");
        exit(1);
    }
    //bpatch.setTypeChecking(false);
    //hashFunctions.push_back(*hashAdd, *hashXor);
    
    BPatch_image *appImage = app->getImage();
	std::vector<BPatch_function *> funcs; 
	appImage->findFunction("InterestingProcedure", funcs);
    std::set<BPatch_basicBlock *> blocks = getBasicBlocksForFunction(funcs[0]);
    
    std::set<BPatch_basicBlock *>::iterator block_iter;
	for (block_iter = blocks.begin(); block_iter != blocks.end(); ++block_iter) {
		BPatch_basicBlock *block = *block_iter; 
		unsigned long correctHash = 0xd7;//computeHash(block, *hashAdd);
		cout<<hex<<correctHash<<endl;
		std::vector<BPatch_snippet *> checkerSnipp = checkerSnippet(app, block, 0, 
					correctHash, 0x8100147, 0x8100159);
		
		//  Insert the snippet
    	//if (!app->insertSnippet(BPatch_sequence(checkerSnipp), *(block->findEntryPoint()))) {
      	  //fprintf(stderr, "insertSnippet failed\n");
      	//}
      	break;
	}

    // Finish instrumentation 
    const char* progName2 = "build/InterestingProgram-rewritten";
    finishInstrumenting(app, progName2);
}

