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

using namespace std;
using namespace Dyninst;

// Create an instance of class BPatch
BPatch bpatch;

// Uncomment this if you want to stop type checking
// on BPatch snippets
//bpatch.setTypeChecking(false);

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

template<typename T>
void releaseBPatchVectorContents(BPatch_Vector<T *> vector) {
	for (auto *element : vector)
      		delete element;
    
    vector.clear();  	
    vector.shrink_to_fit();
} 

std::set<BPatch_basicBlock *> getBasicBlocksForFunction(BPatch_function *function) {
	BPatch_flowGraph *fg = function->getCFG();
	std::set<BPatch_basicBlock *> blocks; 
	fg->getAllBasicBlocks(blocks);
	
	return blocks;
}

BPatch_funcCallExpr* createReportFunctionSnippet(BPatch_addressSpace* app) {
	BPatch_image* appImage = app->getImage();
	
	// Find the printf function
    std::vector<BPatch_function*> printfFuncs;
    appImage->findFunction("print", printfFuncs);
    
    if (printfFuncs.size() == 0) {
        fprintf(stderr, "Could not find printf\n");
    }

	std::vector<BPatch_snippet*> printfArgs;
    BPatch_snippet* fmt = new BPatch_constExpr("Hash corrupted!\n");
    printfArgs.push_back(fmt);
        
    // Construct a function call snippet
    BPatch_funcCallExpr *printfCall = new BPatch_funcCallExpr(*(printfFuncs[0]), printfArgs);
    
    return printfCall;
}

BPatch_Vector<BPatch_snippet *> createCheckerSnippet(BPatch_addressSpace* app, char correctHash, 
													unsigned long startAddress, unsigned long size,
													BPatch_binOp hashFunction = BPatch_plus,
													char hashStartValue = 0) {
	BPatch_image* appImage = app->getImage();
	
	// Holds all created snippets
	BPatch_Vector<BPatch_snippet *> checkerSnippet;
	
	BPatch_variableExpr* counter = 
        app->malloc(*(appImage->findType("unsigned long")), "counter");
    
    BPatch_variableExpr* result = 
        app->malloc(*(appImage->findType("char")), "result");
        	
    BPatch_variableExpr* correctHashConst = 
        app->malloc(*(appImage->findType("char")), "correctHashConst");
        
    // couter = startAddress 
    BPatch_arithExpr *assignCounter = new BPatch_arithExpr(BPatch_assign,
    									*counter, BPatch_constExpr(startAddress));
    
    // result = 0									
    BPatch_arithExpr *assignResult = new BPatch_arithExpr (BPatch_assign,
    									*result, BPatch_constExpr(hashStartValue));
    						
    // correctHashConst = 0									
    BPatch_arithExpr *assignCorrectHashConst = new BPatch_arithExpr (BPatch_assign,
   										*correctHashConst, BPatch_constExpr(correctHash));
    								
    									
   	checkerSnippet.push_back(assignCounter);
   	checkerSnippet.push_back(assignResult);
   	checkerSnippet.push_back(assignCorrectHashConst);
  	
  	BPatch_Vector<BPatch_snippet *> whileBody;
	
	// result + currentByte
	BPatch_arithExpr *addByte = new BPatch_arithExpr(hashFunction, *result, BPatch_arithExpr(BPatch_deref, *counter));
	
	// result = result + currentByte
  	BPatch_arithExpr *hash = new BPatch_arithExpr(BPatch_assign, *result, *addByte);
  	
  	// count++
  	BPatch_arithExpr *countPlus = new BPatch_arithExpr(BPatch_plus, BPatch_constExpr(1), *counter);
  	
  	// count = count + 1
  	BPatch_arithExpr *count = new BPatch_arithExpr(BPatch_assign, *counter, *countPlus);
  	
  	// Add the created instructions to whileBody
  	whileBody.push_back(hash);
  	whileBody.push_back(count);
   
   	// counter < endAddress
   	BPatch_boolExpr *counterLEndAddress = new BPatch_boolExpr(BPatch_lt, *counter, BPatch_constExpr(startAddress + size));
   	
   	// while(counter < endAddress) { whileBody }
   	BPatch_whileExpr *whileHash = new BPatch_whileExpr(*counterLEndAddress, BPatch_sequence(whileBody));
    				
    checkerSnippet.push_back(whileHash);
    
    // create report function snippet
    BPatch_funcCallExpr *printfCall = createReportFunctionSnippet(app);
    
    // if ( result != correctHash) { report (); }
    BPatch_ifExpr *checkHash = new BPatch_ifExpr(
					BPatch_boolExpr(BPatch_ne, *result, *correctHashConst), 
					*printfCall);
 	
 	checkerSnippet.push_back(checkHash);
      	
 	return checkerSnippet;
}

unsigned long computeHash(BPatch_basicBlock *block, unsigned long (*hashFunction)(std::vector<unsigned long>)) {
	std::vector<Dyninst::InstructionAPI::Instruction::Ptr> insns; 
	block->getInstructions(insns);

	std::vector<Dyninst::InstructionAPI::Instruction::Ptr>::iterator instr_iter;
	std::vector<unsigned long> instValues;
	
	for (instr_iter = insns.begin(); instr_iter != insns.end(); ++instr_iter) {
		Dyninst::InstructionAPI::Instruction::Ptr inst = *instr_iter; 

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
    
    BPatch_image *appImage = app->getImage();
	std::vector<BPatch_function *> funcs; 
	appImage->findFunction("InterestingProcedure", funcs);
    std::set<BPatch_basicBlock *> blocks = getBasicBlocksForFunction(funcs[0]);
    
    std::set<BPatch_basicBlock *>::iterator block_iter;
	for (block_iter = blocks.begin(); block_iter != blocks.end(); ++block_iter) {
		BPatch_basicBlock *block = *block_iter; 
		// Choose a hashFunction
		
		// Calculate right hash
		char correctHash = 0x6c;//computeHash(block, *hashAdd);
		cout<<hex<<block->getStartAddress()<<" "<< block->getEndAddress()<<" "<< block->size()<<endl;
		
		// Generate snippet
		BPatch_Vector<BPatch_snippet *> checkerSnippet = 
			createCheckerSnippet(app, correctHash, 0x810017b, block->size());
		
		// Insert the snippet
    	if (!app->insertSnippet(BPatch_sequence(checkerSnippet), *(block->findEntryPoint()))) {
      	  	fprintf(stderr, "insertSnippet failed\n");
      	}
      	releaseBPatchVectorContents(checkerSnippet);
	}

    // Finish instrumentation 
    const char* progName2 = "build/InterestingProgram-rewritten";
    finishInstrumenting(app, progName2);
}

