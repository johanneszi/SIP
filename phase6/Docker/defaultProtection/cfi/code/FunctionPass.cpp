#include <stdio.h>
#include <sstream>
#include <fstream>
#include <stdlib.h>
#include "llvm/Pass.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/IR/TypeBuilder.h"

#include "llvm/IR/DebugInfo.h"

#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/LLVMContext.h"

#include "llvm/Support/CommandLine.h"

#include "Graph.h"

using namespace llvm;
using namespace std;

static cl::opt<string> InputSensitiveFcts("i",
	cl::desc("Specify filename containing the list of sensitive functions"),
	cl::value_desc("filename"));


void readInput(std::vector<std::string> *res) {
	std::ifstream ifs;
	std::string line;
	ifs.open(InputSensitiveFcts.c_str());

	while(std::getline(ifs, line)){
		res->push_back(line);
	}

	ifs.close();
	return;
}

namespace{
  struct OurFunctionPass : public FunctionPass {
	static char ID;
	Graph graph;
	vector<string> sensitiveList;
	OurFunctionPass() : FunctionPass(ID) {}

	virtual bool doInitialization(Module &M){
		graph = Graph();

		errs() << "Input: " << InputSensitiveFcts << "\n";
		readInput(&sensitiveList);
		for(auto iter = sensitiveList.begin(); iter < sensitiveList.end(); iter++) {
			errs() << "Sensitive: '" << *iter << "'\n";
		}
		errs() << "\n";
		return false;
	}

	virtual bool doFinalization(Module &M){
		graph.writeGraphFile();
		return false;
	}

	virtual bool runOnFunction(Function &function) {
		string funcName = function.getName().str();
		Vertex funcVertex = Vertex(funcName);
		bool first_instr = true;
		bool modified = false; // runOnFunction return value
		for (BasicBlock &block : function) {
			for (Instruction &instruction: block) {
				if(first_instr) {
					LLVMContext& Ctx = function.getContext();

					FunctionType *registerType = TypeBuilder<void(char *), false>::get(Ctx);
					Function* registerFunction = cast<Function>(function.getParent()->
						getOrInsertFunction("registerFunction", registerType));

					IRBuilder<> builder(&instruction);
					builder.SetInsertPoint(&block, builder.GetInsertPoint());

					Value *strPtr = builder.CreateGlobalStringPtr(funcName.c_str());
					Value *caller = builder.CreateCall(registerFunction, strPtr);
					DISubprogram *d = function.getSubprogram();
					DebugLoc loc = DebugLoc::get(0, 0, d);
					((Instruction *)caller)->setDebugLoc(loc);

					modified = true;
					first_instr = false;

					// Function is in the sensitive list
					if(find(sensitiveList.begin(), sensitiveList.end(), funcName) != sensitiveList.end()) {
						FunctionType *verifyType = TypeBuilder<void(), false>::get(Ctx);
						Function *verifyFunction = cast<Function>(function.getParent()->
							getOrInsertFunction("verifyStack", verifyType));

						// Insert call
						builder.SetInsertPoint(&block, builder.GetInsertPoint());
						Value *caller = builder.CreateCall(verifyFunction);
						DISubprogram *d = function.getSubprogram();
						DebugLoc loc = DebugLoc::get(0, 0, d);
						((Instruction *)caller)->setDebugLoc(loc);
					}
				}
				if (auto *callInstruction = dyn_cast<CallInst>(&instruction)) {
					Function *called = callInstruction->getCalledFunction();
					if(called) {
						string calledName = called->getName().str();
						Vertex calledVertex;
						if(find(sensitiveList.begin(), sensitiveList.end(), calledName) != sensitiveList.end()) {
							calledVertex = Vertex(calledName, true);
						} else {
							calledVertex = Vertex(calledName);
						}
						graph.addEdge(funcVertex, calledVertex);
					}
				}
				if(auto *callInstruction = dyn_cast<ReturnInst>(&instruction)) {
					LLVMContext& Ctx = function.getContext();

					FunctionType *registerType = TypeBuilder<void(char *), false>::get(Ctx);
					Function* deregisterFunction = cast<Function>(function.getParent()->
					getOrInsertFunction("deregisterFunction", registerType));

					IRBuilder<> builder(&instruction);
					builder.SetInsertPoint(&block, builder.GetInsertPoint());

					// Insert a call to our function.
					Value *strPtr = builder.CreateGlobalStringPtr(funcName.c_str());
					Value *caller = builder.CreateCall(deregisterFunction, strPtr);
					DISubprogram *d = function.getSubprogram();
					DebugLoc loc = DebugLoc::get(0, 0, d);
					((Instruction *)caller)->setDebugLoc(loc);

					modified = true;
				}
			}
		}
		return modified;
	}
  };
}
char OurFunctionPass::ID = 0;
static RegisterPass<OurFunctionPass> X("functionpass", "Function Pass", false, false);
