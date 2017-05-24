#include "llvm/Pass.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Instruction.h"
#include "llvm/Analysis/CallGraph.h"
#include "llvm/Analysis/CallGraphSCCPass.h"
#include "llvm/IR/Dominators.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/ADT/SCCIterator.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"

using namespace llvm;

namespace {
  struct SkeletonPass : public ModulePass {
    static char ID;
    SkeletonPass() : ModulePass(ID) {}
    
	// getAnalysisUsage - This pass requires the CallGraph.
    void getAnalysisUsage(AnalysisUsage &AU) const {
		AU.setPreservesAll();
		AU.addRequired<CallGraphWrapperPass>();
    }
    
    virtual bool runOnModule(Module &M) {
    	//CallGraph g = CallGraph(M);
    	
    	/*CallGraphWrapperPass *CGPass = getAnalysisIfAvailable<CallGraphWrapperPass>();
	    CallGraph *CG = CGPass ? &CGPass->getCallGraph() : nullptr;
	    if (CG == nullptr) {
	    	errs() << "ERROR: No CallGraph\n";
	    	return false;
	    }*/
	  /*
		for (auto i = CG->begin(), ie = CG->end(); i != ie; i++) {
			const Function *func = (*i).first;
			
			if (func != nullptr && func->size() != 0) {
				errs()<<"Function " << func->getName() << "\n";
			} else {
				errs()<<"Function is null or size is 0\n";
			}
			
			CallGraphNode *node = (*i).second.get();
			Function *func2 = node->getFunction();
			errs()<<node->size();
			if (func2 != nullptr) {
				errs()<<"Function2 is not null ";
				errs()<<"and size is: " << func2->size()  << "\n";
				if(func2->size() != 0) {
					errs()<<"Function2 " << func->getName() << "\n";
				}
			} else {
				errs()<<"Function is null\n";
			}
			
			
		}*/
		/*
      	for(auto &i : g) {
      		if (i.first != NULL) {
   				errs()<<"Function " << i.first->getName() << " references:\n";
      			for (const auto &j : *(i.second)) {
      				if (j.second != nullptr) {
      					errs()<<"\t"<<j.second->getFunction()->getName() << "\n";
      				}
      			}
      		}
      	}*/
      	for (Function &F : M) {
			if (F.getName().str() == "InterestingProcedure") {
			
				LLVMContext& Ctx = F.getContext();
				Constant* logFunc = F.getParent()->getOrInsertFunction("_Z5checkm", Type::getVoidTy(Ctx), Type::getInt64Ty(Ctx), NULL);
				
				Function *log = cast<Function>(logFunc);
				
				BasicBlock &block = F.front();
				Instruction &inst = block.front();
				IRBuilder<> builder(&inst);

			  	// Insert a call to our function.
			  	ConstantInt* args = builder.getInt64(42);
			  	builder.CreateCall(log, args);
			}
      	}
      	
      	return true;
    }
  };
}

char SkeletonPass::ID = 0;

// Automatically enable the pass.
// http://adriansampson.net/blog/clangpass.html
static void registerSkeletonPass(const PassManagerBuilder &,
                         legacy::PassManagerBase &PM) {
  	PM.add(new SkeletonPass());
}
static RegisterStandardPasses
  RegisterMyPass(PassManagerBuilder::EP_EnabledOnOptLevel0,
                 registerSkeletonPass);
        
        
