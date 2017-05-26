#include "llvm/Pass.h"

#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/CFG.h"

#include "llvm/Analysis/CallGraph.h"
#include "llvm/Analysis/CallGraphSCCPass.h"

#include "llvm/Transforms/Utils/BasicBlockUtils.h"

#include "llvm/Support/raw_ostream.h"
#include "llvm/ADT/SCCIterator.h"

#include <string>
#include <map>
#include <algorithm>

using namespace llvm;

const std::string CHECKFUNC = "check";
const std::vector<std::string> ENTRYPOINTS = {"main"};

namespace {
  struct SkeletonPass : public ModulePass {
    static char ID;
    Constant * p_check ;
    
    Type *intTy, *ptrTy, *voidTy, *boolTy ; // These variables are to store the type instances for primitive types.
    std::map<std::string, std::vector<std::string> > funcCallGraph;
    
    SkeletonPass() : ModulePass(ID) {}
    
    virtual bool doInitialization(Module &M) {
    	/* check if there is a function in a target program that conflicts
			 * with the probe functions */	
		if (M.getFunction(StringRef(CHECKFUNC)) != nullptr) {
			errs() << "Error: function " << CHECKFUNC << " already exists.\n";
			exit(1);
		}
    
    	/* store the type instances for primitive types */
		intTy = Type::getInt32Ty(M.getContext());
		ptrTy = Type::getInt8PtrTy(M.getContext());
		voidTy = Type::getVoidTy(M.getContext());
		boolTy = Type::getInt1Ty(M.getContext());
		voidTy = Type::getVoidTy(M.getContext());
    	
		Type *args_types[2];
		//args_types[0] = ptrTy; //Type::getInt8PtrTy(*ctx) ;	
		args_types[0] = intTy;
		args_types[1] = boolTy;
		
		//args_types[0] = structTy_class_std_vector;
		
    	p_check = M.getOrInsertFunction(CHECKFUNC, 
					FunctionType::get(boolTy, ArrayRef<Type *>(args_types), false)) ;
					
		return true;
    }
    
    
	// getAnalysisUsage - This pass requires the CallGraph.
    void getAnalysisUsage(AnalysisUsage &AU) const {
		AU.setPreservesAll();
		AU.addRequired<CallGraphWrapperPass>();
    }
    
    virtual bool runOnModule(Module &M) {    	
    	CallGraphWrapperPass *CGPass = getAnalysisIfAvailable<CallGraphWrapperPass>();
	    CallGraph *CG = CGPass ? &CGPass->getCallGraph() : nullptr;
	    if (CG == nullptr) {
	    	errs() << "ERROR: No CallGraph\n";
	    	return false;
	    }
	  	
	  	getCallGraphForFunction(CG, "InterestingProcedure");
      	/* Add a function call to check at the beginning of function*/
    	Function * func = M.getFunction(StringRef("InterestingProcedure"));
		if (func != nullptr && func->size() > 0) {
			Instruction *firstInst = &*(func->getEntryBlock().getFirstInsertionPt());
			IRBuilder<> builder(firstInst);
			
			Value *start = builder.getInt1(false);
			std::vector<Value *> args;
			args.push_back(builder.getInt32(42));
			args.push_back(start);
			
			Value *function = builder.CreateCall(p_check, args) ;
			int i = 3;
			for(i; i>0; i--){
				std::vector<Value *> args;
				args.push_back(builder.getInt32(40));
				args.push_back(function);
				function = builder.CreateCall(p_check, args) ;
			}
		}
		
      	return true;		
    }
    
    std::vector<std::vector<std::string> > getCall(CallGraph *CG, StringRef func, std::vector<std::string> seen) {
    	std::vector<std::vector<std::string> > calls;
    	std::vector<std::vector<std::string> > results;
    	
    	if(std::find(ENTRYPOINTS.begin(), ENTRYPOINTS.end(), func) != ENTRYPOINTS.end()) {
    		std::vector<std::string> call;
    		call.push_back(func);
    		calls.push_back(call);
    		
    		return calls;
    	}
    	
    	for (const auto &caller : *CG) {
    		const Function *callingFunction = caller.first;
    		if (callingFunction == nullptr) { continue; }
			
    		for (const auto &callee : *(caller.second.get())) {
    			Function *calledFunction = callee.second->getFunction();
    			
    			if (calledFunction != nullptr && calledFunction->size() != 0 && calledFunction->getName() == func) {
					if(std::find(seen.begin(), seen.end(), callingFunction->getName()) == seen.end()) {
						seen.push_back(callingFunction->getName());
						std::vector<std::vector<std::string> > oldCalls = getCall(CG, callingFunction->getName(), seen);				
						calls.insert(std::end(calls), std::begin(oldCalls), std::end(oldCalls));
					}
    			}
    		}
    	}
    	
    	for (auto vec : calls) {
    		vec.push_back(func);
    		results.push_back(vec);
    	}
    	
    	return results;
    }
    
    void getCallGraphForFunction(CallGraph *CG, StringRef func) {
    	std::vector<std::vector<std::string> > vec = getCall(CG, func, std::vector<std::string>());
    	for (auto vec1 : vec) {
    		for(auto val : vec1) {
    			errs() << val << " -> ";
    		}	
   			errs()<<"\n";	
    	}
    	
    }
    
    virtual bool doFinalization(Module &M) {
    	
		return true;
	}
  };
}

char SkeletonPass::ID = 0;
/*
static void registerSkeletonPass(const PassManagerBuilder &,
                           PassManagerBase &PM) {
    PM.add(new SkeletonPass());
}
static RegisterStandardPasses
    RegisterMyPass(PassManagerBuilder::EP_EnableOnOptLevel0,
                   registerSkeletonPass);


*/

RegisterPass<SkeletonPass> X("skeleton", "Skeleton Pass", false, false);
/*
static RegisterStandardPasses
    RegisterPass(PassManagerBuilder::EP_EnableOnOptLevel0,
                   registerPass);
         */
