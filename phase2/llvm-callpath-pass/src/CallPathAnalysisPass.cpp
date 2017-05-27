#include "llvm/Pass.h"

#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/IRBuilder.h"

#include "llvm/Analysis/CallGraph.h"
#include "llvm/Support/raw_ostream.h"

#include <string>
#include <map>
#include <algorithm>

using namespace llvm;

namespace {
	const std::string CHECKFUNC = "check";
	const std::vector<std::string> ENTRYPOINTS = {"main"};
	
	typedef std::vector<std::vector<std::string> > VecInVec;
	
	struct CallPathAnalysisPass : public ModulePass {
		static char ID;
		Constant * p_check ;
		
		Type *intTy, *ptrTy, *voidTy, *boolTy ; // These variables are to store the type instances for primitive types.
		
		//TODO: Init this with funcs from file
		//TODO: Find some way to not init with empty vector
		std::map<std::string, VecInVec> CallPaths = {{"InterestingProcedure", VecInVec()} };
		
		CallPathAnalysisPass() : ModulePass(ID) {}
		
		bool doInitialization(Module &M) override;
		void getAnalysisUsage(AnalysisUsage &AU) const override;
		bool runOnModule(Module &M) override;
		VecInVec getCall(CallGraph *CG, StringRef func, std::vector<std::string> seen);
		VecInVec getCallGraphForFunction(CallGraph *CG, StringRef func);
		void dump(VecInVec callGraph);
    };
    
	bool CallPathAnalysisPass::doInitialization(Module &M) {
	/* check if there is a function in a target program that conflicts
		 * with the probe functions */	
		if (M.getFunction(StringRef(CHECKFUNC)) != nullptr) {
			errs() << "ERROR: Function " << CHECKFUNC << " already exists.\n";
			exit(1);
		}

		/* store the type instances for primitive types */
		intTy = Type::getInt32Ty(M.getContext());
		ptrTy = Type::getInt8PtrTy(M.getContext());
		voidTy = Type::getVoidTy(M.getContext());
		boolTy = Type::getInt1Ty(M.getContext());
		voidTy = Type::getVoidTy(M.getContext());
		
		Type *args_types[2];
		//args_types[0] = ptrTy; //Type::getInt8PtrTy(*ctx);	
		args_types[0] = intTy;
		args_types[1] = boolTy;
	
		//args_types[0] = structTy_class_std_vector;
	
		p_check = M.getOrInsertFunction(CHECKFUNC, 
					FunctionType::get(boolTy, ArrayRef<Type *>(args_types), false)) ;
				
		return true;
	}


	// getAnalysisUsage - This pass requires the CallGraph.
	void CallPathAnalysisPass::getAnalysisUsage(AnalysisUsage &AU) const {
		AU.setPreservesAll();
		AU.addRequired<CallGraphWrapperPass>();
	}
	
	bool CallPathAnalysisPass::runOnModule(Module &M) {    	
		CallGraphWrapperPass *CGPass = getAnalysisIfAvailable<CallGraphWrapperPass>();
		CallGraph *CG = CGPass ? &CGPass->getCallGraph() : nullptr;
		if (CG == nullptr) {
			errs() << "ERROR: No CallGraph\n";
			return false;
		}
	  	
	  	// Traverse all functions which have to be protected
	  	for (auto funcCallPath : CallPaths) {	
	  		std::string func = funcCallPath.first;
	  		if (M.getFunction(func) == nullptr) {
	  			errs() << "WARNING: " << func << " not found and will be skipped!\n";
	  			continue;
	  		}
	  		
	  		VecInVec funcCallPaths = getCallGraphForFunction(CG, func);
	  		CallPaths[func] = funcCallPaths;
	  	}
	  	
	  	
	 	dump(CallPaths["InterestingProcedure"]);
		
		
		// Add a function call to check at the beginning of function
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
			for(; i>0; i--){
				std::vector<Value *> args;
				args.push_back(builder.getInt32(40));
				args.push_back(function);
				function = builder.CreateCall(p_check, args) ;
			}
		}
	
	  	return true;		
	}
	
	VecInVec CallPathAnalysisPass::getCall(CallGraph *CG, StringRef func, std::vector<std::string> seen) {
		VecInVec calls;
		VecInVec results;
		
		// If we have found the entry node --> break
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
					
					// Check if we have already seen self to break circles 
					if(std::find(seen.begin(), seen.end(), callingFunction->getName()) == seen.end()) {
						seen.push_back(callingFunction->getName());
						VecInVec oldCalls = getCall(CG, callingFunction->getName(), seen);				
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
	
	VecInVec CallPathAnalysisPass::getCallGraphForFunction(CallGraph *CG, StringRef func) {
		return getCall(CG, func, std::vector<std::string>());
	}
		
	void CallPathAnalysisPass::dump(VecInVec callGraph) {
		for (auto callPath : callGraph) {
			int size = callPath.size();
			for(int i = 0; i < size - 1; i++) {
				errs() << callPath[i] << " -> ";
			}	
   			errs() << callPath[callPath.size() - 1] << "\n";	
		}		
	}
}

char CallPathAnalysisPass::ID = 0;

RegisterPass<CallPathAnalysisPass> X("callpath", "Call Path Analysis Pass", false, false);

