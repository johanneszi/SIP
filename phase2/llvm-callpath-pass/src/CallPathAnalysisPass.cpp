#include "llvm/Pass.h"

#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/IRBuilder.h"

#include "llvm/Support/CommandLine.h"
#include "llvm/Analysis/CallGraph.h"
#include "llvm/Support/raw_ostream.h"

#include <string>
#include <map>
#include <algorithm>
#include <openssl/sha.h>
#include <sstream>
#include <fstream>
#include <iomanip>

using namespace llvm;

namespace {
	const cl::opt<std::string> FileName("ff", cl::desc("File containing new line separated functions to protect."));
	const std::string CHECKFUNC = "check" , REPORTFUNC = "report";
	const std::vector<std::string> ENTRYPOINTS = {"main"};
	
	typedef std::vector<std::vector<std::string> > VecInVec;
	
	struct CallPathAnalysisPass : public ModulePass {
		static char ID;
		Constant *p_check, *p_report;
		
		Type *intTy, *ptrTy, *voidTy, *boolTy ; // These variables are to store the type instances for primitive types.
		
		std::vector<std::string> functionsToProtect;
		
		CallPathAnalysisPass() : ModulePass(ID) {}
		
		bool doInitialization(Module &M) override;
		void getAnalysisUsage(AnalysisUsage &AU) const override;
		bool runOnModule(Module &M) override;
		VecInVec getCall(CallGraph *CG, StringRef func, std::vector<std::string> seen);
		VecInVec getCallGraphForFunction(CallGraph *CG, StringRef func);
		void insertProtect(Function *func, VecInVec paths);
		void dump(VecInVec callGraph);
		
		
    };
    
    std::vector<std::string> parseFunctionToCheckNames() {
		std::vector<std::string> functions;
		std::ifstream infile(FileName);
		
		std::string line;
		while (std::getline(infile, line)) {
			if (line == "") { continue; } // Skip empty lines
			functions.push_back(line);
		}
	
		// The user has to provide at least one function to protect
		if(functions.size() == 0) {
			//usage();
		}
			
		return functions;
	}
    
    std::string sha256(std::vector<std::string> input) {
		unsigned char hash[SHA256_DIGEST_LENGTH];
		SHA256_CTX sha256;
		SHA256_Init(&sha256);
		
		for (auto function : input) {
			SHA256_Update(&sha256, function.c_str(), function.size());
		}
		
		SHA256_Final(hash, &sha256);
		std::stringstream ss;
		for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		    ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    	}
    
    	return ss.str();
	}
    
	bool CallPathAnalysisPass::doInitialization(Module &M) {
	/* check if there is a function in a target program that conflicts
		 * with the probe functions */	
		if (M.getFunction(StringRef(CHECKFUNC)) != nullptr) {
			errs() << "ERROR: Function " << CHECKFUNC << " already exists.\n";
			exit(1);
		} else if (M.getFunction(StringRef(REPORTFUNC)) != nullptr) {
			errs() << "ERROR: Function " << REPORTFUNC << " already exists.\n";
			exit(1);
		}

		functionsToProtect = parseFunctionToCheckNames();
		
		/* store the type instances for primitive types */
		intTy = Type::getInt32Ty(M.getContext());
		ptrTy = Type::getInt8PtrTy(M.getContext());
		voidTy = Type::getVoidTy(M.getContext());
		boolTy = Type::getInt1Ty(M.getContext());
		voidTy = Type::getVoidTy(M.getContext());
		
		Type *args_types[2];
		args_types[0] = ptrTy; //Type::getInt8PtrTy(*ctx);	
		args_types[1] = boolTy;
	
		p_check = M.getOrInsertFunction(CHECKFUNC, 
					FunctionType::get(boolTy, ArrayRef<Type *>(args_types), false));
		
		p_report = M.getOrInsertFunction(REPORTFUNC, 
					FunctionType::get(voidTy, boolTy, false)) ;
				
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
	  	for (auto funcName : functionsToProtect) {	
	  		Function *func = M.getFunction(funcName);
	  		
	  		if (func == nullptr || func->size() <= 0) {
	  			errs() << "WARNING: " << funcName << " not found and will be skipped!\n";
	  			continue;
	  		}
	  		
	  		VecInVec funcCallPaths = getCallGraphForFunction(CG, funcName);
	  		
	  		if (funcCallPaths.size() > 0) { 
	  			errs() << "Inserting in function " << funcName << " with call paths:\n";
	  			dump(funcCallPaths);
	  			insertProtect(func, funcCallPaths);
	  		} else {
	  			errs() << "WARNING: Function " << funcName << " is never called\n";
	  		}
	  	}
	  	
	  	return true;		
	  }
	  	
	 	
		
	void CallPathAnalysisPass::insertProtect(Function *func, VecInVec paths) {
		Instruction *firstInst = &*(func->getEntryBlock().getFirstInsertionPt());
		IRBuilder<> builder(firstInst);
		
		std::string hash = sha256(paths[0]);
		Value *strPtr = builder.CreateGlobalStringPtr(hash);
		
		Value *start = builder.getInt1(false);
		std::vector<Value *> args;
		args.push_back(strPtr);
		args.push_back(start);
		
		Value *function = builder.CreateCall(p_check, args);
		
		
		for (unsigned int i = 1; i < paths.size(); i++) {
			args.clear();
			hash = sha256(paths[i]);
			strPtr = builder.CreateGlobalStringPtr(hash);
			
			args.push_back(strPtr);
			args.push_back(function);
			function = builder.CreateCall(p_check, args);
		}
		
		builder.CreateCall(p_report, function);
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

