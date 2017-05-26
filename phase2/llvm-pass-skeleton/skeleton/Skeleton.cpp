#include "llvm/Pass.h"

#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/CFG.h"

#include "llvm/Analysis/CallGraph.h"
#include "llvm/Analysis/CallGraphSCCPass.h"

#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"

#include "llvm/Support/raw_ostream.h"
#include "llvm/ADT/SCCIterator.h"

#include <string>
#include <map>

using namespace llvm;

const std::string CHECKFUNC = "check";

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
    	
    	FunctionType *fty = FunctionType::get(voidTy, false) ;
    	Type *args_types[1] ;
		//args_types[0] = ptrTy; //Type::getInt8PtrTy(*ctx) ;	
		
		LLVMContext& llvmContext = M.getContext();
		StructType *structTy_class_std_vector = M.getTypeByName("class.std::vector");
		if (!structTy_class_std_vector) {
     		structTy_class_std_vector = StructType::create(llvmContext, "class.std::vector");
		}
		
		args_types[0] = structTy_class_std_vector;
		
    	p_check = M.getOrInsertFunction(CHECKFUNC, 
					FunctionType::get(voidTy, ArrayRef<Type *>(args_types), false)) ;
					
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
	  	
	  	unsigned sccNum = 0;
  		errs() << "SCCs for the program in PostOrder:";
  		
  		for (scc_iterator<CallGraph*> SCCI = scc_begin(CG); !SCCI.isAtEnd(); ++SCCI) {
    		const std::vector<CallGraphNode*> &nextSCC = *SCCI;
    		errs() << "\nSCC #" << ++sccNum << " : ";
    
    		for (std::vector<CallGraphNode*>::const_iterator I = nextSCC.begin(), E = nextSCC.end(); I != E; ++I) {
      			Function *func = (*I)->getFunction();
      			
      			if (func != nullptr) {
      				errs() << func->getName() << ", ";;
      			} else {
      				errs() << "external node" << ", ";
      			}
      		}
  		}
  		
  		errs() << "\n";
	  	
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
			
			
		}
		
      	for(auto &i : g) {
      		if (i.first != NULL) {
   				errs()<<"Function " << i.first->getName() << " references:\n";
      			for (const auto &j : *(i.second)) {
      				if (j.second != nullptr) {
      					errs()<<"\t"<<j.second->getFunction()->getName() << "\n";
      				}
      			}
      		}
      	} */
      	
      	return false;		
    }
    
    virtual bool doFinalization(Module &M) {
    	/* Add a function call to check at the beginning of function*/
    	Function * func = M.getFunction(StringRef("InterestingProcedure"));
		if (func != nullptr && func->size() > 0) {
			Instruction *firstInst = &*(func->getEntryBlock().getFirstInsertionPt());
			IRBuilder<> builder(firstInst);
			
			ConstantInt* args = builder.getInt64(42);
			builder.CreateCall(p_check, args) ;
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
         
