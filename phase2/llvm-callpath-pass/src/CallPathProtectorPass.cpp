#include "llvm/Pass.h"

#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/IRBuilder.h"

#include "llvm/Support/CommandLine.h"
#include "llvm/Analysis/CallGraph.h"
#include "llvm/Support/raw_ostream.h"

#include <algorithm>
#include <fstream>

#include "crypto.h"

#define WARNING "\033[43m\033[1mWARNING:\033[0m"
#define ERROR "\033[101m\033[1mERROR:\033[0m"

using namespace llvm;

namespace {
	typedef std::vector<std::vector<std::string> > VecInVec;

	const std::string CHECKFUNC = "check" , REPORTFUNC = "reporter";
	const std::vector<std::string> ENTRYPOINTS = { "main" };
	const std::string USAGE = "Specify file containing new line separated functions to protect.";

	const cl::opt<std::string> FILENAME("ff", cl::desc(USAGE.c_str()));
	const cl::opt<bool> VERBOSE ("vv", cl::desc("Outputs the LLMV generated CallGraph."));

	struct CallPathProtectorPass : public ModulePass {
		static char ID;
		Constant *checkFunction, *reportFunction;

		Type *ptrTy, *voidTy, *boolTy ; // These variables are to store the type instances for primitive types.

		std::vector<std::string> functionsToProtect;

		CallPathProtectorPass() : ModulePass(ID) {}

		bool doInitialization(Module &M) override;
		void getAnalysisUsage(AnalysisUsage &AU) const override;
		bool runOnModule(Module &M) override;

		VecInVec getCall(CallGraph *CG, StringRef func, std::vector<std::string> seen);
		VecInVec getCallGraphForFunction(CallGraph *CG, StringRef func);
		void insertProtect(Function *func, VecInVec paths);

		void dump(VecInVec callGraph, unsigned int tabs);
		std::vector<std::string> parseFunctionToProtect();
	};

	std::vector<std::string> CallPathProtectorPass::parseFunctionToProtect() {
		std::vector<std::string> functions;
		std::ifstream infile(FILENAME);

		std::string line;
		while (std::getline(infile, line)) {
			if (line == "") { continue; } // Skip empty lines
			functions.push_back(line);
		}

		// The user has to provide at least one function to protect
		if(functions.size() == 0) {
			errs() << USAGE << "\n";
			exit(1);
		}

		return functions;
	}

	bool CallPathProtectorPass::doInitialization(Module &M) {
		// Check if there is a function in the target program that conflicts
		// with the current set of functions
		if (M.getFunction(StringRef(CHECKFUNC)) != nullptr ||
			M.getFunction(StringRef(REPORTFUNC)) != nullptr) {
			errs() << ERROR << " The target program should not contain functions called"
				   << CHECKFUNC << " or " << REPORTFUNC << "\n";
			exit(1);
		}

		functionsToProtect = parseFunctionToProtect();

		/* store the type instances for primitive types */
		ptrTy = Type::getInt8PtrTy(M.getContext());
		voidTy = Type::getVoidTy(M.getContext());
		boolTy = Type::getInt1Ty(M.getContext());

		Type *argsTypes[2] = {ptrTy, boolTy};

		// Define check and report functions
		checkFunction = M.getOrInsertFunction(CHECKFUNC,
								FunctionType::get(boolTy, ArrayRef<Type *>(argsTypes), false));

		reportFunction = M.getOrInsertFunction(REPORTFUNC,
								FunctionType::get(voidTy, boolTy, false));

		return true;
	}


	// getAnalysisUsage - This pass requires the CallGraph.
	void CallPathProtectorPass::getAnalysisUsage(AnalysisUsage &AU) const {
		AU.setPreservesAll();
		AU.addRequired<CallGraphWrapperPass>();
	}

	bool CallPathProtectorPass::runOnModule(Module &M) {
		CallGraphWrapperPass *CGPass = getAnalysisIfAvailable<CallGraphWrapperPass>();
		CallGraph *CG = CGPass ? &CGPass->getCallGraph() : nullptr;
		if (CG == nullptr) {
			errs() << ERROR << " No CallGraph can be generated!\n";
			return false;
		}

		if (VERBOSE) {
			CG->dump();
		}

		// Traverse all functions which have to be protected
		for (auto funcName : functionsToProtect) {
			Function *func = M.getFunction(funcName);

			if (func == nullptr || func->size() <= 0) {
				errs() << WARNING << " Function " << funcName << " not found and will be skipped!\n";
				continue;
			}

			// Get all call paths for function
			VecInVec funcCallPaths = getCallGraphForFunction(CG, funcName);

			if (funcCallPaths.size() > 0) {
				errs() << "Inserting in function " << funcName << " with call paths:\n";
				dump(funcCallPaths, 1);
			} else {
				errs() << WARNING << " Function " << funcName << " is never called\n";
			}

			insertProtect(func, funcCallPaths);
		}

		return true;
	}

	void CallPathProtectorPass::insertProtect(Function *func, VecInVec paths) {
		Instruction *firstInst = &*(func->getEntryBlock().getFirstInsertionPt());
		IRBuilder<> builder(firstInst);

		// If the function is never called, call the report function
		if (paths.size() == 0) {
			Value *falseValue = builder.getInt1(false);
			builder.CreateCall(reportFunction, falseValue);
			return;
		}

		// Calculate hash for the first function's path
		std::string pathHash = sha256(paths.front());
		Value *hashStringPointer = builder.CreateGlobalStringPtr(pathHash);
		Value *start = builder.getInt1(false);

		// Build paramethers
		std::vector<Value *> args;
		args.push_back(hashStringPointer);
		args.push_back(start);

		// Insert function
		Value *function = builder.CreateCall(checkFunction, args);

		// Calculate hash for the other function's paths
		for (unsigned int i = 1; i < paths.size(); i++) {
			args.clear(); // delete the parameters in args vector

			pathHash = sha256(paths[i]);
			hashStringPointer = builder.CreateGlobalStringPtr(pathHash);

			args.push_back(hashStringPointer);
			args.push_back(function);

			function = builder.CreateCall(checkFunction, args);
		}

		// Finally, insert the report function
		builder.CreateCall(reportFunction, function);
	}

	VecInVec CallPathProtectorPass::getCall(CallGraph *CG, StringRef func, std::vector<std::string> seen) {
		VecInVec calls;
		VecInVec results;

		seen.push_back(func);

		// If we have found the entry node --> break
		if(std::find(ENTRYPOINTS.begin(), ENTRYPOINTS.end(), func) != ENTRYPOINTS.end()) {
			std::vector<std::string> call;
			call.push_back(func);
			calls.push_back(call);

			return calls;
		}

		for (const auto &caller : *CG) {
			const Function *callingFunction = caller.first;
			if (callingFunction == nullptr || callingFunction->isDeclaration()) { continue; }

			for (const auto &callee : *(caller.second.get())) {
				Function *calledFunction = callee.second->getFunction();

				if (calledFunction != nullptr && !calledFunction->isDeclaration() &&
				    calledFunction->size() != 0 && calledFunction->getName() == func) {

					// Check if we have already seen self to break circles
					if(std::find(seen.begin(), seen.end(), callingFunction->getName()) == seen.end()) {
						VecInVec oldCalls = getCall(CG, callingFunction->getName(), seen);
						calls.insert(calls.end(), oldCalls.begin(), oldCalls.end());

						break;
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

	VecInVec CallPathProtectorPass::getCallGraphForFunction(CallGraph *CG, StringRef func) {
		return getCall(CG, func, std::vector<std::string>());
	}

	void CallPathProtectorPass::dump(VecInVec callGraph, unsigned int tabs = 0) {
		for (auto callPath : callGraph) {
			int size = callPath.size();
			errs() << std::string("\t", tabs);
			for(int i = 0; i < size - 1; i++) {
				errs() << callPath[i] << " -> ";
			}
			errs() << callPath[size - 1] << "\n";
		}
	}
}

char CallPathProtectorPass::ID = 0;

RegisterPass<CallPathProtectorPass> X("callpath", "Call Path Protector Pass", false, false);
