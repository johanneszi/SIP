#include "llvm/Pass.h"

#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/IRBuilder.h"

#include "llvm/Support/raw_ostream.h"

#include "input-dependency/InputDependencyAnalysis.h"

#include <string>
#include <vector>
#include <algorithm>

#include <json/value.h>
#include <json/reader.h>
#include <json/writer.h>

#define WARNING "\033[43m\033[1mWARNING:\033[0m "
#define ERROR "\033[101m\033[1mERROR:\033[0m "

using namespace llvm;
using std::vector;
using std::string;

namespace {
    struct OHProtectorPass : public ModulePass {
        // Variables
        static char ID;
        bool verbose = false;

        Type *boolTy, *voidTy;

        OHProtectorPass() : ModulePass(ID) {}

        // Functions
        bool doInitialization(Module &M) override;
        bool runOnModule(Module &M) override;
        void getAnalysisUsage(AnalysisUsage &AU) const override;
    };

    bool OHProtectorPass::doInitialization(Module &M) {
        LLVMContext &ctx = M.getContext();

        boolTy = Type::getInt1Ty(ctx);
        voidTy = Type::getVoidTy(ctx);

        return false;
    }

    void OHProtectorPass::getAnalysisUsage(AnalysisUsage &AU) const {
        AU.setPreservesAll();
        AU.addRequired<input_dependency::InputDependencyAnalysis>();
    }

    bool OHProtectorPass::runOnModule(Module &M) {
        const auto &input_dependency_info = getAnalysis<input_dependency::InputDependencyAnalysis>();


        LLVMContext &ctx = M.getContext();
        IRBuilder<> builder(ctx);
        Constant *printmeCond = M.getOrInsertFunction("printmeCond",
                                        FunctionType::get(Type::getInt32Ty(ctx), Type::getInt32Ty(ctx), false));

        for (auto &F : M) {
            // No input dependency info for declarations
            if (F.isDeclaration()) {
                continue;
            }

            for (auto &B : F) {
                for (auto &I : B) {
                    if (input_dependency_info.isInputDependent(&I)) {
                        continue;
                    }

                    errs() << "Instruction: " << I << " is input independent\n";
                    switch (I.getOpcode()) {
                        case Instruction::Load: {
                            //errs() << I.getOpcodeName() << "\n";
                            auto *instruction = dyn_cast<LoadInst>(&I);
                            Value *memory = instruction->getPointerOperand();

                            Type *type = memory->getType();
                            Type *content = type->getContainedType(0);

                            if(content->isPointerTy()) {
                                continue;
                            }

                            Constant *printme = M.getOrInsertFunction("printme",
                                                        FunctionType::get(Type::getVoidTy(ctx), Type::getInt32Ty(ctx), false));

                            //IRBuilder<> builder(I.getNextNode());
                            //memory = builder.CreatePtrToInt(memory, Type::getInt32Ty(ctx));
                            //builder.CreateCall(printme, memory);

                            break;
                        }
                        case Instruction::Store: {
                            //errs() << I.getOpcodeName() << "\n";
                            break;
                        }
                        case Instruction::ICmp: {
                            //errs() << I.getOpcodeName() << "\n";

                            auto *instruction = dyn_cast<ICmpInst>(&I);


                            builder.SetInsertPoint(I.getNextNode());
                            //IRBuilder<> builder(I.getNextNode());

                            //builder.CreateCall(printmeCond, hash);

                            break;
                        }
                        case Instruction::Br: {
                            //errs() << I.getOpcodeName() << "\n";
                            auto *instruction = dyn_cast<BranchInst>(&I);
                            if (instruction->isConditional()) {
                                Value *cond = instruction->getCondition();

                                Constant *printmeCond = M.getOrInsertFunction("printmeCond",
                                                            FunctionType::get(Type::getVoidTy(ctx), Type::getInt64Ty(ctx), false));


                                //IRBuilder<> builder(I.getNextNode());

                                //builder.CreateCall(printmeCond, cond);

                            }

                            break;
                        }
                        case Instruction::Add: {
                            //errs() << I.getOpcodeName() << "\n";
                            break;
                        }

                        default:
                            break;
                    }
                }
            }
        }

        return false;
    }
}

char OHProtectorPass::ID = 0;

RegisterPass<OHProtectorPass> X("OHProtect", "Oblivious Hashing Protector Pass", false, false);
