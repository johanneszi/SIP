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
#include <random>
#include <ctime>

#include <json/value.h>
#include <json/reader.h>
#include <json/writer.h>

#define WARNING "\033[43m\033[1mWARNING:\033[0m "
#define ERROR "\033[101m\033[1mERROR:\033[0m "

using namespace llvm;
using std::vector;
using std::string;

namespace {
    const static vector<unsigned> PROTECTEDINSTRUCTIONS = {Instruction::Load, Instruction::Store,
                                                           Instruction::ICmp, Instruction::Sub,
                                                           Instruction::Add};

    struct OHProtectorPass : public ModulePass {
        // Variables
        static char ID;
        int numHashVariables = 5;
        bool verbose = false;

        Type *boolTy, *voidTy, *int32Ty;
        vector<Instruction *> instToProtect, instToObfuscate;
        vector<GlobalVariable *> globals;

        std::random_device rd;

        OHProtectorPass() : ModulePass(ID) {}

        // Functions
        bool doInitialization(Module &M) override;
        bool runOnModule(Module &M) override;
        void getAnalysisUsage(AnalysisUsage &AU) const override;

        bool shouldProtect(Instruction *instruction);
        void insertGlobals(Module &M, int numHashVars);
        void insertProtection(Module &M, vector<Instruction *> instuctions, bool finalRun);
        BinaryOperator* generateHashFunction(IRBuilder<> *builder, Value *operandOne, Value *operandTwo);
        template<typename T>
        vector<T *> twistGetPartFromVector(vector<T *> input, double procent);
    };

    bool OHProtectorPass::doInitialization(Module &M) {
        LLVMContext &ctx = M.getContext();

        boolTy = Type::getInt1Ty(ctx);
        voidTy = Type::getVoidTy(ctx);
        int32Ty = Type::getInt32Ty(ctx);

        srand(time(0));

        return false;
    }

    void OHProtectorPass::getAnalysisUsage(AnalysisUsage &AU) const {
        AU.setPreservesAll();
        AU.addRequired<input_dependency::InputDependencyAnalysis>();
    }

    bool OHProtectorPass::runOnModule(Module &M) {
        const auto &input_dependency_info = getAnalysis<input_dependency::InputDependencyAnalysis>();

        insertGlobals(M, numHashVariables);

        // Save all input independent instructions which has to be protected
        for (auto &F : M) {
            // No input dependency info for declarations
            if (F.isDeclaration()) {
                continue;
            }

            for (auto &B : F) {
                for (auto &I : B) {
                    if (shouldProtect(&I) && !input_dependency_info.isInputDependent(&I)) {
                        instToProtect.push_back(&I);
                    }
                }
            }
        }

        insertProtection(M, instToProtect, false);

        vector<Instruction *> instToObfuscatePart = twistGetPartFromVector(instToObfuscate, 0.2);
        instToObfuscate.clear();

        insertProtection(M, instToObfuscatePart, true);

        return true;
    }

    template<typename T>
    vector<T *> OHProtectorPass::twistGetPartFromVector(vector<T *> input, double procent) {
        std::mt19937 twister(rd());
        std::shuffle(input.begin(), input.end(), twister);

        typename vector<T *>::const_iterator first = input.begin();
        typename vector<T *>::const_iterator last = input.begin() + int(input.size() * procent);
        vector<T *> part(first, last);

        return part;
    }

    bool OHProtectorPass::shouldProtect(Instruction *instruction) {
        unsigned opCode = instruction->getOpcode();
        return std::find(PROTECTEDINSTRUCTIONS.begin(), PROTECTEDINSTRUCTIONS.end(), opCode) != PROTECTEDINSTRUCTIONS.end();
    }

    BinaryOperator* OHProtectorPass::generateHashFunction(IRBuilder<> *builder, Value *operandOne, Value *operandTwo) {
        int randNum = rand() % 2;

        if (randNum == 0) {
            return dyn_cast<BinaryOperator>(builder->CreateAdd(operandOne, operandTwo));
        }

        return dyn_cast<BinaryOperator>(builder->CreateXor(operandOne, operandTwo));
    }

    void OHProtectorPass::insertProtection(Module &M, vector<Instruction *> instuctions, bool finalRun) {
        LLVMContext &ctx = M.getContext();
        IRBuilder<> builder(ctx);

        unsigned int globalsIndex = 0;
        std::mt19937 twister(rd());

        for (auto *I : instuctions) {

            switch (I->getOpcode()) {
                case Instruction::Load: {
                    auto *instruction = dyn_cast<LoadInst>(I);

                    Value *memory = instruction->getPointerOperand();
                    Type *type = memory->getType();
                    Type *content = type->getContainedType(0);

                    if(content->isPointerTy()) {
                        continue;
                    }

                    builder.SetInsertPoint(instruction->getNextNode());

                    LoadInst *loadGlobal = builder.CreateLoad(globals[globalsIndex]);
                    Value *casted = CastInst::CreateIntegerCast(instruction, int32Ty, false, "", loadGlobal->getNextNode());
                    BinaryOperator *hash = generateHashFunction(&builder, casted, loadGlobal);
                    StoreInst *storeGlobal = builder.CreateStore(hash, globals[globalsIndex]);

                    if (!finalRun) {
                        instToObfuscate.push_back(hash);
                        instToObfuscate.push_back(loadGlobal);
                        instToObfuscate.push_back(storeGlobal);
                    }

                    break;
                }
                case Instruction::Store: {
                    auto *instruction = dyn_cast<StoreInst>(I);

                    Value *memory = instruction->getPointerOperand();
                    Type *type = memory->getType();
                    Type *content = type->getContainedType(0);

                    if(content->isPointerTy()) {
                        continue;
                    }

                    builder.SetInsertPoint(instruction->getNextNode());

                    LoadInst *loadValue = builder.CreateLoad(memory);
                    LoadInst *loadGlobal = builder.CreateLoad(globals[globalsIndex]);
                    Value *casted = CastInst::CreateIntegerCast(loadValue, int32Ty, false, "", loadGlobal->getNextNode());

                    BinaryOperator *hash = generateHashFunction(&builder, casted, loadGlobal);
                    StoreInst *storeGlobal = builder.CreateStore(hash, globals[globalsIndex]);

                    if (!finalRun) {
                        instToObfuscate.push_back(hash);
                        instToObfuscate.push_back(loadGlobal);
                        instToObfuscate.push_back(storeGlobal);
                    }

                    break;
                }
                case Instruction::ICmp: {
                    auto *instruction = dyn_cast<ICmpInst>(I);

                    builder.SetInsertPoint(instruction->getNextNode());

                    LoadInst *loadGlobal = builder.CreateLoad(globals[globalsIndex]);
                    Value *casted = CastInst::CreateIntegerCast(instruction, int32Ty, false, "", loadGlobal->getNextNode());
                    BinaryOperator *hash = generateHashFunction(&builder, casted, loadGlobal);
                    StoreInst *storeGlobal = builder.CreateStore(hash, globals[globalsIndex]);

                    if (!finalRun) {
                        instToObfuscate.push_back(hash);
                        instToObfuscate.push_back(loadGlobal);
                        instToObfuscate.push_back(storeGlobal);
                    }

                    break;
                }
                case Instruction::Sub: case Instruction::Add: {
                    auto *instruction = dyn_cast<BinaryOperator>(I);

                    builder.SetInsertPoint(instruction->getNextNode());

                    LoadInst *loadGlobal = builder.CreateLoad(globals[globalsIndex]);

                    Value *firstOperand = instruction->getOperand(0);
                    firstOperand = CastInst::CreateIntegerCast(firstOperand, int32Ty, false, "", loadGlobal->getNextNode());
                    Value *secondOperand = instruction->getOperand(1);
                    secondOperand = CastInst::CreateIntegerCast(secondOperand, int32Ty, false, "", loadGlobal->getNextNode());

                    BinaryOperator *intermediateHash = generateHashFunction(&builder, firstOperand, loadGlobal);
                    BinaryOperator *hash = generateHashFunction(&builder, secondOperand, intermediateHash);
                    StoreInst *storeGlobal = builder.CreateStore(hash, globals[globalsIndex]);

                    if (!finalRun) {
                        instToObfuscate.push_back(intermediateHash);
                        instToObfuscate.push_back(hash);
                        instToObfuscate.push_back(loadGlobal);
                        instToObfuscate.push_back(storeGlobal);
                    }

                    break;
                }

                default:
                    break;
            }

            globalsIndex++;
            if (globalsIndex >= globals.size()) {
                globalsIndex = 0;

                std::shuffle(globals.begin(), globals.end(), twister);
            }
        }
    }

    void OHProtectorPass::insertGlobals(Module &M, int numHashVars) {
        for (int i = 0; i < numHashVars; i++) {
            GlobalVariable *global = new GlobalVariable(M, int32Ty, false, GlobalValue::CommonLinkage, 0, "veryglobalmuchsecure");
            global->setAlignment(4);

            // Constant Definitions
            ConstantInt *constInt = ConstantInt::get(M.getContext(), APInt(32, 0));

            // Global Variable Definitions
            global->setInitializer(constInt);

            globals.push_back(global);
        }
    }
}

char OHProtectorPass::ID = 0;

RegisterPass<OHProtectorPass> X("OHProtect", "Oblivious Hashing Protector Pass", false, false);
