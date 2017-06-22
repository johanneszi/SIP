#include "llvm/Pass.h"

#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"

#include "llvm/Support/raw_ostream.h"

#include "input-dependency/InputDependencyAnalysis.h"

#include <string>
#include <vector>
#include <algorithm>
#include <fstream>
#include <random>
#include <ctime>

#include <json/value.h>
#include <json/reader.h>

#define WARNING "\033[43m\033[1mWARNING:\033[0m "
#define ERROR "\033[101m\033[1mERROR:\033[0m "

using namespace llvm;
using std::vector;
using std::string;

namespace {
    const string PUTSFUNC = "puts";
    const static vector<unsigned> PROTECTEDINSTRUCTIONS = {Instruction::Load, Instruction::Store,
                                                           Instruction::ICmp, Instruction::Sub,
                                                           Instruction::Add};

    const static string USAGE = "Specify file containing configuration file!";
    const cl::opt<string> FILENAME("ff", cl::desc(USAGE.c_str()));

    struct OHProtectorPass : public ModulePass {
        // Variables
        static char ID;
        int numHashVariables = 0;
        bool verbose = false;

        Type *ptrTy, *voidTy, *int32Ty;
        Constant *putsFunction = nullptr;

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
        void insertProtection(IRBuilder<> *builder, vector<Instruction *> instuctions, bool finalRun);
        void insertReportFunction(IRBuilder<> *builder);
        BinaryOperator* generateHashFunction(IRBuilder<> *builder, Value *operandOne, Value *operandTwo);

        template<typename T> vector<T *> twistGetPartFromVector(vector<T *> input, double procent);
        bool isPtrToPtr(Value *value);
        Json::Value parseJSONFromFile(string fileName);
        void parseConfiguration(string fileName);
    };

    bool OHProtectorPass::doInitialization(Module &M) {
        parseConfiguration(FILENAME);

        LLVMContext &ctx = M.getContext();

        ptrTy = Type::getInt8PtrTy(ctx);
        voidTy = Type::getVoidTy(ctx);
        int32Ty = Type::getInt32Ty(ctx);

        if (verbose) {
            putsFunction = M.getOrInsertFunction(PUTSFUNC, FunctionType::get(voidTy, ptrTy, false));
        }

        srand(time(0));

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

        insertProtection(&builder, instToProtect, false);

        vector<Instruction *> instToObfuscatePart = twistGetPartFromVector(instToObfuscate, 0.2);
        instToObfuscate.clear();

        insertProtection(&builder, instToObfuscatePart, true);

        return true;
    }

    void OHProtectorPass::insertProtection(IRBuilder<> *builder, vector<Instruction *> instuctions, bool finalRun) {
        std::mt19937 twister(rd());

        unsigned int globalsIndex = 0;
        GlobalVariable *currentGlobal;
        LoadInst *loadGlobal;
        Value *toCast;

        for (auto *I : instuctions) {
            builder->SetInsertPoint(I->getNextNode());
            currentGlobal = globals[globalsIndex];

            loadGlobal = builder->CreateLoad(currentGlobal);

            switch (I->getOpcode()) {
                case Instruction::Load: {
                    LoadInst *loadInst = dyn_cast<LoadInst>(I);
                    if (isPtrToPtr(loadInst->getPointerOperand())) {
                        continue;
                    }

                    toCast = loadInst;
                    break;
                }
                case Instruction::Store: {
                    StoreInst *storeInst = dyn_cast<StoreInst>(I);
                    if (isPtrToPtr(storeInst->getPointerOperand())) {
                        continue;
                    }

                    toCast = builder->CreateLoad(storeInst->getPointerOperand());
                    break;
                }
                case Instruction::ICmp: {
                    toCast = dyn_cast<ICmpInst>(I);
                    break;
                }
                case Instruction::Sub: case Instruction::Add: case Instruction::Xor: {
                    Value *firstOperand = I->getOperand(0);
                    Value *secondOperand = I->getOperand(1);

                    toCast = generateHashFunction(builder, firstOperand, secondOperand);
                    break;
                }
                default:
                    errs() << ERROR << "Instruction type cannot be protected\n";
                    I->dump();
                    exit(1);
            }

            Value *casted = builder->CreateIntCast(toCast, int32Ty, false);
            BinaryOperator *hash = generateHashFunction(builder, casted, loadGlobal);
            StoreInst *storeGlobal = builder->CreateStore(hash, currentGlobal);

            if (!finalRun) {
                instToObfuscate.push_back(loadGlobal);
                instToObfuscate.push_back(hash);
                instToObfuscate.push_back(storeGlobal);
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
            GlobalVariable *global = new GlobalVariable(M, int32Ty, false, GlobalValue::CommonLinkage,
                                                        0, "veryglobalmuchsecure");
            global->setAlignment(4);

            // Constant Definitions
            ConstantInt *constInt = ConstantInt::get(M.getContext(), APInt(32, 0));

            // Global Variable Definitions
            global->setInitializer(constInt);

            globals.push_back(global);
        }
    }

    void OHProtectorPass::insertReportFunction(IRBuilder<> *builder) {
        if (verbose) {
            Value *corruptedString = builder->CreateGlobalStringPtr("Hash corrupted!");
            builder->CreateCall(putsFunction, corruptedString);
        }

        InlineAsm *corruptStack = InlineAsm::get(FunctionType::get(voidTy, false), "add $$0x10, %rsp", "", false);
        builder->CreateCall(corruptStack);
    }

    BinaryOperator* OHProtectorPass::generateHashFunction(IRBuilder<> *builder, Value *operandOne, Value *operandTwo) {
        int randNum = rand() % 2;

        if (randNum == 0) {
            return dyn_cast<BinaryOperator>(builder->CreateAdd(operandOne, operandTwo));
        }

        return dyn_cast<BinaryOperator>(builder->CreateXor(operandOne, operandTwo));
    }

    bool OHProtectorPass::shouldProtect(Instruction *instruction) {
        unsigned int opCode = instruction->getOpcode();
        return std::find(PROTECTEDINSTRUCTIONS.begin(), PROTECTEDINSTRUCTIONS.end(), opCode) != PROTECTEDINSTRUCTIONS.end();
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

    bool OHProtectorPass::isPtrToPtr(Value *value) {
        return value->getType()->getContainedType(0)->isPointerTy();
    }

    void OHProtectorPass::parseConfiguration(string fileName) {
        Json::Value config = parseJSONFromFile(fileName); // Parse config file

        numHashVariables = config["hashVariables"].asInt();
        verbose = config["verbose"].asBool();

        if (numHashVariables < 1 || numHashVariables > 99) {
            errs() << ERROR << "Not initialised correctly! Number of hash variables"
                            << "should be between 1 and 99!\n";
            exit(1);
        }
    }

    Json::Value OHProtectorPass::parseJSONFromFile(string fileName) {
        Json::Value root;
        Json::Reader reader;

        std::ifstream file(fileName);

        if (!file.good()) {
            errs() << ERROR << "File " << fileName << " could not be found!\n";
            exit(1);
        }

        bool parsingSuccessful = reader.parse(file, root, false);

        if (!parsingSuccessful) {
            errs()  << WARNING << "Failed to parse file " << fileName << " correctly!\n"
                    << reader.getFormattedErrorMessages() << "\n";
        }

        file.close();

        return root;
    }
}

char OHProtectorPass::ID = 0;

RegisterPass<OHProtectorPass> X("OHProtect", "Oblivious Hashing Protector Pass", false, false);
