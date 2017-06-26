#include "llvm/Pass.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Support/raw_ostream.h"

#include "input-dependency/InputDependencyAnalysis.h"

#include <string>
#include <vector>
#include <algorithm>
#include <fstream>
#include <random>
#include <ctime>
#include <limits>

#include <json/value.h>
#include <json/reader.h>

#define WARNING "\033[43m\033[1mWARNING:\033[0m "
#define ERROR "\033[101m\033[1mERROR:\033[0m "

using namespace llvm;
using std::vector;
using std::string;

namespace {
    const string PUTSFUNC = "puts", PRINTFFUNC = "printf";
    const static vector<unsigned> PROTECTEDINSTRUCTIONS = {Instruction::Load, Instruction::Store,
                                                           Instruction::ICmp, Instruction::Sub,
                                                           Instruction::Add};

    const static string USAGE = "Specify file containing configuration data!";
    const cl::opt<string> FILENAME("ff", cl::desc(USAGE.c_str()));

    struct OHProtectorPass : public ModulePass {
        // Variables
        static char ID;
        int numHashVariables = 0;
        int checksPerHashVariable = 0;
        double obfuscationLevel = 0;
        bool debug = false;

        Type *ptrTy, *voidTy, *int32Ty;
        Constant *putsFunction = nullptr, *printfFunction;

        vector<Instruction *> instToProtect, instToObfuscate;
        vector<GlobalVariable *> globals;
        vector<int> ids;

        std::random_device rd;

        OHProtectorPass() : ModulePass(ID) {}

        // Functions
        bool doInitialization(Module &M) override;
        bool runOnModule(Module &M) override;
        void getAnalysisUsage(AnalysisUsage &AU) const override;

        void insertGlobals(Module &M, int numHashVariables);
        void insertProtection(IRBuilder<> *builder, vector<Instruction *> instuctions, bool finalRun);
        void insertCheck(IRBuilder<> *builder, Instruction *inst, GlobalVariable *global, int id);
        void insertGuards(Module &M, IRBuilder<> *builder);
        void insertReportFunction(IRBuilder<> *builder);
        BinaryOperator* generateHashFunction(IRBuilder<> *builder, Value *operandOne, Value *operandTwo);

        template<typename T> vector<T *> twistGetPartFromVector(vector<T *> input, double percent);
        bool isPtrToPtr(Value *value);
        int generateHashVariableID();
        bool shouldProtect(Instruction *instruction);
        bool shouldInsertGuard();
        Json::Value parseJSONFromFile(string fileName);
        void parseConfiguration(string fileName);
    };

    bool OHProtectorPass::doInitialization(Module &M) {
        parseConfiguration(FILENAME);

        LLVMContext &ctx = M.getContext();

        ptrTy = Type::getInt8PtrTy(ctx);
        voidTy = Type::getVoidTy(ctx);
        int32Ty = Type::getInt32Ty(ctx);

        if (debug) {
            putsFunction = M.getOrInsertFunction(PUTSFUNC, FunctionType::get(voidTy, ptrTy, false));
        }

        Type *argsTypes[3] = {ptrTy, int32Ty, int32Ty};

        printfFunction = M.getOrInsertFunction(PRINTFFUNC, FunctionType::get(voidTy, ArrayRef<Type *>(argsTypes), false));

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

        // Save all input independent instructions which have to be protected
        // Inserting directly in this iteration would result in an endless loop since each hash function
        // insert would add loads, stores and add that would be protected afterwards adding the same again
        for (auto &F : M) {
            // No input dependency info for declarations
            if (F.isDeclaration()) {
                continue;
            }

            for (auto &B : F) {
                for (auto &I : B) {
                    // Only add instructions that should be protected (Load/Store/ICmp/Add/Sub) and that are not input dependent
                    if (shouldProtect(&I) && !input_dependency_info.isInputDependent(&I)) {
                        instToProtect.push_back(&I);
                    }
                }
            }
        }

        // Add hash functions to all instructions above
        insertProtection(&builder, instToProtect, false);

        // All added instructions are added to the vector instToObfuscate, the user can specify a percantage of those that should be protected additionally
        // Therefore the vector is randomly shuffled and protected
        vector<Instruction *> instToObfuscatePart = twistGetPartFromVector(instToObfuscate, obfuscationLevel);
        instToObfuscate.clear();

        insertProtection(&builder, instToObfuscatePart, true);

        // Insert asserts at random positions
        insertGuards(M, &builder);

        return true;
    }

    void OHProtectorPass::insertGuards(Module &M, IRBuilder<> *builder) {
        int checkCounter = 0;

        while (true) {
            for (auto &F : M) {
                if (F.isDeclaration()) {
                    continue;
                }

                for (auto &B : F) {
                    for (auto &I : B) {
                        // PHINode Instructions and the back of a block or terminators can not be used to split blocks which is done during checker insertion
                        if (!isa<PHINode>(I) && &I != &(I.getParent()->back()) && !I.isTerminator() && shouldInsertGuard()) {
                            builder->SetInsertPoint(&I);

                            GlobalVariable *currentGlobal = globals[checkCounter % numHashVariables];
                            int id = generateHashVariableID();
                            ids.push_back(id);

                            insertCheck(builder, &I, currentGlobal, id);

                            checkCounter++;

                            if (checkCounter >= numHashVariables * checksPerHashVariable) {
                                return;
                            }

                            // Since iterator get invalidated (SplitBlockAndInsertIfThen) skip the rest of this basic block
                            break;
                        }
                    }
                }
            }
        }
    }

    void OHProtectorPass::insertCheck(IRBuilder<> *builder, Instruction *inst, GlobalVariable *global, int id) {
        // Builds a call to printf which prints an ID and
        // the value of the corresponding hash
        LoadInst *loadGlobal = builder->CreateLoad(global);
        Value *idValue = builder->getInt32(id);
        Value *format = builder->CreateGlobalStringPtr("\n%d,%d\n");
        vector<Value *> args = {format, idValue, loadGlobal};
        builder->CreateCall(printfFunction, args);

        // Creates and injects assert
        // SplitBlockAndInsertIfThen invalidates the iterator this has to be considered while inserting the checkers
        Value *cmp = builder->CreateICmpEQ(loadGlobal, idValue);
        TerminatorInst *reportBlock = SplitBlockAndInsertIfThen(cmp, inst, false, nullptr, nullptr);

        // Finally, inserts report function
        builder->SetInsertPoint(reportBlock);
        insertReportFunction(builder);
    }

    void OHProtectorPass::insertProtection(IRBuilder<> *builder, vector<Instruction *> instuctions, bool finalRun) {
        std::mt19937 twister(rd());

        unsigned int globalsIndex = 0;
        GlobalVariable *currentGlobal;
        LoadInst *loadGlobal;
        Value *toCast;

        // For all instructions which will be protected
        for (auto *I : instuctions) {
            builder->SetInsertPoint(I->getNextNode());
            // load a global variable that can be
            currentGlobal = globals[globalsIndex];

            loadGlobal = builder->CreateLoad(currentGlobal);

            switch (I->getOpcode()) {
                case Instruction::Load: {
                    LoadInst *loadInst = dyn_cast<LoadInst>(I);
                    if (isPtrToPtr(loadInst->getPointerOperand())) {
                        continue;
                    }

                    // The value that has to be loaded is hashed
                    toCast = loadInst;
                    break;
                }
                case Instruction::Store: {
                    StoreInst *storeInst = dyn_cast<StoreInst>(I);
                    if (isPtrToPtr(storeInst->getPointerOperand())) {
                        continue;
                    }

                    // The value that has to be stored is hashed
                    toCast = builder->CreateLoad(storeInst->getPointerOperand());
                    break;
                }
                case Instruction::ICmp: {
                    // The result of the comparison is hashed
                    toCast = dyn_cast<ICmpInst>(I);
                    break;
                }
                case Instruction::Sub: case Instruction::Add: case Instruction::Xor: {
                    Value *firstOperand = I->getOperand(0);
                    Value *secondOperand = I->getOperand(1);

                    // An Additional Hash function is added since both operands should be hashed
                    toCast = generateHashFunction(builder, firstOperand, secondOperand);
                    break;
                }
                default:
                    errs() << ERROR << "Instruction type cannot be protected\n";
                    I->dump();
                    exit(1); // All defined instructions have to be protected!
            }
            
            Value *alloc = builder->CreateAlloca(int32Ty);
            Value *casted = builder->CreateIntCast(toCast, int32Ty, false);
            builder->CreateStore(casted, alloc);
            LoadInst *loadResult = builder->CreateLoad(alloc);
            BinaryOperator *hash = generateHashFunction(builder, loadResult, loadGlobal);
            StoreInst *storeGlobal = builder->CreateStore(hash, currentGlobal);
           
            if (I->getOpcode() == Instruction::ICmp) {
                LoadInst *loadResult = builder->CreateLoad(alloc);
                
                Instruction *nextBrInst = I;
                while (nextBrInst->getOpcode() != Instruction::Br) {
                    nextBrInst = nextBrInst->getNextNode();
                }
                 
                nextBrInst->setOperand(0, builder->CreateICmpNE(loadResult, builder->getInt32(0))); 
            }
            
            // Save inserted protection instruction to be protected in
            // one last run
            if (!finalRun) {
                instToObfuscate.push_back(loadGlobal);
                instToObfuscate.push_back(hash);
                instToObfuscate.push_back(storeGlobal);
            }

            globalsIndex++;
            if (globalsIndex >= globals.size()) {
                // shuffle all global variables to insert them randomly
                globalsIndex = 0;

                std::shuffle(globals.begin(), globals.end(), twister);
            }
        }
    }

    void OHProtectorPass::insertGlobals(Module &M, int numHashVariables) {
        string globalName = "";

        if (debug) {
            globalName = "veryglobalmuchsecure";
        }

        for (int i = 0; i < numHashVariables; i++) {
            GlobalVariable *global = new GlobalVariable(M, int32Ty, false, GlobalValue::CommonLinkage,
                                                        0, globalName);
            global->setAlignment(4);

            // Constant Definitions
            ConstantInt *constInt = ConstantInt::get(M.getContext(), APInt(32, 0));

            // Global Variable Definitions
            global->setInitializer(constInt);

            globals.push_back(global);
        }
    }

    void OHProtectorPass::insertReportFunction(IRBuilder<> *builder) {
        if (debug) {
            Value *corruptedString = builder->CreateGlobalStringPtr("Hash corrupted!");
            builder->CreateCall(putsFunction, corruptedString);
        }

        InlineAsm *corruptStack = InlineAsm::get(FunctionType::get(voidTy, false), "add $$0x10, %rsp", "", false);
        builder->CreateCall(corruptStack);
    }

    BinaryOperator* OHProtectorPass::generateHashFunction(IRBuilder<> *builder, Value *operandOne, Value *operandTwo) {
        int randNum = rand() % 2;
        // randomly add an Addition or a XOR as hash function
        if (randNum == 0) {
            return dyn_cast<BinaryOperator>(builder->CreateAdd(operandOne, operandTwo));
        }

        return dyn_cast<BinaryOperator>(builder->CreateXor(operandOne, operandTwo));
    }

    int OHProtectorPass::generateHashVariableID() {
        int generatedID;
        // creates a variable ID that can be used to find a checker for patching hash variables
        do {
            generatedID = rand() % 100000 + (std::numeric_limits<int>::max() - 100001);
        } while(std::find(ids.begin(), ids.end(), generatedID) != ids.end()); // unique

        return generatedID;
    }

    bool OHProtectorPass::shouldInsertGuard() {
        return rand() % 42 < 1;
    }

    bool OHProtectorPass::shouldProtect(Instruction *instruction) {
        unsigned int opCode = instruction->getOpcode();
        return std::find(PROTECTEDINSTRUCTIONS.begin(), PROTECTEDINSTRUCTIONS.end(), opCode) != PROTECTEDINSTRUCTIONS.end();
    }

    template<typename T>
    vector<T *> OHProtectorPass::twistGetPartFromVector(vector<T *> input, double percent) {
        // randomly shuffles a vetor and returns the first percentage of it
        std::mt19937 twister(rd());
        std::shuffle(input.begin(), input.end(), twister);

        typename vector<T *>::const_iterator first = input.begin();
        typename vector<T *>::const_iterator last = input.begin() + int(input.size() * percent);
        vector<T *> part(first, last);

        return part;
    }

    bool OHProtectorPass::isPtrToPtr(Value *value) {
        return value->getType()->getContainedType(0)->isPointerTy();
    }

    void OHProtectorPass::parseConfiguration(string fileName) {
        Json::Value config = parseJSONFromFile(fileName); // Parse config file

        numHashVariables = config["hashVariables"].asInt();
        checksPerHashVariable = config["checksPerHashVariable"].asInt();
        obfuscationLevel = config["obfuscationLevel"].asDouble();
        debug = config["debug"].asBool();

        if (numHashVariables < 1 || numHashVariables > 99 ||
            checksPerHashVariable <= 0 ||
            obfuscationLevel < 0 || obfuscationLevel > 1) {

            errs() << ERROR << "Not initialised correctly!\n";
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
