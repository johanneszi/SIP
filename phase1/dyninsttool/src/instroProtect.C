#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <algorithm>

#include "BPatch.h"
#include "BPatch_addressSpace.h"
#include "BPatch_process.h"
#include "BPatch_binaryEdit.h"
#include "BPatch_point.h"
#include "BPatch_function.h"
#include "BPatch_flowGraph.h"
#include "Instruction.h"
#include "InstructionCategories.h"

#define NUMBER_HASHFUNCTIONS 2

#include <boost/graph/adjacency_list.hpp>
#include <boost/graph/graphviz.hpp>

using namespace std;
using namespace Dyninst;

typedef BPatch_Vector<BPatch_snippet *> (hashFunction) (BPatch_addressSpace*, BPatch_variableExpr*,
													unsigned long, long, char);
													
hashFunction createHashFunctionAddSnippet;
hashFunction createHashFunctionSubSnippet;

// Create an instance of class BPatch
BPatch bpatch;

// Uncomment this if you want to stop type checking
// on BPatch snippets
//bpatch.setTypeChecking(false);

// Different ways to perform instrumentation
typedef enum {
    create,
    attach,
    open
} accessType_t;

typedef void (*BPatchDynLibraryCallback)(BPatch_thread *thr, BPatch_object *obj, bool loaded); 

// Network
struct Vertex{BPatch_basicBlock *block;};
struct Edge{std::string blah;};

typedef boost::adjacency_list<boost::setS, boost::vecS, boost::bidirectionalS, Vertex, Edge> Graph;
//typedef boost::graph_traits<Graph>::disallow_parallel_edges;
typedef boost::graph_traits<Graph>::vertex_descriptor vertex_t;
typedef boost::graph_traits<Graph>::edge_descriptor edge_t;

// Attach, create, or open a file for rewriting
BPatch_addressSpace* startInstrumenting(accessType_t accessType,
        const char* name,
        int pid,
        const char* argv[]) {
    BPatch_addressSpace* handle = NULL;

    switch(accessType) {
        case create:
            handle = bpatch.processCreate(name, argv);
            if (!handle) { fprintf(stderr, "processCreate failed\n"); }
            break;
        case attach:
            handle = bpatch.processAttach(name, pid);
            if (!handle) { fprintf(stderr, "processAttach failed\n"); }
            break;
        case open:
            // Open the binary file; do not open dependencies
            handle = bpatch.openBinary(name, true);
            if (!handle) { fprintf(stderr, "openBinary failed\n"); }
            break;
    }

    return handle;
}

template<typename T>
void releaseBPatchVectorContents(BPatch_Vector<T *> vector) {
	for (auto *element : vector)
      		delete element;
    
    vector.clear();  	
    vector.shrink_to_fit();
} 

std::set<BPatch_basicBlock *> getBasicBlocksForFunction(BPatch_function *function) {
	BPatch_flowGraph *fg = function->getCFG();
	std::set<BPatch_basicBlock *> blocks; 
	fg->getAllBasicBlocks(blocks);
	
	return blocks;
}

BPatch_funcCallExpr* createReportFunctionSnippet(BPatch_addressSpace* app) {
	BPatch_image* appImage = app->getImage();
	
	// Find the printf function
    std::vector<BPatch_function*> printfFuncs;
    appImage->findFunction("print", printfFuncs);
    
    if (printfFuncs.size() == 0) {
        fprintf(stderr, "Could not find printf\n");
    }

	std::vector<BPatch_snippet*> printfArgs;
    BPatch_snippet* fmt = new BPatch_constExpr("Hash corrupted!\n");
    printfArgs.push_back(fmt);
        
    // Construct a function call snippet
    BPatch_funcCallExpr *printfCall = new BPatch_funcCallExpr(*(printfFuncs[0]), printfArgs);
    
    return printfCall;
}

BPatch_Vector<BPatch_snippet *> createHashFunctionSubSnippet(BPatch_addressSpace* app, BPatch_variableExpr* result,
													unsigned long startAddress, long blockSize,
													char hashStartValue) {
	
	BPatch_image* appImage = app->getImage();
	BPatch_Vector<BPatch_snippet *> hashFunctionSnippet;
	
	BPatch_variableExpr* counter = 
        app->malloc(*(appImage->findType("unsigned long")), "counter");
    
    BPatch_variableExpr* size = 
        app->malloc(*(appImage->findType("long")), "size");
    
    // couter = startAddress 
    BPatch_arithExpr *assignCounter = new BPatch_arithExpr(BPatch_assign,
    									*counter, BPatch_constExpr(startAddress));
	
	// result = 0									
    BPatch_arithExpr *assignResult = new BPatch_arithExpr (BPatch_assign,
    									*result, BPatch_constExpr(hashStartValue));
    									
    // size = size									
    BPatch_arithExpr *assignSize = new BPatch_arithExpr (BPatch_assign,
    									*size, BPatch_constExpr(blockSize));
    									
   	hashFunctionSnippet.push_back(assignResult);
   	hashFunctionSnippet.push_back(assignCounter);
   	hashFunctionSnippet.push_back(assignSize);
   	
   	BPatch_Vector<BPatch_snippet *> whileBody;
	
	// result + currentByte
	BPatch_arithExpr *addByte = new BPatch_arithExpr(BPatch_minus, *result, BPatch_arithExpr(BPatch_deref, *counter));
	
	// result = result + currentByte
  	BPatch_arithExpr *hash = new BPatch_arithExpr(BPatch_assign, *result, *addByte);
  	
  	// count+1
  	BPatch_arithExpr *countPlus = new BPatch_arithExpr(BPatch_plus, BPatch_constExpr(1), *counter);
  	
  	// count = count + 1
  	BPatch_arithExpr *count = new BPatch_arithExpr(BPatch_assign, *counter, *countPlus);
  	
 	// size-1
  	BPatch_arithExpr *sizeMinus = new BPatch_arithExpr(BPatch_minus, *size, BPatch_constExpr(1));
  	
  	// count = count - 1
  	BPatch_arithExpr *sizeMinusMinus = new BPatch_arithExpr(BPatch_assign, *size, *sizeMinus);
  	
  	// Add the created instructions to whileBody
  	whileBody.push_back(hash);
  	whileBody.push_back(count);
  	whileBody.push_back(sizeMinusMinus);
   
   	// counter < endAddress
   	BPatch_boolExpr *counterLEndAddress = new BPatch_boolExpr(BPatch_gt, *size, BPatch_constExpr((long)0));
   	
   	// while(counter < endAddress) { whileBody }
   	BPatch_whileExpr *whileHash = new BPatch_whileExpr(*counterLEndAddress, BPatch_sequence(whileBody));
    				
    hashFunctionSnippet.push_back(whileHash);
    									
   	return hashFunctionSnippet;
}

BPatch_Vector<BPatch_snippet *> createHashFunctionAddSnippet(BPatch_addressSpace* app, BPatch_variableExpr* result,
													unsigned long startAddress, long blockSize,
													char hashStartValue) {
	
	BPatch_image* appImage = app->getImage();
	BPatch_Vector<BPatch_snippet *> hashFunctionSnippet;
	
	BPatch_variableExpr* counter = 
        app->malloc(*(appImage->findType("unsigned long")), "counter");
    
    BPatch_variableExpr* size = 
        app->malloc(*(appImage->findType("long")), "size");
    
    // couter = startAddress 
    BPatch_arithExpr *assignCounter = new BPatch_arithExpr(BPatch_assign,
    									*counter, BPatch_constExpr(startAddress));
	
	// result = 0									
    BPatch_arithExpr *assignResult = new BPatch_arithExpr (BPatch_assign,
    									*result, BPatch_constExpr(hashStartValue));
    									
    // size = size									
    BPatch_arithExpr *assignSize = new BPatch_arithExpr (BPatch_assign,
    									*size, BPatch_constExpr(blockSize));
    									
   	hashFunctionSnippet.push_back(assignResult);
   	hashFunctionSnippet.push_back(assignCounter);
   	hashFunctionSnippet.push_back(assignSize);
   	
   	BPatch_Vector<BPatch_snippet *> whileBody;
	
	// result + currentByte
	BPatch_arithExpr *addByte = new BPatch_arithExpr(BPatch_plus, *result, BPatch_arithExpr(BPatch_deref, *counter));
	
	// result = result + currentByte
  	BPatch_arithExpr *hash = new BPatch_arithExpr(BPatch_assign, *result, *addByte);
  	
  	// count+1
  	BPatch_arithExpr *countPlus = new BPatch_arithExpr(BPatch_plus, BPatch_constExpr(1), *counter);
  	
  	// count = count + 1
  	BPatch_arithExpr *count = new BPatch_arithExpr(BPatch_assign, *counter, *countPlus);
  	
 	// size-1
  	BPatch_arithExpr *sizeMinus = new BPatch_arithExpr(BPatch_minus, *size, BPatch_constExpr(1));
  	
  	// count = count - 1
  	BPatch_arithExpr *sizeMinusMinus = new BPatch_arithExpr(BPatch_assign, *size, *sizeMinus);
  	
  	// Add the created instructions to whileBody
  	whileBody.push_back(hash);
  	whileBody.push_back(count);
  	whileBody.push_back(sizeMinusMinus);
   
   	// counter < endAddress
   	BPatch_boolExpr *counterLEndAddress = new BPatch_boolExpr(BPatch_gt, *size, BPatch_constExpr((long)0));
   	
   	// while(counter < endAddress) { whileBody }
   	BPatch_whileExpr *whileHash = new BPatch_whileExpr(*counterLEndAddress, BPatch_sequence(whileBody));
    				
    hashFunctionSnippet.push_back(whileHash);
    									
   	return hashFunctionSnippet;
}

BPatch_Vector<BPatch_snippet *> createCheckerSnippet(BPatch_addressSpace* app, char correctHash, 
													unsigned long startAddress, unsigned long size,
													hashFunction *snippetHashFunction, char hashStartValue = 0) {
	BPatch_image* appImage = app->getImage();
	
	// Holds all created snippets
	BPatch_Vector<BPatch_snippet *> checkerSnippet;
    
    BPatch_variableExpr* result = 
        app->malloc(*(appImage->findType("char")), "result");
        	
    BPatch_variableExpr* correctHashConst = 
        app->malloc(*(appImage->findType("char")), "correctHashConst");
    						
    // correctHashConst = 0									
    BPatch_arithExpr *assignCorrectHashConst = new BPatch_arithExpr (BPatch_assign,
   										*correctHashConst, BPatch_constExpr((unsigned int)correctHash));
   										
   	checkerSnippet.push_back(assignCorrectHashConst);
  	
  	// Create a hash function snippet
    BPatch_Vector<BPatch_snippet *> hashFunctionSnippet = snippetHashFunction(app, result,
													startAddress, size,
													hashStartValue);
    
    						
    checkerSnippet.insert(std::end(checkerSnippet), std::begin(hashFunctionSnippet), std::end(hashFunctionSnippet));
    
    // Create report function snippet
    BPatch_funcCallExpr *printfCall = createReportFunctionSnippet(app);
    
    // if ( result != correctHash) { report (); }
    BPatch_ifExpr *checkHash = new BPatch_ifExpr(
					BPatch_boolExpr(BPatch_ne, *result, *correctHashConst), 
					*printfCall);
 	
 	checkerSnippet.push_back(checkHash);
      	
 	return checkerSnippet;
}

char hashFunctionAdd(std::vector<char> values) {
	char result = 0;
	for(auto value : values) 
		result += value;
	
	return result;
}

char hashFunctionSub(std::vector<char> values) {
	char result = 0;
	for(auto value : values) 
		result -=  value;
	
	return result;
}

int blockLengthUntilCall(BPatch_basicBlock *block) {
	std::vector<Dyninst::InstructionAPI::Instruction::Ptr> insns; 
	block->getInstructions(insns);
	
	int length = 0;
	
	for (Dyninst::InstructionAPI::Instruction::Ptr inst : insns) {
		if (inst->getCategory() == Dyninst::InstructionAPI::c_CallInsn) { break; }
		length+=inst->size();
	}
	
	return length;
}

char computeHash(BPatch_basicBlock *block, char (*hashFunction)(std::vector<char>)) {
	std::vector<Dyninst::InstructionAPI::Instruction::Ptr> insns; 
	block->getInstructions(insns);

	std::vector<char> instValues;
	
	for (Dyninst::InstructionAPI::Instruction::Ptr inst : insns) {
		if (inst->getCategory() == Dyninst::InstructionAPI::c_CallInsn) { break; }
		for (unsigned int i = 0; i < inst->size(); i++) {			
			instValues.push_back(inst->rawByte(i));
		}
	}
	
	return hashFunction(instValues);
}

void finishInstrumenting(BPatch_addressSpace* app, const char* newName) {
    BPatch_process* appProc = dynamic_cast<BPatch_process*>(app);
    BPatch_binaryEdit* appBin = dynamic_cast<BPatch_binaryEdit*>(app);
   
    if (appProc) {
        if (!appProc->continueExecution()) {
            fprintf(stderr, "continueExecution failed\n");
        }
        while (!appProc->isTerminated()) {
            bpatch.waitForStatusChange();
        }
    } else if (appBin) {
        if (!appBin->writeFile(newName)) {
            fprintf(stderr,"writeFile failed\n");
        }
    }
}

Graph createCheckerNetwork(BPatch_addressSpace* app, int connectivity, std::vector<char*> functions){
	Graph g;
	BPatch_image *appImage = app->getImage();
	std::vector<vertex_t> vertices;
	for (auto name : functions){
		std::vector<BPatch_function *> funcs;
		appImage->findFunction(name, funcs);
		for  (auto singleFunc : funcs){
			std::set<BPatch_basicBlock *> blocks = getBasicBlocksForFunction(singleFunc);
			for (auto singleBlock : blocks){
				BPatch_basicBlock *block = singleBlock; 
				vertex_t u = boost::add_vertex(g);
				g[u].block = block;
				vertices.push_back(u);
			}
		}
	}
	connectivity = std::min((int)(vertices.size()-1), connectivity);
	std::vector<vertex_t> verticesDest = vertices;
	for (auto blockFrom : vertices){
		int out = 0;
		while(out < connectivity){
			vertex_t blockTo;
			int rand_pos;
			while(true){
				rand_pos = rand() % verticesDest.size();
				blockTo = verticesDest[rand_pos];
				if (blockFrom != blockTo){
					break;
				}
			}
			if(boost::add_edge(blockTo, blockFrom, g).second){
				Graph::in_edge_iterator inI, inEnd;
      			boost::tie(inI, inEnd) = in_edges(blockTo,g);
				out += 1;
			}
		}
	}
	write_graphviz(std::cout, g);
	return g;
}

int main() {
	srand(time(NULL));

    // Set up information about the program to be instrumented
    const char* progName = "build/InterestingProgram";
    int progPID = 42;
    const char* progArgv[] = {"InterestingProgram", "-h", NULL};
    accessType_t mode = open;

    // Create/attach/open a binary
    BPatch_addressSpace* app = 
        startInstrumenting(mode, progName, progPID, progArgv);
    if (!app) {
        fprintf(stderr, "startInstrumenting failed\n");
        exit(1);
    }
    std::vector<char*> functions;
    functions.push_back("print");
    functions.push_back("InterestingProcedure");
    Graph g = createCheckerNetwork(app, 2, functions);
    
    //Graph::vertex_iterator vertices, verticesEnd;
    //boost::tie(vertices, verticesEnd) = boost::vertices(g);
    
   	typedef Graph::vertex_descriptor Vertex;
   	typedef Graph::vertex_iterator vertex_iter;
    std::pair<vertex_iter, vertex_iter> vp;
    for (vp = vertices(g); vp.first != vp.second; ++vp.first) {
      Vertex v = *vp.first;
      std::cout << g[v].block->getBlockNumber() <<  "\n " << endl;
      
      typedef Graph::adjacency_iterator adj_vertex_iter;
      std::pair<adj_vertex_iter, adj_vertex_iter> adj_vp;
      
      for (adj_vp = adjacent_vertices(v, g); adj_vp.first != adj_vp.second; ++adj_vp.first) {
      	v = *adj_vp.first;
      	std::cout << g[v].block->getBlockNumber() <<  " " << endl;
      }
      cout<<"\n"<<endl;
    }

    /*
    BPatch_image *appImage = app->getImage();
	std::vector<BPatch_function *> funcs; 
	appImage->findFunction("InterestingProcedure", funcs);
    std::set<BPatch_basicBlock *> blocks = getBasicBlocksForFunction(funcs[0]);
    
    std::set<BPatch_basicBlock *>::iterator block_iter;
	for (block_iter = blocks.begin(); block_iter != blocks.end(); ++block_iter) {
		BPatch_basicBlock *block = *block_iter; 
		// Choose a hashFunction
		
		// Calculate right hash
		char correctHash = 0;
		//cout<<hex<<block->getStartAddress()<<" "<< block->getEndAddress()<<" "<< block->size()<<endl;
		
		hashFunction *hashFunctionSnippet = NULL;
		int chooseHashFunction = rand() % NUMBER_HASHFUNCTIONS;
    	//cout << chooseHashFunction << endl;
    	if (chooseHashFunction == 0) {
    		hashFunctionSnippet = &createHashFunctionAddSnippet;
    		correctHash = computeHash(block, *hashFunctionAdd);
    		cout<<"ADD" << endl;
    	} else {
    		hashFunctionSnippet = &createHashFunctionSubSnippet;
    		correctHash = computeHash(block, *hashFunctionSub);
    		cout<<"SUB" << endl;
   		}
    	cout << hex<<int(correctHash) <<" " <<blockLengthUntilCall(block) << endl;
		// Generate snippet
		BPatch_Vector<BPatch_snippet *> checkerSnippet = 
			createCheckerSnippet(app, correctHash, 0x810019e, blockLengthUntilCall(block), hashFunctionSnippet);
		
		// Insert the snippet
    	if (!app->insertSnippet(BPatch_sequence(checkerSnippet), *(block->findEntryPoint()))) {
      	  	fprintf(stderr, "insertSnippet failed\n");
      	}
      	releaseBPatchVectorContents(checkerSnippet);
	}*/

    // Finish instrumentation 
    const char* progName2 = "build/InterestingProgram-rewritten";
    finishInstrumenting(app, progName2);
    
    return 0;
}

