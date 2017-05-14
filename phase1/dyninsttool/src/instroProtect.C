#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <algorithm>
#include <unistd.h>
#include <fstream>
#include <sstream>
#include <string>

#include "BPatch.h"
#include "BPatch_addressSpace.h"
#include "BPatch_process.h"
#include "BPatch_binaryEdit.h"
#include "BPatch_point.h"
#include "BPatch_function.h"
#include "BPatch_flowGraph.h"
#include "Instruction.h"
#include "InstructionCategories.h"

#include <boost/graph/adjacency_list.hpp>
#include <boost/graph/graphviz.hpp>

#define NUMBER_HASHFUNCTIONS 2
#define PLACEHOLDER 0x0

using namespace std;
using namespace Dyninst;

typedef BPatch_Vector<BPatch_snippet *> (hashFunction) (BPatch_addressSpace*, BPatch_variableExpr*,
													unsigned long, long, char);
													
hashFunction createHashFunctionAddSnippet;
hashFunction createHashFunctionSubSnippet;

// Create an instance of class BPatch
BPatch bpatch;

// Public Variables
int connectivity;
bool verbose = false;
const char *progName;
const char *functionsFileName;

// Uncomment this if you want to stop type checking
// on BPatch snippets
//bpatch.setTypeChecking(false);

// Network
struct Vertex{BPatch_basicBlock *block;};
struct Edge{std::string blah;};

typedef boost::adjacency_list<boost::setS, boost::vecS, boost::bidirectionalS, Vertex, Edge> Graph;
typedef boost::graph_traits<Graph>::vertex_descriptor vertex_t;
typedef boost::graph_traits<Graph>::edge_descriptor edge_t;

// Open a file for rewriting
BPatch_addressSpace* startInstrumenting(const char* name) {
    BPatch_addressSpace* handle = bpatch.openBinary(name, true);
    if (!handle) { 
    	fprintf(stderr, "openBinary failed\n"); 
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
    
    //TODO: Fix Dyninst library and actually insert printf
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
    BPatch_funcCallExpr *reportFunction = createReportFunctionSnippet(app);
    
    // if ( result != correctHash) { report (); }
    BPatch_ifExpr *checkHash = new BPatch_ifExpr(
					BPatch_boolExpr(BPatch_ne, *result, *correctHashConst), 
					*reportFunction);
 	
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

bool instructionUsesAddress(Dyninst::InstructionAPI::Instruction::Ptr inst) {
	return inst->getCategory() == Dyninst::InstructionAPI::c_CallInsn;
}

int blockLengthUntilCall(BPatch_basicBlock *block) {
	std::vector<Dyninst::InstructionAPI::Instruction::Ptr> insns; 
	block->getInstructions(insns);
	
	int length = 0;
	
	for (Dyninst::InstructionAPI::Instruction::Ptr inst : insns) {
		if (instructionUsesAddress(inst)) { break; }
		length += inst->size();
	}
	
	return length;
}

char computeHash(BPatch_basicBlock *block, char (*hashFunction)(std::vector<char>)) {
	std::vector<Dyninst::InstructionAPI::Instruction::Ptr> insns; 
	block->getInstructions(insns);

	std::vector<char> instValues;
	
	for (Dyninst::InstructionAPI::Instruction::Ptr inst : insns) {
		if (instructionUsesAddress(inst)) { break; }
		for (unsigned int i = 0; i < inst->size(); i++) {			
			instValues.push_back(inst->rawByte(i));
		}
	}
	
	return hashFunction(instValues);
}

void finishInstrumenting(BPatch_addressSpace* app, const char* newName) {
    BPatch_binaryEdit* appBin = dynamic_cast<BPatch_binaryEdit*>(app);
    
    if (!appBin) {
    	fprintf(stderr,"appBin not defined!\n");
    	return;
    }
    
    if (!appBin->writeFile(newName)) {
		fprintf(stderr,"writeFile failed\n");
    }
}

Graph createCheckerNetwork(BPatch_addressSpace* app, int connectivity, std::vector<std::string> functions){
	Graph g;
	BPatch_image *appImage = app->getImage();
	std::vector<vertex_t> vertices;
	for (auto name : functions){
		std::vector<BPatch_function *> funcs;
		appImage->findFunction(name.c_str(), funcs);
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
	
	if (connectivity > (int) vertices.size() - 1) {
		cout << "WARNING" << endl;
		cout << "The specified connectivity " << connectivity << " is larger than the number of basic blocks." << endl;
		cout << "Connectivity set to: " << vertices.size() - 1 << endl;
	}
	
	connectivity = std::min((int)(vertices.size()-1), connectivity);
	std::vector<vertex_t> verticesDest = vertices;
	
	for (auto blockFrom : vertices){
		int out = 0;
		while(out < connectivity) {
			vertex_t blockTo;
			int rand_pos;
			while(true){
				rand_pos = rand() % verticesDest.size();
				blockTo = verticesDest[rand_pos];
				if (blockFrom != blockTo){
					break;
				}
			}
			if(boost::add_edge(blockTo, blockFrom, g).second) {
				Graph::in_edge_iterator inI, inEnd;
      			boost::tie(inI, inEnd) = in_edges(blockTo,g);
				out += 1;
			}
		}
	}
	
	if (verbose) { 
		write_graphviz(std::cout, g); 
	}
	
	return g;
}

void usage() {
	puts("instroProtect [OPTIONS]\n" 
		 "\t-b\tname of binary to protect\n"
		 "\t-c\tpositive number indicating how many checkers check each basic block\n"
		 "\t-f\tname of a file containing the names of functions to be protected (line separated)\n"
		 "\t-v\tverbose output including a \"nice\" graph of the checker network\n");
	exit(1);
}

void parseArgs(int argc, char** argv) {

	int opt;
	while((opt = getopt(argc, argv, "b:c:f:v")) != EOF) {
		switch(opt) {
			case 'b':
				progName = optarg;
				break;
			case 'c':
				connectivity = std::stoi(optarg);
				break;
			case 'f':
				functionsFileName = optarg;
				break;
			case 'v':
				verbose = true;
				break;
			default:
				usage();
		}
	}
	
	if(progName == NULL || connectivity < 1 || functionsFileName == NULL) {
		usage();
	}
}

std::vector<std::string> parseFunctionToCheckNames() {
	std::vector<std::string> functions;
	std::ifstream infile(functionsFileName);
		
	std::string line;
	while (std::getline(infile, line)) {
		if (line == "") { continue; }
		functions.push_back(line);
	}
	
	if(functions.size() == 0) {
		usage();
	}
			
	return functions;
}

int main(int argc, char* argv[]) {
	parseArgs(argc, argv);
	
	srand(time(NULL));

    // Open a binary
    BPatch_addressSpace* app = startInstrumenting(progName);
    if (!app) {
        fprintf(stderr, "startInstrumenting failed\n");
        exit(1);
    }
    
    std::vector<std::string> functions = parseFunctionToCheckNames();
    
    Graph g = createCheckerNetwork(app, connectivity, functions);
   	typedef Graph::vertex_descriptor Vertex;
   	typedef Graph::vertex_iterator vertex_iter;
    std::pair<vertex_iter, vertex_iter> vp;
    
	for (vp = vertices(g); vp.first != vp.second; ++vp.first) {
    	Vertex v = *vp.first;
    	BPatch_basicBlock *basicBlock = g[v].block;
      	cout << "Block " << v << " with startAddress " << hex <<"0x"<< basicBlock->getStartAddress() << " checks:" << endl;
		typedef Graph::adjacency_iterator adj_vertex_iter;
		std::pair<adj_vertex_iter, adj_vertex_iter> adj_vp;
		
		int chooseHashFunction;
		
		// Generate snippet
		BPatch_Vector<BPatch_snippet *> checkerSnippet; 

		for (adj_vp = adjacent_vertices(v, g); adj_vp.first != adj_vp.second; ++adj_vp.first) {
			v = *adj_vp.first;
			BPatch_basicBlock *blockToCheck = g[v].block;
			cout<< "\tBlock " << v << " with startAddress " << "0x"<< blockToCheck->getStartAddress() <<endl;

			char correctHash = 0;

			hashFunction *hashFunctionSnippet = NULL;
			chooseHashFunction = rand() % NUMBER_HASHFUNCTIONS;

			if (chooseHashFunction == 0) {
				hashFunctionSnippet = &createHashFunctionAddSnippet;
				correctHash = computeHash(blockToCheck, *hashFunctionAdd);
			} else {
				hashFunctionSnippet = &createHashFunctionSubSnippet;
				correctHash = computeHash(blockToCheck, *hashFunctionSub);
			}

			// Generate snippet
			BPatch_Vector<BPatch_snippet *> currentCheckerSnippet = 
				createCheckerSnippet(app, correctHash, blockToCheck->getStartAddress(), blockLengthUntilCall(blockToCheck), hashFunctionSnippet);
		
			checkerSnippet.insert(std::end(checkerSnippet), std::begin(currentCheckerSnippet), std::end(currentCheckerSnippet));	
		}
		
		if (vp.first != vp.second-1) {

			hashFunction *hashFunctionSnippet = NULL;
			chooseHashFunction = rand() % NUMBER_HASHFUNCTIONS;

			if (chooseHashFunction == 0) {
				hashFunctionSnippet = &createHashFunctionAddSnippet;
			} else {
				hashFunctionSnippet = &createHashFunctionSubSnippet;
			}

			BPatch_Vector<BPatch_snippet *> currentCheckerCheckSnippet = 
					createCheckerSnippet(app, PLACEHOLDER, PLACEHOLDER, PLACEHOLDER, hashFunctionSnippet);
		  	checkerSnippet.insert(std::end(checkerSnippet), std::begin(currentCheckerCheckSnippet), std::end(currentCheckerCheckSnippet));
		}
      	
    	// Insert the snippet
		if (!app->insertSnippet(BPatch_sequence(checkerSnippet), *(basicBlock->findEntryPoint()))) {
      	  	fprintf(stderr, "insertSnippet failed\n");
      	}
      	releaseBPatchVectorContents(checkerSnippet);
    }

	// Finish instrumentation 
    const std::string progName2 = std::string(progName) + "-rewritten";
    finishInstrumenting(app, progName2.c_str());
    
    return 0;
}

