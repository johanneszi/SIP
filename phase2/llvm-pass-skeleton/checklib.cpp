#include <vector>
#include <string>
#include <iostream>
#include <cstdarg>
#include <execinfo.h>

//#include "merkletree.h"

#define STACKTRACE 256

// Calculate backtrace
std::vector<std::string> stackTrace() {
	std::vector<std::string> trace;
	void *array[STACKTRACE];
  	size_t size;

  	// get void*'s for all entries on the stack
  	size = backtrace(array, STACKTRACE);

  	char **traces = backtrace_symbols(array, size);
  	
  	// Skip the check and stackTrace
  	for(int i = 2; i < size; i++) {
  		char *begin = traces[i];
  		
  		for (char* p = traces[i]; *p; p++) {
  			if (*p == '(') 
  				begin = p + 1;
  			else if(*p == '+') {
  				*p = '\0';
  				break;
  			}
  		}
  		
  		std::string funcName(begin);
  		
  		trace.push_back(funcName);
  	}
  	
	return trace;
} 
/*
uint8_t* calculateCallHash(std::vector<std::string> trace) {
 	// Hash backtrace
 	mt_t *mt = mt_create();
 	
 	for (int i = 0; i < trace.size(); i++) {
 		std::string frame = trace[i];
 		size_t length = frame.length();
 		uint8_t *frameToHash = (uint8_t *) frame.c_str();
 		
 		mt_add(mt, frameToHash, length);
 	}
 	
 	uint8_t *hash = new uint8_t[HASH_LENGTH]; 
 	mt_get_root(mt, hash);
 	
 	mt_delete(mt);
 	
	return hash;
}*/

extern "C" bool check(int validHash, bool hastocheck) {
  	std::cout<<validHash << hastocheck << "\n";
	// Get current stack trace
	if (!hastocheck){
		std::vector<std::string> currentTrace = stackTrace();
		for (int i = 0; i < currentTrace.size(); i++) {
			std::cout<<currentTrace[i]<<"\n";
		}
		return false;
	}
	else {
		return true;
	}
}

