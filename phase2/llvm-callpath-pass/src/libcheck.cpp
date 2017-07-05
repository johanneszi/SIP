#include <algorithm>
#include <cstring>
#include <iostream>
#include <execinfo.h>

#include "crypto.h"

#define STACKTRACE 256

const std::string libcStartMain = "__libc_start_main";

// Calculate backtrace
std::vector<std::string> stackTrace() {
	std::vector<std::string> trace;
	void *array[STACKTRACE];
  	size_t size;
   std::string start;
   
  	// get void*'s for all entries on the stack
  	size = backtrace(array, STACKTRACE);

  	char **traces = backtrace_symbols(array, size);
  	
  	// Skip the check and stackTrace
  	for(unsigned int i = 2; i < size; i++) {
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
  		
  		if (i == 2) {
  		   start = funcName;
  		}
  		
  		// Skip libc functions
  		if (funcName == libcStartMain) {
  			break;
  		}
  		
  	   std::vector<std::string>::iterator position = std::find(trace.begin(), trace.end(), funcName); 
  		
  		if (position != trace.end()) {
  		   trace.erase(position);
  		}  
  		 
  		trace.push_back(funcName);
  	}
  	
  	std::reverse(trace.begin(), trace.end());
  		
  	std::vector<std::string>::iterator position = std::find(trace.begin(), trace.end(), start);
  	
  	if (position != trace.end()) {
  	   trace.erase(++position, trace.end());
  	}
  	
	return trace;
} 

extern "C" bool check(char *validHash, bool hasToCheck) {
	if (!hasToCheck) {
		std::vector<std::string> currentTrace = stackTrace();
		std::string hash = sha256(currentTrace);
	
		return std::memcmp(validHash, hash.c_str(), SHA256_DIGEST_LENGTH) == 0;
	}
	 
	return true;
}

extern "C" void report(bool valid) {
	if (!valid) {
		std::cout << "Hash corrupted!" << std::endl; 
	}
}

