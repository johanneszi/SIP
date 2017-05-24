#include <vector>
#include <string>
#include <execinfo.h>
#include <iostream>

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

unsigned long calculateCallHash(std::vector<std::string>) {
 	// Hash backtrace
	return 42;
}

void check(unsigned long validHash) {
  
	// Get current stack trace
	std::vector<std::string> currentTrace = stackTrace();
	for (int i = 0; i < currentTrace.size(); i++) {
		std::cout<<currentTrace[i]<<"\n";
	}
	
	// Calculate current call hash
	unsigned long callHash = calculateCallHash(currentTrace);
	
	if (validHash != callHash) {
		std::cout<<"Hash corrupted!\n";
	}
}

