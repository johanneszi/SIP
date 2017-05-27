#include <vector>
#include <algorithm>
#include <string>
#include <cstring>
#include <iostream>
#include <execinfo.h>

#include <openssl/sha.h>
#include <sstream>
#include <iomanip>

#define STACKTRACE 256

extern "C" void report(bool valid) {
	if (!valid)
		std::cout << "Hash corrupted!" << std::endl; 
}

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
  		if (funcName == "main") {
  			break;
  		}
  	}
  	
  	std::reverse(trace.begin(), trace.end());
  	
	return trace;
} 

std::string sha256(std::vector<std::string> input) {
		unsigned char hash[SHA256_DIGEST_LENGTH];
		SHA256_CTX sha256;
		SHA256_Init(&sha256);
		
		for (auto function : input) {
			SHA256_Update(&sha256, function.c_str(), function.size());
		}
		
		SHA256_Final(hash, &sha256);
		std::stringstream ss;
		for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		    ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    	}
    
    	return ss.str();
}

extern "C" bool check(char* validHash, bool hastocheck) {
	// Get current stack trace
	if (!hastocheck){
		std::vector<std::string> currentTrace = stackTrace();
		std::string hash = sha256(currentTrace);
	
		return std::memcmp(validHash, hash.c_str(), SHA256_DIGEST_LENGTH) == 0;
	} else {
		return true;
	}
}

