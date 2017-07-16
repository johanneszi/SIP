#include <openssl/sha.h>
#include <iomanip>
#include <sstream>

#include "crypto.h"

std::string sha256(std::vector<std::string> input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);

    for (auto function : input) {
        SHA256_Update(&sha256, function.c_str(), function.size());
    }

    SHA256_Final(hash, &sha256);
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }

    return ss.str();
}
