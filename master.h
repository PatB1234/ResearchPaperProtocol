#pragma once
#include <vector>
#include <openfhe.h>
#include <chrono>

using namespace lbcrypto;
using namespace std;
using namespace std::chrono;
std::vector<int64_t> generate_data();
extern CryptoContext<DCRTPoly> cc;
extern vector<int64_t> times;
