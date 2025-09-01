#pragma once
#include <ciphertext-fwd.h>
#include <lattice/hal/lat-backend.h>
using namespace lbcrypto;
using namespace std;
using namespace std::chrono;
Ciphertext<DCRTPoly> switchKeyData(const Ciphertext<DCRTPoly>& encData, PrivateKey<DCRTPoly> privKey, PublicKey<DCRTPoly> pubKey);
Ciphertext<DCRTPoly> encryptData(vector<int64_t> data);
PublicKey<DCRTPoly> getClientPublicKey();
void receiveDataFromServer(vector<Ciphertext<DCRTPoly>> encData, vector<EvalKey<DCRTPoly>> switchKey);
void receiveDataFromDevice(vector<int64_t> raw_data);
void generateClientKeys();
extern time_point<steady_clock, steady_clock::duration> start;
