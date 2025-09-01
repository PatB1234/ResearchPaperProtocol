#pragma once
using namespace  lbcrypto;
using namespace std;
PublicKey<DCRTPoly> getServerPublicKey();
void receiveSwitchedData(vector<Ciphertext<DCRTPoly>> encData, vector<EvalKey<DCRTPoly>> switchKey);
void generateServerKeys();