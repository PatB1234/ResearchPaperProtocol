#include <openfhe.h>
#include <thread>
#include "client.h"
#include "master.h"
using namespace lbcrypto;
using namespace std;

KeyPair<DCRTPoly> kp2;

void generateServerKeys() {
    // Generate keys
    kp2 = cc->KeyGen();
    cc->EvalMultKeyGen(kp2.secretKey);
    cc->EvalAtIndexKeyGen(kp2.secretKey, {1,2,4,-1,-2,-4});
    cc->EvalSumKeyGen(kp2.secretKey);

}

PublicKey<DCRTPoly> getServerPublicKey() {

    if (!cc) { // Means that we do not have defined keys, so we are generating them

        generateServerKeys();
    }

    return kp2.publicKey;
}

Ciphertext<DCRTPoly> encryptDataServer(vector<int64_t> data) { // ADD NODES HERE

    // Encode + encrypt
    Plaintext ptxt = cc->MakeCoefPackedPlaintext(data);
    auto ciphertext = cc->Encrypt(kp2.publicKey, ptxt);
    return ciphertext;
}

tuple<Ciphertext<DCRTPoly>, EvalKey<DCRTPoly>> switchServerToClient(const Ciphertext<DCRTPoly>& encData, PrivateKey<DCRTPoly> privKey, PublicKey<DCRTPoly> /*pubKey*/) {
    PublicKey<DCRTPoly> c_pk = getClientPublicKey();
    auto switchingKey = cc->ReKeyGen(privKey, c_pk);  // rk: S -> C
    return {encData, switchingKey};
}

void receiveSwitchedData(vector<Ciphertext<DCRTPoly>> encData, vector<EvalKey<DCRTPoly>> switchKey) {
    // No need to generate keys as getting to this step requires the keys to already have been made
    vector<int64_t> decData;
    vector<thread> decThreads;

    for (int i = 0; i < encData.size(); i++) {
        decThreads.emplace_back([&, i]() { // Use threading to decrypt
            auto ciphertext = cc->ReEncrypt(encData.at(i), switchKey.at(i));
            Plaintext res;
            cc->Decrypt(kp2.secretKey, ciphertext, &res);
            vector<int64_t> val = res->GetCoefPackedValue();
            decData.push_back(val.at(0));
        });
    }

    for (auto& t : decThreads) {
        t.join();
    }
    constexpr uint64_t modulus = 131071;
    constexpr int64_t shift = modulus / 2;

    int64_t total = decData[0];
    // % Modulus is done as all homomorphic operations are done as modulus of the plaintext modulus, so this is mimicking that
    for (int j = 0; j < 3; j++) {
        for (size_t i = 1; i < decData.size(); i++) {
            for (int r = 0; r < 20; r++) {
                total = (total + decData[i]) % modulus;
            }
        }
        for (size_t i = 0; i < decData.size(); i++) {
            for (int r = 0; r < 20; r++) {
                total = (total - decData[i] + modulus) % modulus;
            }
        }
    }

    for (size_t i = 1; i < decData.size(); i++) {
        for (int r = 0; r < 20; r++) {
            total = (total + decData[i]) % modulus;
        }
    }

    for (size_t i = 0; i < decData.size(); i++) {
        for (size_t j = 0; j < decData.size(); j++) {
            total = (total - decData[i] + modulus) % modulus;
        }
    }

    int64_t totalSigned = ((total - shift) + modulus) % modulus - shift;
    vector<int64_t> resultVector{totalSigned};


    vector<Ciphertext<DCRTPoly>> ciphertexts; // The locations in the vector correlate to the equivalent values and keys in each vector.
    vector<EvalKey<DCRTPoly>> switchingKeys;
    auto otherPublicKey = getClientPublicKey();
    vector<thread> encThreads;

    for (int i = 0; i < resultVector.size(); i++) {

        encThreads.emplace_back([&, i]() { // Add each routine to a thread

            vector<int64_t> curr_data{resultVector.at(i)};
            Ciphertext<DCRTPoly> ciphertext = encryptDataServer(curr_data);

            tuple<Ciphertext<DCRTPoly>, EvalKey<DCRTPoly>> res = switchServerToClient(ciphertext, kp2.secretKey, otherPublicKey);
            ciphertexts.push_back(get<0>(res));
            switchingKeys.push_back(get<1>(res));
        });
    }

    for (auto& t : encThreads) { // Run all the threads
        t.join();
    }


    receiveDataFromServer(ciphertexts, switchingKeys);

}