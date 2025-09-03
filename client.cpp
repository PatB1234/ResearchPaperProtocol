#include <openfhe.h>
#include <utility>
#include <chrono>
#include <thread>
#include "master.h"
#include "server.h"

using namespace std;
using namespace lbcrypto;
using namespace std::chrono;

KeyPair<DCRTPoly> kp1;
high_resolution_clock::time_point start; // Variables to calculate and record time taken
void generateClientKeys() {
    // Generate keys
    kp1 = cc->KeyGen();

}

PublicKey<DCRTPoly> getClientPublicKey() {
    if (!kp1.publicKey) {            // ensure keys exist
        generateClientKeys();
    }
    return kp1.publicKey;
}

Ciphertext<DCRTPoly> encryptDataClient(vector<int64_t> data) { // ADD NODES HERE

    if (!kp1.publicKey) {

        generateClientKeys();
    }
    Plaintext ptxt = cc->MakeCoefPackedPlaintext(data);
    auto ciphertext = cc->Encrypt(kp1.publicKey, ptxt);
    return ciphertext;

}

tuple<Ciphertext<DCRTPoly>, EvalKey<DCRTPoly>>  switchClientToServer(const Ciphertext<DCRTPoly>& encData, PrivateKey<DCRTPoly> privKey, PublicKey<DCRTPoly> pubKey) {

    PublicKey<DCRTPoly> s_pk = getServerPublicKey(); // Get other public key
    auto switchingKey = cc->ReKeyGen(privKey, s_pk); // (Our secret key, Their public key)
    return tuple<Ciphertext<DCRTPoly>, EvalKey<DCRTPoly>> (encData, switchingKey);
}

void receiveDataFromDevice(vector<int64_t> raw_data) {
    start = high_resolution_clock::now();
    vector<Ciphertext<DCRTPoly>> ciphertexts; // The locations in the vector correlate to the equivalent values and keys in each vector.
    vector<EvalKey<DCRTPoly>> switchingKeys;
    auto otherPublicKey = getServerPublicKey();
    vector<thread> threads;

    for (int i = 0; i < raw_data.size(); i++) {

        threads.emplace_back([&, i]() { // Add each routine to a thread

            vector<int64_t> curr_data{raw_data.at(i)};
            Ciphertext<DCRTPoly> ciphertext = encryptDataClient(curr_data);

            tuple<Ciphertext<DCRTPoly>, EvalKey<DCRTPoly>> res = switchClientToServer(ciphertext, kp1.secretKey, otherPublicKey);
            ciphertexts.push_back(get<0>(res));
            switchingKeys.push_back(get<1>(res));
        });
    }

    for (auto& t : threads) { // Run all the threads
        t.join();
    }

    receiveSwitchedData(ciphertexts, switchingKeys);

}

void receiveDataFromServer(vector<Ciphertext<DCRTPoly>> encData, vector<EvalKey<DCRTPoly>> switchKey) {

    vector<int64_t> decData;
    vector<thread> decThreads;

    for (int i = 0; i < encData.size(); i++) {
        decThreads.emplace_back([&, i]() { // Use threading to decrypt
            auto ciphertext = cc->ReEncrypt(encData.at(i), switchKey.at(i));
            Plaintext res;
            cc->Decrypt(kp1.secretKey, ciphertext, &res);
            vector<int64_t> val = res->GetCoefPackedValue();
            decData.push_back(val.at(0));
        });
    }

    for (auto& t : decThreads) {
        t.join();
    }

    cout << "IoT device computed data: " << endl;
    for (int i = 0; i < decData.size(); i++) {

        cout << decData[i] << endl;
    }
    auto end = high_resolution_clock::now();
    auto time_taken = duration_cast<milliseconds>(end - start);
    cout << "Time Taken: " << time_taken.count() << " ms" << endl;
    times.push_back(time_taken.count());
}