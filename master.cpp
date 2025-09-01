#include "master.h"
#include "client.h"
#include <iostream>
#include <openfhe.h>
#include "server.h"
#include <queue>
#include <fstream> // For reading files
#include <cstdint>

using namespace std;
using namespace lbcrypto;
using namespace std::chrono;

// Define the shared context
CryptoContext<DCRTPoly> cc;
vector<int64_t> times;
void InitContext() {
    if (cc) return; // already init

    //Paramater setup
    CCParams<CryptoContextBGVRNS> parameters;
    parameters.SetPlaintextModulus(131071);
    parameters.SetMultiplicativeDepth(3);
    parameters.SetRingDim(16384);

    cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(PRE);
}

int main() {


    // Load data into queue
    queue<vector<int64_t>> data;
    ifstream file;
    file.open("data.txt");
    string line;
    while (getline (file, line)) {
        stringstream ss(line);
        vector<int64_t> row;
        string token;

        // split by commas
        while (getline(ss, token, ',')) {
            if (!token.empty()) {
                row.push_back(stoll(token));
            }
        }

        if (!row.empty()) {
            data.push(row);
        }
    }

    file.close();
    while (!data.empty()) {
        InitContext();
        // Each party creates its keys in the same context
        generateClientKeys();
        generateServerKeys();
        auto currData = data.front();
        // Simulate device->client side action (encrypt & send to server with rk(C->S))
        receiveDataFromDevice(currData);
        data.pop();
    }

    // Calculate average time:
    int64_t sum = 0;
    for (size_t i = 0; i < times.size(); i++) {
        sum += times[i];
    }

    double avg = 0.0;
    if (!times.empty()) {
        avg = static_cast<double>(sum) / times.size();
    }

    cout << "Average time: " <<  avg << " ms" << endl;
    return 0;

}
