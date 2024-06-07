                   Rail Fence Cipher – Encryption and  Decryption

Code:
#include <iostream>
#include <string>
#include <vector>

using namespace std;

string encryptRailFence(const string& text, int key) {
    vector<string> rails(key);
    int row = 0;
    bool down = false;

    for (char c : text) {
        rails[row] += c;
        if (row == 0 || row == key - 1) down = !down;
        row += down ? 1 : -1;
    }

    string result;
    for (const string& rail : rails) {
        result += rail;
    }
    return result;
}

string decryptRailFence(const string& cipher, int key) {
    vector<string> rails(key);
    int idx = 0;
    int row = 0;
    bool down = false;

    for (int i = 0; i < cipher.length(); ++i) {
        rails[row] += '*';
        if (row == 0 || row == key - 1) down = !down;
        row += down ? 1 : -1;
    }

    for (int i = 0; i < key; ++i) {
        for (int j = 0; j < rails[i].length(); ++j) {
            if (rails[i][j] == '*') {
                rails[i][j] = cipher[idx++];
            }
        }
    }

    string result;
    row = 0;
    down = false;
    for (int i = 0; i < cipher.length(); ++i) {
        result += rails[row][i];
        if (row == 0 || row == key - 1) down = !down;
        row += down ? 1 : -1;
    }

    return result;
}

int main() {
    cout << encryptRailFence("attack at once", 2) << endl;
    cout << encryptRailFence("GeeksforGeeks", 3) << endl;
    cout << encryptRailFence("defend the east wall", 3) << endl;

    cout << decryptRailFence("Gsekfrek eoeGs", 3) << endl;
    cout << decryptRailFence("atc toctaka ne", 2) << endl;
    cout << decryptRailFence("dnhaweedtees alf tl", 3) << endl;

    return 0;
}


Output:
atc toctaka ne
GsGsekfrek eoe
dnhaweedtees alf  tl
GeeksforGeeks 
attack at once
defend the east wall
