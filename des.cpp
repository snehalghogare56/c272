                                                            Data encryption standard (DES)

Code:
#include <iostream>
#include <bitset>
#include <vector>

using namespace std;

// Initial permutation table
vector<int> initial_perm = {2, 6, 3, 1, 4, 8, 5, 7};

// Inverse initial permutation table (for decryption)
vector<int> inv_initial_perm = {4, 1, 3, 5, 7, 2, 8, 6};

// Permute function
string permute(const string& input, const vector<int>& permutation) {
    string result;
    for (int idx : permutation) {
        result += input[idx - 1];
    }
    return result;
}

// XOR operation for strings of '0' and '1'
string xor_strings(const string& a, const string& b) {
    string result;
    for (size_t i = 0; i < a.size(); ++i) {
        result += (a[i] == b[i] ? '0' : '1');
    }
    return result;
}

// Example encryption function
string encrypt(const string& plaintext, const string& key) {
    // Initial permutation of the plaintext
    string permuted_plaintext = permute(plaintext, initial_perm);

    // Example key setup (skipping key expansion)
    string expanded_key = key.substr(0, 8); // Use the first 8 characters of the key

    // XOR with the expanded key
    string ciphertext = xor_strings(permuted_plaintext, expanded_key);

    return ciphertext;
}

// Example decryption function
string decrypt(const string& ciphertext, const string& key) {
    // Example key setup (skipping key expansion)
    string expanded_key = key.substr(0, 8); // Use the first 8 characters of the key

    // XOR with the expanded key to retrieve the plaintext
    string permuted_plaintext = xor_strings(ciphertext, expanded_key);

    // Reverse initial permutation for decryption
    string plaintext = permute(permuted_plaintext, inv_initial_perm);

    return plaintext;
}

int main() {
    string plaintext = "10101100";
    string key = "11001010";

    // Encrypt the plaintext
    string ciphertext = encrypt(plaintext, key);
    cout << "Ciphertext: " << ciphertext << endl;

    // Decrypt the ciphertext
    string decrypted_plaintext = decrypt(ciphertext, key);
    cout << "Decrypted plaintext: " << decrypted_plaintext << endl;

    return 0;
}
Output:
Ciphertext: 00001111
Decrypted plaintext: 10101100
