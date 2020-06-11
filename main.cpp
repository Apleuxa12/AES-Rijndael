/*
 * This project is created to show the main point of Rijndael algo.(Advanced Encryption Standard for now)
 * It's quite easy, main functions are encode and decode. (their names speak for themselves)
 * First part is used for 'key expansion', this is creation of special Rijndael key from input key. (it is #ROUNDS times larger)
 * Second part is used for encoding/decoding from expanded key.
 * Encoding consists of #ROUNDS rounds, more rounds: stronger cipher text.
 * I use 10 rounds.
 * This is 128-bit version of AES, that means that block of cipher text consists of 16 symbols. (key too)
 * (Read more at: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
 *
 * Author: Mukhin Dmitry.
 * Moscow, Russia 2020.
 */

#include <string>
#include <iostream>

#define SIZE 256
#define WORD_SIZE 4
#define ROUNDS 10
#define TEXT_SIZE 16

int sbox[SIZE] = {
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

int invsbox[SIZE] = {
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

//Warning: if you want to change number of rounds, you should change your rcon array!
int rcon[ROUNDS + 1][WORD_SIZE] = {
        {0x00, 0x00, 0x00, 0x00},
        {0x01, 0x00, 0x00, 0x00},
        {0x02, 0x00, 0x00, 0x00},
        {0x04, 0x00, 0x00, 0x00},
        {0x08, 0x00, 0x00, 0x00},
        {0x10, 0x00, 0x00, 0x00},
        {0x20, 0x00, 0x00, 0x00},
        {0x40, 0x00, 0x00, 0x00},
        {0x80, 0x00, 0x00, 0x00},
        {0x1b, 0x00, 0x00, 0x00},
        {0x36, 0x00, 0x00, 0x00}
};

int mix[WORD_SIZE][WORD_SIZE] = {
        {0x02, 0x03, 0x01, 0x01},
        {0x01, 0x02, 0x03, 0x01},
        {0x01, 0x01, 0x02, 0x03},
        {0x03, 0x01, 0x01, 0x02}
};

int invmix[WORD_SIZE][WORD_SIZE] = {
        {0x0e, 0x0b, 0x0d, 0x09},
        {0x09, 0x0e, 0x0b, 0x0d},
        {0x0d, 0x09, 0x0e, 0x0b},
        {0x0b, 0x0d, 0x09, 0x0e}
};

//FUNCTIONS FOR KEY EXPANSION

//RotWord procedure: shift bytes of word on 1 at right
int *rotWord(int *word) {
    int *newWord = new int[WORD_SIZE];
    for (int i = 0; i < WORD_SIZE; ++i)
        newWord[i] = word[(i + 1) % WORD_SIZE];
    return newWord;
}

//SubWord procedure: change every byte to appropriate from the sbox array
int *subWord(int *word) {
    int *newWord = new int[WORD_SIZE];
    for (int i = 0; i < WORD_SIZE; ++i) {
        newWord[i] = sbox[word[i]];
    }
    return newWord;
}

//Rcon procedure: xor every byte with appropriate in rcon array, depending on round.
int *sumRcon(int *word, int round) {
    int *newWord = new int[WORD_SIZE];
    for (int i = 0; i < WORD_SIZE; ++i) {
        newWord[i] = word[i] ^ rcon[round][i];
    }
    return newWord;
}

//Final g function for key expansion, composition of all listed below functions
int *g(int *word, int round) {
    return sumRcon(subWord(rotWord(word)), round);
}

//Split one-dimensional array into 2-dimensional array, because key expansion works with 2-dimensional array
void splitKey(int *key, int N, int result[][WORD_SIZE]) {

    int counter = 0;

    for (int i = 0; i < N; ++i) {
        result[counter][i % WORD_SIZE] = key[i];

        if ((i + 1) % WORD_SIZE == 0)
            ++counter;
    }
}

//Xor of 2 arrays
int *keySum(int *key1, int *key2) {
    int *res = new int[WORD_SIZE];

    for (int i = 0; i < WORD_SIZE; ++i)
        res[i] = key1[i] ^ key2[i];

    return res;
}

//KeyExpansion function (key is input key, keys_size is its size, gkeys - expanded key)
void keyExpansion(int *key, int keys_size, int gkeys[][WORD_SIZE]) {

    int keys[keys_size][WORD_SIZE];

    splitKey(key, WORD_SIZE * keys_size, keys);

    //zero round
    for (int i = 0; i < keys_size; ++i) {
        for (int j = 0; j < WORD_SIZE; ++j) {
            gkeys[i][j] = keys[i][j];
        }
    }

    int round = 1;

    //main key expansion algo
    for (int i = keys_size; i < keys_size * (ROUNDS + 1); i += keys_size) {
        int *ws[keys_size];

        ws[0] = keySum(g(gkeys[i - 1], round++), gkeys[i - keys_size]);

        for (int k = 1; k < keys_size; ++k) {
            ws[k] = keySum(ws[k - 1], gkeys[i - (keys_size - k)]);
        }

        for (int j = 0; j < WORD_SIZE; ++j) {
            for (int k = 0; k < keys_size; ++k) {
                gkeys[i + k][j] = ws[k][j];
            }
        }
    }
}

// FUNCTIONS FOR RIJNDAEL ENCODING

//Shift rows of input array on right, first row on 1 pos, second on 2 pos, ... , n on n pos.
void shiftRows(int state[][WORD_SIZE]) {

    int newState[WORD_SIZE][WORD_SIZE];

    for (int i = 0; i < WORD_SIZE; ++i) {
        for (int j = 0; j < WORD_SIZE; ++j) {
            newState[i][j] = state[i][(i + j) % WORD_SIZE];
        }
    }

    for (int i = 0; i < WORD_SIZE; ++i) {
        for (int j = 0; j < WORD_SIZE; ++j) {
            state[i][j] = newState[i][j];
        }
    }
}

//Multiplication in Galois Field (2^n)
// (see more at https://en.wikipedia.org/wiki/Finite_field_arithmetic, 'Rijndael's (AES) finite field' part).
int gfmult(int a, int b) {
    int res = 0;
    for (; b; b >>= 1) {
        if (b & 1)
            res ^= a;
        if (a & 0x80)
            a = (a << 1) ^ 0x11b;
        else
            a <<= 1;
    }
    return res;
}

//MixColumns procedure: matrix multiplication of input array and mix array (don't remember we are in Galois Field (2^n))
void mixColumns(int state[][WORD_SIZE]) {

    int newState[WORD_SIZE][WORD_SIZE];

    for (int i = 0; i < WORD_SIZE; ++i) {
        for (int j = 0; j < WORD_SIZE; ++j) {
            int s = 0;
            for (int k = 0; k < WORD_SIZE; ++k) {
                s ^= gfmult(mix[i][k], state[k][j]);
            }
            newState[i][j] = s;
        }
    }

    for (int i = 0; i < WORD_SIZE; ++i) {
        for (int j = 0; j < WORD_SIZE; ++j) {
            state[i][j] = newState[i][j];
        }
    }
}

//Change byte to appropriate from sbox array
int subByte(int x) {
    return sbox[x];
}

//SubByteState procedure: use subByte to every byte of input array
void subByteState(int state[WORD_SIZE][WORD_SIZE]) {
    for (int i = 0; i < WORD_SIZE; ++i) {
        for (int j = 0; j < WORD_SIZE; ++j) {
            state[i][j] = subByte(state[i][j]);
        }
    }
}

//Adding round key to state - xor part of keys and current state (state is input text, keys is expanded key, round is current round)
void addRoundKey(int state[WORD_SIZE][WORD_SIZE], int keys[][WORD_SIZE], int round) {
    for (int i = 0; i < WORD_SIZE; ++i) {
        for (int j = 0; j < WORD_SIZE; ++j) {
            state[i][j] = state[i][j] ^ keys[j + round * WORD_SIZE][i];
        }
    }
}

using namespace std;

//Encode: text is input text, key is input key, cipherText is encoded cipher text (Everything should be in HEX!)
void encode(int *text, int *key, int cipherText[TEXT_SIZE]) {

    int keys[WORD_SIZE * (ROUNDS + 1)][WORD_SIZE];

    keyExpansion(key, WORD_SIZE, keys);

    int state[WORD_SIZE][WORD_SIZE];

    int round = 0;

    //zero round
    for (int i = 0; i < TEXT_SIZE; ++i)
        state[i % WORD_SIZE][i / WORD_SIZE] = text[i];

    addRoundKey(state, keys, round);

    for (round = 1; round < ROUNDS + 1; ++round) {

        subByteState(state);
        shiftRows(state);
        if (round != ROUNDS)
            mixColumns(state);

        addRoundKey(state, keys, round);
    }

    for (int i = 0; i < WORD_SIZE; ++i) {
        for (int j = 0; j < WORD_SIZE; ++j) {
            cipherText[i + j * WORD_SIZE] = state[i][j];
        }
    }
}

// FUNCTIONS FOR RIJNDAEL DECODING

//Shift rows of input array on left, first row on 1 pos, second on 2 pos, ... , n on n pos. (inversion to shiftRows procedure)
void invShiftRows(int state[][WORD_SIZE]) {

    int newState[WORD_SIZE][WORD_SIZE];

    for (int i = 0; i < WORD_SIZE; ++i) {
        for (int j = 0; j < WORD_SIZE; ++j) {
            newState[i][(i + j) % WORD_SIZE] = state[i][j];
        }
    }

    for (int i = 0; i < WORD_SIZE; ++i) {
        for (int j = 0; j < WORD_SIZE; ++j) {
            state[i][j] = newState[i][j];
        }
    }
}

//InvMixColumns procedure: matrix multiplication of input array and invMix array (inversion to mixColumns procedure)
void invMixColumns(int state[][WORD_SIZE]) {

    int newState[WORD_SIZE][WORD_SIZE];

    for (int i = 0; i < WORD_SIZE; ++i) {
        for (int j = 0; j < WORD_SIZE; ++j) {
            int s = 0;
            for (int k = 0; k < WORD_SIZE; ++k) {
                s ^= gfmult(invmix[i][k], state[k][j]);
            }
            newState[i][j] = s;
        }
    }

    for (int i = 0; i < WORD_SIZE; ++i) {
        for (int j = 0; j < WORD_SIZE; ++j) {
            state[i][j] = newState[i][j];
        }
    }
}

//Change byte to appropriate from invsbox array
int invSubByte(int hex) {
    return invsbox[hex];
}

//InvSubByteState procedure: use invSubByte to every byte of input array
void invSubByteState(int state[WORD_SIZE][WORD_SIZE]) {
    for (int i = 0; i < WORD_SIZE; ++i) {
        for (int j = 0; j < WORD_SIZE; ++j) {
            state[i][j] = invSubByte(state[i][j]);
        }
    }
}

//Inversive adding of round key, xor part of keys from the end and current state (state is input text, keys is expanded key, round is current round)
void invAddRoundKey(int state[WORD_SIZE][WORD_SIZE], int keys[][WORD_SIZE], int round) {
    for (int i = 0; i < WORD_SIZE; ++i) {
        for (int j = 0; j < WORD_SIZE; ++j) {
            state[i][j] = state[i][j] ^ keys[j + (ROUNDS - round) * WORD_SIZE][i];
        }
    }
}

//Decode: text is input text, key is input key, cipherText is decoded cipher text (Everything should be in HEX!)
void decode(int *cipherText, int *key, int text[TEXT_SIZE]) {

    int keys[WORD_SIZE * (ROUNDS + 1)][WORD_SIZE];

    //To decode we use same key expansion
    keyExpansion(key, WORD_SIZE, keys);

    int state[WORD_SIZE][WORD_SIZE];

    int round = 0;

    //zero round
    for (int i = 0; i < TEXT_SIZE; ++i)
        state[i % WORD_SIZE][i / WORD_SIZE] = cipherText[i];

    invAddRoundKey(state, keys, round);

    for (round = 1; round < ROUNDS + 1; ++round) {

        invShiftRows(state);
        invSubByteState(state);
        invAddRoundKey(state, keys, round);

        if (round != ROUNDS)
            invMixColumns(state);
    }

    for (int i = 0; i < WORD_SIZE; ++i) {
        for (int j = 0; j < WORD_SIZE; ++j) {
            text[i + j * WORD_SIZE] = state[i][j];
        }
    }
}

using namespace std;

int main() {

    //Example

    string text = "Hello, world!!!!";

    //Text as hex
    int hexText[TEXT_SIZE] = {
            0x48, 0x65, 0x6c, 0x6c,
            0x6f, 0x2c, 0x20, 0x77,
            0x6f, 0x72, 0x6c, 0x64,
            0x21, 0x21, 0x21, 0x21,
    };

    cout << "Input text: " << endl;
    for(int i = 0; i < TEXT_SIZE; ++i)
        cout << hex << hexText[i] << " ";
    cout << endl;

    string key = "Two One Nine Two";

    //Key as Hex
    int hexKey[TEXT_SIZE] = {
            0x54, 0x77, 0x6F, 0x20,
            0x4F, 0x6E, 0x65, 0x20,
            0x4E, 0x69, 0x6E, 0x65,
            0x20, 0x54, 0x77, 0x6F
    };

    cout << "Key: " << endl;
    for(int i = 0; i < TEXT_SIZE; ++i){
        cout << hexKey[i] << " ";
    }
    cout << endl;

    int cipherText[TEXT_SIZE];

    encode(hexText, hexKey, cipherText);

    cout << "Encoded text: " << endl;
    for(int i = 0; i < TEXT_SIZE; ++i){
        cout << hex << cipherText[i] << " ";
    }
    cout << endl;

    int realText[TEXT_SIZE];

    decode(cipherText, hexKey, realText);

    cout << "Decoded text: " << endl;
    for(int i = 0; i < TEXT_SIZE; ++i){
        cout << hex << realText[i] << " ";
    }
    cout << endl;

    return 0;
}
