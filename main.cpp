/*
 * This project is created to show the point of Rijndael algo.
 * It's quite easy, main functions are encode and decode. (their names speak for themselves)
 * First part is used for 'key expansion', this is creation of special Rijndael key from input key.
 * Second part is used for encoding/decoding from expansed key.
 * Encoding consists of #ROUNDS rounds, more rounds: stronger cipher text.
 * I use 10 rounds.
 *
 * Author: Mukhin Dmitry.
 * Moscow, Russia 2020.
 */

#include <vector>

#define SIZE 256
#define WORD_SIZE 4
#define ROUNDS 10
#define TEXT_SIZE 16

using namespace std;

//FUNCTIONS FOR KEY EXPANSION

int *rotWord(int *word) {
    int *newWord = new int[WORD_SIZE];
    for (int i = 0; i < WORD_SIZE; ++i)
        newWord[i] = word[(i + 1) % WORD_SIZE];
    return newWord;
}

int main() {


    return 0;
}
