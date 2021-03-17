#include <stdio.h>
#include <openssl/sha.h>
#include <stdlib.h>

#ifdef __linux__

#include <sys/auxv.h>

#elif
#include <bits/types/time_t.h>
#include <time.h>
#endif

static const int MAX_HASH_SIZE = 48;

int main(int argc, char *argv[]) {
    int numOfZeros;
    /* check input argument */
    if (argc == 1) {
        fprintf(stderr, "usage: %s n\n", argv[0]);
        fprintf(stderr, "\tn: expected number of leading 0-bits in outputted SHA-384 hash.\n");
        return 6;
    }

    if (argc != 2
        || sscanf(argv[1], " %d ", &numOfZeros) != 1
        || numOfZeros < 0
        || numOfZeros > 384) {
        return 7;
    }
    /* initializes rand function */
    /*If program is compiled on linux, then random function is initialized using a more random seed.*/
#ifdef __linux__
    srand((unsigned int) getauxval(AT_RANDOM));
#elif
    time_t t;
    srand((unsigned) time(&t));
#endif

    /* 48*8=384; input size == output size; using smaller input size might cause inability to generate wanted output values */
    unsigned char inputToHash[MAX_HASH_SIZE];

    SHA512_CTX shaCtx; /* Context for SHA function */
    unsigned char hash[MAX_HASH_SIZE]; /* char array for hash */

    /* init input array */
    for (int i = 0; i < MAX_HASH_SIZE; i++) {
        inputToHash[i] = 0;
    }

    while (1) {
        inputToHash[rand() % MAX_HASH_SIZE]++; /* increments random element in array */

        /* Hash the text */
        if (!SHA384_Init(&shaCtx)) { /* context setup for our hash type */
            return 3;
        }

        if (!SHA384_Update(&shaCtx, inputToHash, MAX_HASH_SIZE)) {/* feed the message in */
            return 4;
        }

        if (!SHA384_Final(hash, &shaCtx)) {/* get the hash */
            return 5;
        }

        uint8_t nextIteration = 0;
        /* goes by entire bytes */
        for (int i = 0; i < numOfZeros / 8; i++) {
            if (hash[i] != 0x00) {
                nextIteration++;
                break;
            }
        }
        /* goes through the rest */
        if (!nextIteration && hash[numOfZeros / 8] >> (8 - (numOfZeros % 8)) == 0x00) {
            break;
        }
    }

    /* Write hash function input data*/
    for (int i = 0; i < MAX_HASH_SIZE; i++) {
        printf("%02x", inputToHash[i]);
    }
    printf("\n");

    /* Write output hash */
    for (int i = 0; i < MAX_HASH_SIZE; i++)
        printf("%02x", hash[i]);
    printf("\n");
    return 0;
}
