#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

#define INPUT_ARRAY_SIZE 48

int main (int argc, char * argv[]) {

    int numOfZeros;
    //check input argument
    if(argc != 2
        || sscanf(argv[1], " %d ", &numOfZeros ) != 1
        || numOfZeros < 0
        || numOfZeros > 384) {
        return 6;
    }
    printf("numOfZeros: %d\n", numOfZeros);

    char text[] = "Text pro hash.";
    uint8_t inputToHash[INPUT_ARRAY_SIZE]; //48*8=384; input size == output size; using smaller input size might cause inability to generate wanted output values
    char hashFunction[] = "sha384";  // zvolena hashovaci funkce ("sha1", "md5", ...)

    EVP_MD_CTX * ctx;  // struktura kontextu
    const EVP_MD * type; // typ pouzite hashovaci funkce
    unsigned char hash[EVP_MAX_MD_SIZE]; // char pole pro hash - 64 bytu (max pro sha 512)
    unsigned int length;  // vysledna delka hashe

    /* Inicializace OpenSSL hash funkci */
    OpenSSL_add_all_digests();
    /* Zjisteni, jaka hashovaci funkce ma byt pouzita */
    type = EVP_get_digestbyname(hashFunction);

    /* Pokud predchozi prirazeni vratilo -1, tak nebyla zadana spravne hashovaci funkce */
    if (!type) {
        printf("Hash %s neexistuje.\n", hashFunction);
        return 1;
    }

    ctx = EVP_MD_CTX_new(); // create context for hashing
    if (ctx == NULL)
        return 2;


    //init input array
    for(int i = 0; i < INPUT_ARRAY_SIZE; i++) {
        inputToHash[i] = 0;
    }

    int a=0;
    while(a++ < 2) {
        printf("Iteration %d: ", a);

        inputToHash[rand() % INPUT_ARRAY_SIZE]++; //increments random element in array
//        inputToHash[rand() % INPUT_ARRAY_SIZE] ^= (uint8_t)(rand() % 128); //experimental for now

        /* Hash the text */
        if (!EVP_DigestInit_ex(ctx, type, NULL)) // context setup for our hash type
            return 3;

        if (!EVP_DigestUpdate(ctx, inputToHash, INPUT_ARRAY_SIZE)) // feed the message in
            return 4;

        if (!EVP_DigestFinal_ex(ctx, hash, &length)) // get the hash
            return 5;

        for (unsigned int i = 0; i < length; i++)
            printf("%02x", hash[i]);
        printf("\n");

        //todo check 0-bits
    }


    EVP_MD_CTX_free(ctx); // destroy the context

    /* Vypsani vysledneho hashe */
    printf("Hash textu \"%s\" je: ", text);
    for (unsigned int i = 0; i < length; i++)
        printf("%02x", hash[i]);
    printf("\n");
    return 0;
}
