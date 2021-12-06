#include <iostream>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>

namespace crypto {
    RSA* createRSAKeyPair(int bits) {
        RSA* keyPair = RSA_new();
        BIGNUM* e = BN_new();
        BN_set_word(e, 65537);
        RSA_generate_key_ex(keyPair, bits, e, NULL);
        BN_free(e);
        return keyPair;
    }
}