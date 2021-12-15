#include <string.h>
#include <iostream>
#include <openssl/evp.h>
#include <openssl/err.h>


namespace crypto {

    int hmac_it(const unsigned char *msg, size_t mlen, unsigned char **val, size_t *vlen, EVP_PKEY *pkey, const char* alg)
{
    int result = 0;
    EVP_MD_CTX* ctx = NULL;
    size_t req = 0;
    int rc;
    
    if(!msg || !mlen || !val || !pkey)
        return 0;
    
    *val = NULL;
    *vlen = 0;

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        std::cout << "EVP_MD_CTX_create failed, error" << ERR_get_error()<< std::endl;
        goto err;
    }

    if(strcmp(alg, "sha256") == 0) {
        rc = EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey);
    } else if (strcmp(alg, "sha384") == 0) {
        rc = EVP_DigestSignInit(ctx, NULL, EVP_sha384(), NULL, pkey);
    } else if (strcmp(alg, "sha512") == 0) {
        rc = EVP_DigestSignInit(ctx, NULL, EVP_sha512(), NULL, pkey);
    } else {
        std::cout << "EVP_MD_CTX_create failed, invalid algorithm" << std::endl;
        goto err;
    }
    
    
    if (rc != 1) {
        std::cout << "EVP_DigestSignInit failed, error 0x%lx\n" << ERR_get_error()<< std::endl;
        goto err;
    }
    
    rc = EVP_DigestSignUpdate(ctx, msg, mlen);
    if (rc != 1) {
        std::cout << "EVP_DigestSignUpdate failed, error 0x%lx\n" << ERR_get_error()<< std::endl;
        goto err;
    }
    
    rc = EVP_DigestSignFinal(ctx, NULL, &req);
    if (rc != 1) {
        std::cout << "EVP_DigestSignFinal failed (1), error 0x%lx\n" << ERR_get_error()<< std::endl;
        goto err;
    }
    
    *val = (unsigned char *)OPENSSL_malloc(req);
    if (*val == NULL) {
        std::cout << "OPENSSL_malloc failed, error 0x%lx\n" << ERR_get_error()<< std::endl;
        goto err;
    }
    
    *vlen = req;
    rc = EVP_DigestSignFinal(ctx, *val, vlen);
    if (rc != 1) {
        std::cout << "EVP_DigestSignFinal failed (3), return code %d, error 0x%lx\n" << rc << ERR_get_error()<< std::endl;
        goto err;
    }
    
    result = 1;
    
   
 err:
    EVP_MD_CTX_free(ctx);
    if (!result) {
        OPENSSL_free(*val);
        *val = NULL;
    }
    return result;
}

}