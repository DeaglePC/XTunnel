#ifndef __CRYPTOR_H__
#define __CRYPTOR_H__

#include <stdint.h>
#include <time.h>
#include <stdlib.h>

#include "aes.h"

enum CRYPT_METHOD
{
    CRYPT_CBC,
    CRYPT_CTR
};

void genRandomIv(uint8_t *buf, uint32_t length);

class Cryptor
{
private:
    struct AES_ctx m_ctx;
    uint8_t m_key[AES_KEYLEN];

    CRYPT_METHOD m_method;

    uint32_t PKCS7_padding(uint8_t *buf, uint32_t length);

public:
    Cryptor(CRYPT_METHOD method, uint8_t *key);
    ~Cryptor();

    uint32_t encrypt(uint8_t *iv, uint8_t *buf, uint32_t length);
    uint32_t decrypt(uint8_t *iv, uint8_t *buf, uint32_t length);
};

#endif // __CRYPTOR_H__