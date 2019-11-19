#include "cryptor.h"

#include <netinet/in.h>
#include <string.h>


void genRandomIv(uint8_t *buf, uint32_t length)
{
    srand(time(NULL));

    for (uint32_t i = 0; i < length; i++)
    {
        buf[i] = rand() % UINT8_MAX;
    }
}

Cryptor::Cryptor(CRYPT_METHOD method, uint8_t *key) : m_method(method)
{
    if (key == nullptr)
    {
        return;
    }

    memcpy(m_key, key, AES_KEYLEN);
    AES_init_ctx(&m_ctx, key);
}

Cryptor::~Cryptor()
{
}

uint32_t Cryptor::PKCS7_padding(uint8_t *buf, uint32_t length)
{
    if (buf == nullptr)
    {
        return length;
    }

    uint8_t padding_len = AES_BLOCKLEN - length % AES_BLOCKLEN;

    for (uint32_t i = 0; i < padding_len; i++)
    {
        buf[length + i] = padding_len;
    }

    return length + padding_len;
}

uint32_t Cryptor::encrypt(uint8_t *iv, uint8_t *buf, uint32_t length)
{
    uint32_t res_len = PKCS7_padding(buf, length);
    AES_ctx_set_iv(&m_ctx, iv);

    if (m_method == CRYPT_CBC)
    {
        AES_CBC_encrypt_buffer(&m_ctx, buf, res_len);
    }
    else if (m_method == CRYPT_CTR)
    {
        AES_CTR_xcrypt_buffer(&m_ctx, buf, res_len);
    }

    return res_len;
}

uint32_t Cryptor::decrypt(uint8_t *iv, uint8_t *buf, uint32_t length)
{
    AES_ctx_set_iv(&m_ctx, iv);

    if (m_method == CRYPT_CBC)
    {
        AES_CBC_decrypt_buffer(&m_ctx, buf, length);
    }
    else if (m_method == CRYPT_CTR)
    {
        AES_CTR_xcrypt_buffer(&m_ctx, buf, length);
    }

    return length - buf[length - 1];
}
