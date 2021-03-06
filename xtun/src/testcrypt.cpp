#include "aes.hpp"
#include <stdio.h>
#include <vector>

#include "cryptor.h"

std::vector<uint8_t> key = {0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                            0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};

std::vector<uint8_t> iv = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

/*
uint8_t key[] = { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                      0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 };

uint8_t iv[]  = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
*/

void display(uint8_t *src, uint32_t len)
{
    for (int i = 0; i < len; i++)
    {
        printf("%02x ", src[i]);
        if ((i + 1) % 8 == 0)
        {
            printf("\n");
        }
    }
    printf("\n");
}

void test(CRYPT_METHOD method)
{
    uint8_t in[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

    Cryptor cryptor(method, key.data());
    uint32_t len = cryptor.encrypt(iv.data(), in, 16);

    display(in, len);
    printf("===========================\n");

    uint32_t dlen = cryptor.decrypt(iv.data(), in, len);
    display(in, dlen);
}

int main(int argc, char const *argv[])
{
    test(CRYPT_CTR);
    printf("##########################\n");
    test(CRYPT_CBC);

    uint8_t c[16];
    genRandomIv(c, 16);
    display(c, 16);

    return 0;
}
