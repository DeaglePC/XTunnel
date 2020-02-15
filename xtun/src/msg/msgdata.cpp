#include <cstring>

#include "msgdata.h"


uint32_t MsgUtil::ensureEncryptedDataSize(uint32_t dataLen)
{
    return sizeof(DataHeader) + dataLen + AES_BLOCKLEN;
}

uint32_t MsgUtil::packEncryptedData(const std::unique_ptr<Cryptor>& cryptor, uint8_t *buf, uint8_t *data, uint32_t dataSize)
{
    if(buf == nullptr || data == nullptr || !dataSize)
    {
        return dataSize;
    }

    DataHeader dataHeader;
    size_t headerLen = sizeof(DataHeader);

    genRandomIv(dataHeader.iv, sizeof(dataHeader.iv));
    memcpy(buf + headerLen, data, dataSize);
    dataHeader.dataLen = cryptor->encrypt(dataHeader.iv, buf + headerLen, dataSize);
    memcpy(buf, &dataHeader, headerLen);

    return dataHeader.dataLen + headerLen;
}
