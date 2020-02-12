#ifndef __MSGDATA_H__
#define __MSGDATA_H__

#include "../third_part/aes.h"
#include "cryptor.h"

const size_t PW_MAX_LEN = 32; // len of md5
const size_t MAX_BUF_SIZE = 1024 * 1024 * 5; // 1m


enum MSGTYPE
{
    MSGTYPE_HEARTBEAT = 1,      // 心跳
    MSGTYPE_NEW_PROXY,          // 服务端-》客户端，建立一个新的代理连接
    MSGTYPE_REPLY_NEW_PROXY,    // 客户端-》 服务端， 返回是否成功建立连接
    MSGTYPE_CLIENT_APP_DATA,    // 客户端发来的应用数据
    MSGTYPE_LOCAL_DOWN,         // 本地应用断开连接
    MSGTYPE_USER_DOWN           // 用户断开连接
};

struct MsgData
{
    int type{-1};   // 消息类型
    int size{0};    // 结构体之后的数据大小
    int userid{0};
};

struct NewProxyMsg
{
    int UserId;                // 客户端在服务端的id，暂时用客户端的connection fd表示
    unsigned short rmeotePort; // 对外暴露的端口
};

struct ReplyNewProxyMsg
{
    bool IsSuccess;
};

struct DataHeader
{
    uint32_t dataLen;
    uint8_t iv[AES_BLOCKLEN];
    DataHeader() : dataLen(0) {}

    uint32_t ensureTargetDataSize()
    {
        return dataLen > 0 ? dataLen : sizeof(DataHeader);
    }
};


const char HEARTBEAT_CLIENT_MSG[] = "ping";
const char HEARTBEAT_SERVER_MSG[] = "pong";

const char AUTH_TOKEN[] = "DGPJCY";

class MsgUtil
{
private:
public:
    MsgUtil();
    ~MsgUtil();

    static uint32_t ensureCryptedDataSize(uint32_t dataLen);
    static uint32_t packCryptedData(Cryptor* cryptor, uint8_t *buf, uint8_t *data, uint32_t dataSize);
};

#endif