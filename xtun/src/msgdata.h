#ifndef __MSGDATA_H__
#define __MSGDATA_H__

enum MSGTYPE
{
    MSGTYPE_HEARTBEAT = 1, // 心跳
    MSGTYPE_NEW_PROXY,     // 服务端-》客户端，建立一个新的代理连接
    MSGTYPE_REPLY_NEW_PROXY// 客户端-》 服务端， 返回是否成功建立连接
};

struct MsgData
{
    int type; // 消息类型
    int size; // 结构体之后的数据大小
    MsgData() : type(-1), size(0) {}
};

struct NewProxyMsg
{
    int UserId;                // 客户端在服务端的id，暂时用客户端的connection fd表示
    unsigned short rmeotePort; // 对外暴露的端口
};

struct ReplyNewProxyMsg
{
    int UserId;
    bool IsSuccess;
};


#endif