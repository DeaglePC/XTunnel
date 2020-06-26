#ifndef __SERVER_H__
#define __SERVER_H__

#include <cstdio>
#include <unordered_map>
#include <vector>
#include <memory>

#include "../msg/msgdata.h"
#include "../msg/cryptor.h"

#include "../net/tnet.h"
#include "../net/reactor.h"
#include "../third_part/logger.h"


const unsigned short DEFAULT_PORT = 10086;

const int HEARTBEAT_INTERVAL_MS = 1000;      // 每次心跳的间隔时间
const long DEFAULT_SERVER_TIMEOUT_MS = 5000; // 默认5秒没收到服务端的心跳表示服务端不在


enum ClientStatus
{
  CLIENT_STATUS_CONNECTED,
  CLIENT_STATUS_PW_OK,
  CLIENT_STATUS_PW_WRONG,
};


struct ClientInfo
{
  DataHeader header;

  size_t recvNum{0};
  char recvBuf[MAX_BUF_SIZE + AES_BLOCKLEN];  // AES_BLOCKLEN is for aes padding size
  
  size_t sendSize{0};
  char sendBuf[MAX_BUF_SIZE + AES_BLOCKLEN];

  ClientStatus status{CLIENT_STATUS_CONNECTED};
  
  long long lastHeartbeat{-1}; // 上次收到心跳的时间戳，如果是-1，表示还没初始化客户端，无需检测

  std::vector<unsigned short> remotePorts;

  bool isSendBufFull()
  {
    return sendSize >= MAX_BUF_SIZE;
  }

  bool isRecvBufFull()
  {
    return recvNum >= MAX_BUF_SIZE;
  }

  char* currSendBufAddr()
  {
    return sendBuf + sendSize;
  }
};
using ClientInfoMap = std::unordered_map<int, ClientInfo>;


struct ListenInfo
{
  unsigned short port; //  监听的对外端口
  int clientFd;        // 属于哪个客户端
};
using ListenInfoMap = std::unordered_map<int, ListenInfo>;


struct UserInfo
{
  unsigned short port;
  int cfd;

  size_t sendSize{0}; // 发送缓冲区现有数据
  char sendBuf[MAX_BUF_SIZE + AES_BLOCKLEN + sizeof(DataHeader)];

  bool isSendBufFull()
  {
    return sendSize >= MAX_BUF_SIZE;
  }

  bool isSendBufFull(size_t size)
  {
      return sendSize + size >= MAX_BUF_SIZE;
  }

  char* currSendBufAddr()
  {
    return sendBuf + sendSize;
  }
};
using UserInfoMap = std::unordered_map<int, UserInfo>;


struct UserFullBufferInfo
{
    int ufd{-1};
    size_t msgSize{0};

    void reset()
    {
        ufd = -1;
        msgSize = 0;
    }

    bool isFull()
    {
        return ufd != -1;
    }
};


class Server
{
private:
  Reactor m_reactor;

  int m_serverSocketFd;

  unsigned short m_serverPort;

  char m_serverPassword[PW_MAX_LEN]{};

  std::shared_ptr<Logger> m_pLogger;
  std::unique_ptr<Cryptor> m_pCryptor;

  long long m_heartbeatTimerId{};

  ClientInfoMap m_mapClients;
  ListenInfoMap m_mapListen;
  UserInfoMap m_mapUsers;

  UserFullBufferInfo m_userFullBuffer;

  // server init methods
  int listenControl(); // 监听服务器控制端口，负责新客户端接入
  void initServer();
  void serverAcceptProc(int fd, int mask);

  // recv and send
  void clientSafeRecv(int cfd, const std::function<void(int cfd, size_t dataSize)>& callback);
  void clientSafeSend(int cfd, const std::function<void(int cfd)>& callback);

  // auth methods
  void clientAuthProc(int fd, int mask);       // 1.接收客户端的认证消息
  void checkClientAuthResult(int cfd, size_t dataSize); // callback func
  void processClientAuthResult(int cfd, bool isGood);
  void replyClientAuthProc(int cfd, int mask);   // 回复认证结果
  void onReplyClientAuthDone(int cfd);  // callback func

  // proxy ports methods
  void checkClientProxyPortsResult(int cfd, size_t dataSize);
  void recvClientProxyPortsProc(int cfd, int mask);

  void userAcceptProc(int fd, int mask); // 接收user的连接
  void sendClientNewProxy(int cfd, int ufd, unsigned short port);
  void sendClientNewProxyProc(int cfd, int mask);   
  void onSendClientNewProxyDone(int cfd); // callback

  void recvClientDataProc(int fd, int mask);   // 正常建立链接后，客户端和服务器交互的数据处理
  void processClientBuf(int cfd,  size_t dataSize);
  
  // heartbeat
  void sendHeartbeat(int cfd);         // 回复心跳
  void writeHeartbeatDataProc(int cfd, int mask);
  void onWriteHeartbeatDataDone(int cfd);

  void updateClientHeartbeat(int cfd); // 更新客户端心跳时间
  int checkHeartbeatTimerProc(long long id); // 检查客户端心跳,定时器

  void processNewProxy(const ReplyNewProxyMsg &rnpm, int uid);  // 处理新代理连接
  int findClientfdByPort(unsigned short port);  // 通过对外端口查找属于哪个客户端

  int listenRemotePort(int cfd);                // 监听cfd客户端的远程端口

  void userReadDataProc(int fd, int mask);   // 接收用户发来的数据
  void userWriteDataProc(int ufd, int mask);  // 给用户发送的数据
  void sendUserDataProc(int fd, int mask);  // 把用户发来的数据给客户端发过去
  void onSendUserDataDone(int fd);  // 发送完成时的回调

  void tellClientUserDown(int ufd);
  void tellClientUserDownProc(int cfd, int mask);
  void onTellClientUserDownDone(int cfd);

  void initClient(int fd);
  void deleteClient(int fd);
  void deleteUser(int fd);

public:
  explicit Server(std::shared_ptr<Logger> &logger, unsigned short port = DEFAULT_PORT);
  ~Server();

  void setPassword(const char *password);

  void startEventLoop();
};

#endif // __SERVER_H__