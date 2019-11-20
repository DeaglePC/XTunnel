#ifndef __SERVER_H__
#define __SERVER_H__

#include <cstdio>
#include <unordered_map>
#include <vector>

#include "tnet.h"
#include "reactor.h"
#include "msgdata.h"
#include "logger.h"
#include "cryptor.h"

const unsigned short DEFAULT_PORT = 10086;
const unsigned short DEFAULT_PROXY_PORT = 10001;

const size_t AUTH_BUF_SIZE = 32;
const size_t MAX_BUF_SIZE = 1024;

const int HEARTBEAT_INTERVAL_MS = 1000;      // 每次心跳的间隔时间
const long DEFAULT_SERVER_TIMEOUT_MS = 5000; // 默认5秒没收到服务端的心跳表示服务端不在

extern const char HEARTBEAT_CLIENT_MSG[];
extern const char HEARTBEAT_SERVER_MSG[];

extern const char AUTH_TOKEN[];

enum ClientStatus
{
  CLIENT_STATUS_CONNECTED,
  CLIENT_STATUS_PW_OK,
  CLIENT_STATUS_PW_WRONG,
};

struct ClientInfo
{
  DataHeader header;

  MsgData msgData;
  size_t recvNum;
  size_t recvSize;
  char recvBuf[MAX_BUF_SIZE + AES_BLOCKLEN];  // AES_BLOCKLEN is for aes padding size
  
  size_t sendSize;
  char sendBuf[MAX_BUF_SIZE + AES_BLOCKLEN];

  ClientStatus status;
  
  long long lastHeartbeat; // 上次收到心跳的时间戳，如果是-1，表示还没初始化客户端，无需检测

  std::vector<unsigned short> remotePorts;

  ClientInfo() : recvNum(0), sendSize(0), lastHeartbeat(-1), status(CLIENT_STATUS_CONNECTED) {}
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
  int proxyFd;

  int sendSize; // 发送缓冲区现有数据
  char sendBuf[MAX_BUF_SIZE];
  UserInfo() : sendSize(0) {}
};
using UserInfoMap = std::unordered_map<int, UserInfo>;

struct ProxyConnInfo
{
  int userFd;

  int recvNum;
  int recvSize;
  char recvBuf[MAX_BUF_SIZE];

  int sendSize;
  char sendBuf[MAX_BUF_SIZE];
  ProxyConnInfo() : sendSize(0), recvNum(0), recvSize(0) {}
};
using ProxyConnInfoMap = std::unordered_map<int, ProxyConnInfo>;

class Server
{
private:
  Reactor m_reactor;
  int m_serverSocketFd;
  int m_proxySocketFd;
  unsigned short m_serverPort;
  unsigned short m_proxyPort;
  char m_serverPassword[AUTH_BUF_SIZE];

  Logger *m_pLogger;
  Cryptor *m_pCryptor;

  long long m_heartbeatTimerId;

  ClientInfoMap m_mapClients;
  ListenInfoMap m_mapListen;
  UserInfoMap m_mapUsers;
  ProxyConnInfoMap m_mapProxy;

  // server init methods
  int listenControl(); // 监听服务器控制端口，负责新客户端接入
  int listenProxy();   // 监听代理端口，负责客户端建立代理连接
  void initServer();
  void serverAcceptProc(int fd, int mask);

  void clientSafeRecv(int cfd, std::function<void(int cfd, size_t dataSize)> callback);

  // auth methods
  void clientAuthProc(int fd, int mask);       // 1.接收客户端的认证消息
  void processClientAuthResult(int cfd, bool isGood);
  void checkClientAuthResult(int cfd, size_t dataSize);
  void replyClientAuthProc(int cfd, int mask);   // 回复认证结果

  // proxy ports methods
  void checkClientProxyPortsResult(int cfd, size_t dataSize);
  void recvClientProxyPortsProc(int cfd, int mask);

  //void recvClientProxyPorts(int fd, int mask); // 2.接收客户端发来的需要监听的外网端口
  void recvClientDataProc(int fd, int mask);   // 正常建立链接后，客户端和服务器交互的数据处理
  void processClientBuf(int cfd);
  void userAcceptProc(int fd, int mask); // 接收user的连接
  void sendClientNewProxy(int cfd, int ufd, unsigned short port);
  void sendHeartbeat(int cfd);         // 回复心跳
  void updateClientHeartbeat(int cfd); // 更新客户端心跳时间

  int checkHeartbeatTimerProc(long long id); // 检查客户端心跳,定时器

  void processNewProxy(ReplyNewProxyMsg rnpm);  // 处理新代理连接
  int findClientfdByPort(unsigned short port);  // 通过对外端口查找属于哪个客户端
  bool isExistsPort(unsigned short port);       // 检查对外端口是不是已经被其他客户端使用了，如果使用了，则丢弃该客户端

  int listenRemotePort(int cfd);                // 监听cfd客户端的远程端口
  void proxyAcceptProc(int fd, int mask);       // 代理端口收到新连接的处理
  void proxyReadUserInfoProc(int fd, int mask); // 首次接收是和哪个user进行数据转发

  void proxyReadDataProc(int fd, int mask);  // 接收客户端代理通道发来的数据
  void proxyWriteDataProc(int fd, int mask); // 给客户端的代理通道发送数据
  void userReadDataProc(int fd, int mask);   // 接收用户发来的数据
  void userWriteDataProc(int fd, int mask);  // 给用户发送的数据

  void initClient(int fd);
  void deleteClient(int fd);
  void deleteUser(int fd);
  void deleteProxyConn(int fd);

  void initCryptor();

public:
  Server(unsigned short port = DEFAULT_PORT, unsigned short proxyPort = DEFAULT_PROXY_PORT);
  ~Server();
  void setPassword(const char *password);
  void setLogger(Logger *logger);
  void startEventLoop();
};

#endif // __SERVER_H__