#ifndef __SERVER_H__
#define __SERVER_H__

#include "tnet.h"
#include "reactor.h"
#include "msgdata.h"
#include <cstdio>
#include <unordered_map>
#include <vector>

const unsigned short DEFAULT_PORT = 10086;
const size_t AUTH_BUF_SIZE = 32;
const size_t MAX_BUF_SIZE = 1024;

struct ClientInfo
{
  int authRecvNum;
  char authBuf[AUTH_BUF_SIZE];

  MsgData msgData;
  int recvNum;
  int recvSize;
  char recvBuf[MAX_BUF_SIZE];

  std::vector<unsigned short> remotePorts;

  ClientInfo() : authRecvNum(0), recvNum(0) {}
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

  ClientInfoMap m_mapClients;
  ListenInfoMap m_mapListen;
  UserInfoMap m_mapUsers;
  ProxyConnInfoMap m_mapProxy;

  int listenControl(); // 监听服务器控制端口，负责新客户端接入
  int listenProxy();   // 监听代理端口，负责客户端建立代理连接
  void initServer();
  void serverAcceptProc(int fd, int mask);
  void clientAuthProc(int fd, int mask);       // 1.接收客户端的认证消息
  void replyClientAuthProcY(int fd, int mask); // 回复客户端认证成功
  void replyClientAuthProcN(int fd, int mask); // 回复认证失败
  void replyClientAuth(int fd, bool isGood);   // 回复认证结果
  void recvClientProxyPorts(int fd, int mask); // 2.接收客户端发来的需要监听的外网端口
  void recvClientDataProc(int fd, int mask);   // 正常建立链接后，客户端和服务器交互的数据处理
  void processClientBuf(int cfd);
  void userAcceptProc(int fd, int mask); // 接收user的连接
  void sendClientNewProxy(int cfd, int ufd, unsigned short port);

  void processNewProxy(ReplyNewProxyMsg rnpm);

  int listenRemotePort(int cfd);                // 监听cfd客户端的远程端口
  void proxyAcceptProc(int fd, int mask);       // 代理端口收到新连接的处理
  void proxyReadUserInfoProc(int fd, int mask); // 首次接收是和哪个user进行数据转发

  void proxyReadDataProc(int fd, int mask);  // 接收客户端代理通道发来的数据
  void proxyWriteDataProc(int fd, int mask); // 给客户端的代理通道发送数据
  void userReadDataProc(int fd, int mask);   // 接收用户发来的数据
  void userWriteDataProc(int fd, int mask);  // 给用户发送的数据

  void deleteClient(int fd);
  void deleteUser(int fd);
  void deleteProxyConn(int fd);

public:
  Server(unsigned short port = DEFAULT_PORT);
  ~Server();
  void setPassword(const char *password);
  void startEventLoop();
};

#endif // __SERVER_H__