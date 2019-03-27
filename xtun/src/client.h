#ifndef __CLIENT_H__
#define __CLIENT_H__
#include <netinet/in.h>
#include <vector>
#include <unordered_map>
#include "reactor.h"
#include "msgdata.h"

const size_t PW_MAX_LEN = 32; // len of md5
const size_t MAX_BUF_SIZE = 1024;

struct ProxyInfo
{
  unsigned short remotePort;
  unsigned short localPort;
  char localIp[INET_ADDRSTRLEN];
};

enum AUTH_STATUS
{
  AUTH_ERR = -1,  // 程序出错
  AUTH_OK = 0,    // 密码正确
  AUTH_WRONG = 1, // 密码错误
  AUTH_UNKNOW     // 服务器返回了未知数据
};

struct NetData
{
  size_t recvNum;
  size_t recvSize;
  MsgData msgData;
  char buf[MAX_BUF_SIZE];
  NetData() : recvNum(0), recvSize(sizeof(msgData)) {}
};

struct ProxyConnInfo
{
  /* data */
  int localFd;

  int sendSize;
  char sendBuf[MAX_BUF_SIZE];
  ProxyConnInfo() : sendSize(0) {}
};
using ProxyConnInfoMap = std::unordered_map<int, ProxyConnInfo>;

struct LocalConnInfo
{
  /* data */
  int proxyFd;

  int sendSize;
  char sendBuf[MAX_BUF_SIZE];
  LocalConnInfo() : sendSize(0) {}
};
using LocalConnInfoMap = std::unordered_map<int, LocalConnInfo>;

class Client
{
private:
  std::vector<ProxyInfo> m_configProxy;
  unsigned short m_serverPort;
  unsigned short m_serverProxyPort;
  char m_serverIp[INET_ADDRSTRLEN];
  int m_clientSocketFd;

  Reactor m_reactor;
  NetData m_clientData;

  ProxyConnInfoMap m_mapProxyConn;
  LocalConnInfoMap m_mapLocalConn;

  void clientReadProc(int fd, int mask);
  int sendPorts();
  void porcessMsgBuf();
  void makeNewProxy(NewProxyMsg newProxy);
  int connectLocalApp(unsigned short remotePort);
  int connectServerProxy();
  void replyNewProxy(int userId, bool isSuccess);
  int sendProxyInfo(int porxyFd, int userId);

  void localReadDataProc(int fd, int mask);
  void localWriteDataProc(int fd, int mask);
  void proxyReadDataProc(int fd, int mask);
  void proxyWriteDataProc(int fd, int mask);

  void deleteProxyConn(int fd);
  void deleteLocalConn(int fd);

public:
  Client(const char *sip, unsigned short sport);
  ~Client();

  void setProxyConfig(const std::vector<ProxyInfo> &pcs);
  void setProxyPort(unsigned short proxyPort);
  int connectServer();
  int authServer(const char *password);
  void runClient();
};

#endif // __CLIENT_H__