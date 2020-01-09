#ifndef __CLIENT_H__
#define __CLIENT_H__

#include <netinet/in.h>
#include <vector>
#include <unordered_map>

#include "../msg/msgdata.h"
#include "../msg/cryptor.h"

#include "../net/reactor.h"
#include "../third_part/logger.h"


extern const size_t PW_MAX_LEN; // len of md5
extern const size_t MAX_BUF_SIZE;

const int HEARTBEAT_INTERVAL_MS = 1000; // 每次心跳的间隔时间
const long DEFAULT_SERVER_TIMEOUT_MS = 5000; // 默认5秒没收到服务端的心跳表示服务端不在线

extern const char HEARTBEAT_CLIENT_MSG[];
extern const char HEARTBEAT_SERVER_MSG[];

extern const char AUTH_TOKEN[];


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
  SEND_PW_OK,     // 发送密码成功
  AUTH_UNKNOW     // 服务器返回了未知数据
};


struct NetData
{
  size_t recvNum;
  size_t recvSize;

  DataHeader header;

  char recvBuf[MAX_BUF_SIZE + AES_BLOCKLEN + sizeof(DataHeader)];

  size_t sendNum;
  size_t sendSize;
  char sendBuf[MAX_BUF_SIZE + AES_BLOCKLEN + sizeof(DataHeader)];
  NetData() : recvNum(0), recvSize(0) {}
};


struct ProxyConnInfo
{
  int localFd;

  int sendSize;
  char sendBuf[MAX_BUF_SIZE + AES_BLOCKLEN + sizeof(DataHeader)];

  DataHeader header;
  size_t recvNum;
  size_t recvSize;
  char recvBuf[MAX_BUF_SIZE + AES_BLOCKLEN + sizeof(DataHeader)];

  ProxyConnInfo() : sendSize(0), recvNum(0), recvSize(0) {}
};
using ProxyConnInfoMap = std::unordered_map<int, ProxyConnInfo>;


struct LocalConnInfo
{
  int proxyFd;

  size_t sendSize;
  char sendBuf[MAX_BUF_SIZE + AES_BLOCKLEN + sizeof(DataHeader)];

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
  char m_password[PW_MAX_LEN];
  Logger *m_pLogger;

  long long m_heartTimerId;
  long m_maxServerTimeout;   // 多少毫秒没收到服务端的心跳表示断开了连接
  long long m_lastServerHeartbeatMs; // 时间戳，上次收到服务端心跳的时间

  Reactor m_reactor;
  NetData m_clientData;

  ProxyConnInfoMap m_mapProxyConn;
  LocalConnInfoMap m_mapLocalConn;

  Cryptor *m_pCryptor;

  void serverSafeRecv(int fd, std::function<void(size_t dataSize)> callback);  // recv crypted msg from server
  void serverSafeSend(int fd, std::function<void(int fd)> callback);
  
  void clientReadProc(int fd, int mask);
  void onClientReadDone(size_t dataSize);

  int sendPorts();
  void makeNewProxy(NewProxyMsg newProxy);
  int connectLocalApp(unsigned short remotePort);
  int connectServerProxy();

  void replyNewProxy(int userId, bool isSuccess);
  void replyNewProxyProc(int fd, int mask);
  void onReplyNewProxyDone(int fd);

  int sendProxyInfo(int porxyFd, int userId);
  int sendHeartbeatTimerProc(long long id);
  void processHeartbeat();  // 收到服务端的心跳做的处理
  int checkHeartbeatTimerProc(long long id);

  void proxySafeRecv(int fd, std::function<void(int fd, size_t dataSize)> callback);
  void localReadDataProc(int fd, int mask);
  void onProxyReadDataDone(int fd, size_t dataSize);
  void localWriteDataProc(int fd, int mask);
  void proxyReadDataProc(int fd, int mask);
  void proxyWriteDataProc(int fd, int mask);

  void deleteProxyConn(int fd);
  void deleteLocalConn(int fd);

  int connectServer();

  int sendAuthPassword();
  int checkAuthResult();
  int authServer();

  void initCryptor();

public:
  Client(const char *sip, unsigned short sport);
  ~Client();

  void setProxyConfig(const std::vector<ProxyInfo> &pcs);
  void setProxyPort(unsigned short proxyPort);
  void setPassword(const char *password);
  void setLogger(Logger* logger);
  
  void runClient();
  void stopClient();
};

#endif // __CLIENT_H__