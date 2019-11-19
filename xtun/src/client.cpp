#include "client.h"
#include <cstring>
#include <string>
#include "tnet.h"
#include "md5.h"

Client::Client(const char *sip, unsigned short sport) : m_clientSocketFd(-1), m_pLogger(nullptr)
{
    if (sip == NULL)
    {
        return;
    }
    strcpy(m_serverIp, sip);
    m_serverPort = sport;
    m_maxServerTimeout = DEFAULT_SERVER_TIMEOUT_MS;
}

Client::~Client()
{
    m_reactor.stopEventLoop();
    if (m_clientSocketFd != -1)
    {
        close(m_clientSocketFd);
        m_reactor.removeFileEvent(m_clientSocketFd, EVENT_READABLE | EVENT_WRITABLE);
    }

    for (const auto &it : m_mapProxyConn)
    {
        m_reactor.removeFileEvent(it.first, EVENT_READABLE | EVENT_WRITABLE);
        close(it.first);
    }
    for (const auto &it : m_mapLocalConn)
    {
        m_reactor.removeFileEvent(it.first, EVENT_READABLE | EVENT_WRITABLE);
        close(it.first);
    }

    if(m_pCryptor)
    {
        delete m_pCryptor;
    }
    m_pLogger->info("exit client...");
}

int Client::connectServer()
{
    m_clientSocketFd = tnet::tcp_generic_connect(m_serverIp, m_serverPort);
    if (m_clientSocketFd == NET_ERR)
    {
        return -1;
    }
    return 0;
}

int Client::sendAuthPassword()
{
    int ret, sendCnt = 0;

    uint8_t buf[MsgUtil::ensureCryptedDataSize(PW_MAX_LEN)];
    uint32_t dataLen = MsgUtil::packCryptedData(m_pCryptor, buf, (uint8_t*)m_password, PW_MAX_LEN);

    while (1)
    {
        ret = send(m_clientSocketFd, buf + sendCnt, dataLen - sendCnt, 0);
        if (ret > 0)
        {
            sendCnt += ret;
            if (sendCnt == dataLen)
            {
                break;
            }
        }
        else if (ret == -1)
        {
            printf("authServer send err: %d\n", errno);
            m_pLogger->err("authServer send err: %d", errno);
            return AUTH_ERR;
        }
        else if (ret == 0)
        {
            return AUTH_ERR;
        }
    }

    return SEND_PW_OK;
}

int Client::checkAuthResult()
{
    int ret;
    DataHeader header;
    uint8_t recvBuf[sizeof(DataHeader) + AES_BLOCKLEN];
    size_t targetSize, recvNum = 0;

    while (1)
    {
        targetSize = header.ensureTargetDataSize();
        ret = recv(m_clientSocketFd, recvBuf, targetSize, 0);  // block
        
        if (ret == targetSize)
        {
            if (targetSize == sizeof(DataHeader))
            {
                memcpy(&header, recvBuf, targetSize);
            }
            else
            {
                // shoud be sizeof(AUTH_TOKEN), if password is wrong, this value is a random number
                uint32_t realDataSize = m_pCryptor->decrypt(
                    header.iv,
                    recvBuf,
                    targetSize
                );

                if (!memcmp(AUTH_TOKEN, recvBuf, sizeof(AUTH_TOKEN)))
                {
                    return AUTH_OK;
                }
                else
                {
                    return AUTH_WRONG;
                }
            }
        }
        else if (ret == -1)
        {
            printf("authServer recv err: %d\n", errno);
            m_pLogger->err("authServer recv err: %d", errno);
            return AUTH_ERR;
        }
        else if (ret == 0)
        {
            printf("authServer server offline: %d\n", errno);
            m_pLogger->err("authServer server offline: %d", errno);
            return AUTH_UNKNOW;
        }
        else
        {
            // should never happen
            printf("authServer unknown error: %d\n", errno);
            m_pLogger->err("authServer unknown error: %d", errno);
            return AUTH_UNKNOW;
        }
    }
}

/*
 * 认证过程：
 * client->server: md5(password), len=32bytes
 * server->client: Y/N, len=1byte
 * return: -1: err, 0: ok, 1: wrong password
 */
int Client::authServer()
{
    if (sendAuthPassword() != SEND_PW_OK)
    {
        return AUTH_ERR;
    }
    printf("send password ok\n");

    return checkAuthResult();
}

int Client::sendPorts()
{
    size_t portNum = m_configProxy.size();
    if (portNum == 0)
    {
        return 0;
    }
    unsigned short ports[portNum + 1]; // [0]: 存放端口的数量，之后存放端口
    ports[0] = (unsigned short)portNum;
    for (int i = 0; i < portNum; i++)
    {
        ports[i + 1] = m_configProxy[i].remotePort;
    }
    int ret = send(m_clientSocketFd, ports, sizeof(ports), 0);
    if (ret == -1)
    {
        printf("sendPorts err: %d\n", errno);
        m_pLogger->err("sendPorts err: %d\n", errno);
        return -1;
    }
    else if (ret > 0)
    {
        printf("sendPorts num: %ld\n", portNum);
        m_pLogger->info("sendPorts num: %ld", portNum);
        return portNum;
    }
}

void Client::clientReadProc(int fd, int mask)
{
    int ret = recv(fd, m_clientData.buf + m_clientData.recvNum,
                   m_clientData.recvSize - m_clientData.recvNum, MSG_DONTWAIT);
    printf("recv:%d\n", ret);
    if (ret == -1)
    {
        if (errno != EAGAIN && EAGAIN != EWOULDBLOCK)
        {
            printf("clientReadProc err: %d\n", errno);
            m_pLogger->err("clientReadProc err: %d", errno);
            return;
        }
    }
    else if (ret == 0)
    {
        printf("clientReadProc server offline\n");
        m_pLogger->info("clientReadProc server offline");
        exit(-1);
    }
    else if (ret > 0)
    {
        m_clientData.recvNum += ret;
        if (m_clientData.recvNum == m_clientData.recvSize)
        {
            porcessMsgBuf();
        }
    }
}

void Client::porcessMsgBuf()
{
    // 解析结构体
    if (m_clientData.msgData.type < 0)
    {
        memcpy(&m_clientData.msgData, m_clientData.buf, m_clientData.recvSize);
        m_clientData.recvSize = m_clientData.msgData.size;
        m_clientData.recvNum = 0;
    }
    else if (m_clientData.msgData.type == MSGTYPE_HEARTBEAT)
    {
        m_clientData.recvSize = sizeof(MsgData);
        m_clientData.recvNum = 0;
        m_clientData.msgData.type = -1;

        if (strncmp(m_clientData.buf, HEARTBEAT_SERVER_MSG, strlen(HEARTBEAT_SERVER_MSG)) == 0)
        {
            processHeartbeat();
        }
    }
    else if (m_clientData.msgData.type == MSGTYPE_NEW_PROXY)
    {
        NewProxyMsg newProxy;
        memcpy(&newProxy, m_clientData.buf, m_clientData.recvSize);
        m_clientData.recvSize = sizeof(MsgData);
        m_clientData.recvNum = 0;
        m_clientData.msgData.type = -1;
        printf("new proxy %d %d\n", newProxy.UserId, newProxy.rmeotePort);
        m_pLogger->info("new proxy %d %d", newProxy.UserId, newProxy.rmeotePort);
        makeNewProxy(newProxy);
    }
}

void Client::processHeartbeat()
{
    long now_sec, now_ms;
    getTime(&now_sec, &now_ms);
    m_lastServerHeartbeatMs = now_sec * 1000 + now_ms;
}

int Client::checkHeartbeatTimerProc(long long id)
{
    long now_sec, now_ms;
    long long nowTimeStamp;
    getTime(&now_sec, &now_ms);
    nowTimeStamp = now_sec * 1000 + now_ms;
    long subTimeStamp = nowTimeStamp - m_lastServerHeartbeatMs;
    if (subTimeStamp > m_maxServerTimeout)
    {
        printf("server timeout %ldms\n", subTimeStamp);
        m_pLogger->info("server timeout %ldms", subTimeStamp);
        exit(-1);
    }
    printf("check heartbeat ok!%ld\n", subTimeStamp);
    return HEARTBEAT_INTERVAL_MS;
}

/* 创建新代理通道
 * 1.连接本地应用
 * 2.连接代理服务器
 * 3.反馈给服务端结果
 * 4.向代理服务器发送此次连接对应哪个userid，然后此连接只用做转发数据
 */
void Client::makeNewProxy(NewProxyMsg newProxy)
{
    int localFd = connectLocalApp(newProxy.rmeotePort);
    if (localFd == -1)
    {
        replyNewProxy(newProxy.UserId, false);
        return;
    }
    int proxyFd = connectServerProxy();
    if (proxyFd == -1)
    {
        replyNewProxy(newProxy.UserId, false);
        return;
    }
    ProxyConnInfo pci;
    pci.localFd = localFd;
    m_mapProxyConn[proxyFd] = pci;

    LocalConnInfo lci;
    lci.proxyFd = proxyFd;
    m_mapLocalConn[localFd] = lci;

    replyNewProxy(newProxy.UserId, true);
    sendProxyInfo(proxyFd, newProxy.UserId);
    // TODO regist event
    m_reactor.registFileEvent(localFd, EVENT_READABLE,
                              std::bind(&Client::localReadDataProc,
                                        this, std::placeholders::_1, std::placeholders::_2));
    m_reactor.registFileEvent(proxyFd, EVENT_READABLE,
                              std::bind(&Client::proxyReadDataProc,
                                        this, std::placeholders::_1, std::placeholders::_2));
}

void Client::localReadDataProc(int fd, int mask)
{
    int proxyFd = m_mapLocalConn[fd].proxyFd;
    if (m_mapProxyConn[proxyFd].sendSize == sizeof(m_mapProxyConn[proxyFd].sendBuf))
    {
        printf("proxy send buf full\n");
        return;
    }
    int numRecv = recv(fd, m_mapProxyConn[proxyFd].sendBuf + m_mapProxyConn[proxyFd].sendSize,
                       sizeof(m_mapProxyConn[proxyFd].sendBuf) - m_mapProxyConn[proxyFd].sendSize, MSG_DONTWAIT);
    if (numRecv == -1)
    {
        if (errno != EAGAIN && EAGAIN != EWOULDBLOCK)
        {
            printf("localReadDataProc recv err: %d\n", errno);
            m_pLogger->err("localReadDataProc recv err: %d\n", errno);
            return;
        }
    }
    else if (numRecv == 0)
    {
        deleteProxyConn(proxyFd);
        deleteLocalConn(fd);
    }
    else if (numRecv > 0)
    {
        m_mapProxyConn[proxyFd].sendSize += numRecv;
        m_reactor.registFileEvent(proxyFd, EVENT_WRITABLE,
                                  std::bind(&Client::proxyWriteDataProc,
                                            this, std::placeholders::_1, std::placeholders::_2));
        printf("localReadDataProc: recv from local: %d, proxy snedSize: %d\n", numRecv, m_mapProxyConn[proxyFd].sendSize);
    }
}

void Client::proxyWriteDataProc(int fd, int mask)
{
    int numSend = send(fd, m_mapProxyConn[fd].sendBuf, m_mapProxyConn[fd].sendSize, MSG_DONTWAIT);
    if (numSend > 0)
    {
        if (numSend == m_mapProxyConn[fd].sendSize)
        {
            m_reactor.removeFileEvent(fd, EVENT_WRITABLE);
            m_mapProxyConn[fd].sendSize = 0;
            printf("proxyWriteDataProc: send all data: %d\n", numSend);
        }
        else
        {
            size_t newSize = m_mapProxyConn[fd].sendSize - numSend;
            m_mapProxyConn[fd].sendSize = newSize;
            memmove(m_mapProxyConn[fd].sendBuf, m_mapProxyConn[fd].sendBuf + numSend, newSize);
            printf("proxyWriteDataProc: send partial data: %d, left:%lu\n", numSend, newSize);
        }
    }
    else
    {
        if (errno != EAGAIN && EAGAIN != EWOULDBLOCK)
        {
            printf("proxyWriteDataProc send err:%d\n", errno);
            m_pLogger->err("proxyWriteDataProc send err:%d\n", errno);
        }
    }
}

void Client::proxyReadDataProc(int fd, int mask)
{
    int localFd = m_mapProxyConn[fd].localFd;
    if (m_mapLocalConn[localFd].sendSize == sizeof(m_mapLocalConn[localFd].sendBuf))
    {
        printf("local send buf full\n");
        //m_pLogger->warn("local send buf full");
        return;
    }
    int numRecv = recv(fd, m_mapLocalConn[localFd].sendBuf + m_mapLocalConn[localFd].sendSize,
                       sizeof(m_mapLocalConn[localFd].sendBuf) - m_mapLocalConn[localFd].sendSize, MSG_DONTWAIT);
    if (numRecv == -1)
    {
        if (errno != EAGAIN && EAGAIN != EWOULDBLOCK)
        {
            printf("proxyReadDataProc recv err: %d\n", errno);
            m_pLogger->err("proxyReadDataProc recv err: %d", errno);
            return;
        }
    }
    else if (numRecv == 0)
    {
        deleteProxyConn(fd);
        deleteLocalConn(localFd);
    }
    else if (numRecv > 0)
    {
        m_mapLocalConn[localFd].sendSize += numRecv;
        m_reactor.registFileEvent(localFd, EVENT_WRITABLE,
                                  std::bind(&Client::localWriteDataProc,
                                            this, std::placeholders::_1, std::placeholders::_2));
        printf("proxyReadDataProc: recv from proxy: %d, local snedSize: %d\n", numRecv, m_mapLocalConn[localFd].sendSize);
    }
}

void Client::localWriteDataProc(int fd, int mask)
{
    int numSend = send(fd, m_mapLocalConn[fd].sendBuf, m_mapLocalConn[fd].sendSize, MSG_DONTWAIT);
    if (numSend > 0)
    {
        if (numSend == m_mapLocalConn[fd].sendSize)
        {
            m_reactor.removeFileEvent(fd, EVENT_WRITABLE);
            m_mapLocalConn[fd].sendSize = 0;
            printf("localWriteDataProc: send all data: %d\n", numSend);
        }
        else
        {
            size_t newSize = m_mapLocalConn[fd].sendSize - numSend;
            m_mapLocalConn[fd].sendSize = newSize;
            memmove(m_mapLocalConn[fd].sendBuf, m_mapLocalConn[fd].sendBuf + numSend, newSize);
            printf("localWriteDataProc: send partial data: %d, left:%lu\n", numSend, newSize);
            m_pLogger->warn("localWriteDataProc: send partial data: %d, left:%lu", numSend, newSize);
        }
    }
    else
    {
        if (errno != EAGAIN && EAGAIN != EWOULDBLOCK)
        {
            printf("localWriteDataProc send err:%d\n", errno);
            m_pLogger->err("localWriteDataProc send err:%d", errno);
        }
    }
}

void Client::deleteProxyConn(int fd)
{
    m_mapProxyConn.erase(fd);
    close(fd);
    m_reactor.removeFileEvent(fd, EVENT_WRITABLE | EVENT_READABLE);
    printf("deleted proxy conn: %d\n", fd);
    m_pLogger->info("deleted proxy conn: %d", fd);
}

void Client::deleteLocalConn(int fd)
{
    m_mapLocalConn.erase(fd);
    close(fd);
    m_reactor.removeFileEvent(fd, EVENT_WRITABLE | EVENT_READABLE);
    printf("deleted local conn: %d\n", fd);
    m_pLogger->info("deleted local conn: %d", fd);
}

int Client::sendProxyInfo(int porxyFd, int userId)
{
    int ret = send(porxyFd, &userId, sizeof(userId), MSG_DONTWAIT);
    if (ret != sizeof(userId))
    {
        printf("sendProxyInfo err: %d\n", errno);
        m_pLogger->err("sendProxyInfo err: %d", errno);
        return -1;
    }
}

void Client::replyNewProxy(int userId, bool isSuccess)
{
    MsgData msgData;
    ReplyNewProxyMsg replyMsg;

    replyMsg.UserId = userId;
    replyMsg.IsSuccess = isSuccess;
    msgData.type = MSGTYPE_REPLY_NEW_PROXY;
    msgData.size = sizeof(replyMsg);

    size_t bufSize = sizeof(msgData) + sizeof(replyMsg);
    char buf[bufSize];
    memcpy(buf, &msgData, sizeof(msgData));
    memcpy(buf + sizeof(msgData), &replyMsg, sizeof(replyMsg));

    int ret = send(m_clientSocketFd, buf, bufSize, MSG_DONTWAIT);
    if (ret != bufSize)
    {
        printf("replyNewProxy send err: %d\n", errno);
        m_pLogger->err("replyNewProxy send err: %d", errno);
    }
}

int Client::connectLocalApp(unsigned short remotePort)
{
    unsigned short localPort = 0;
    char localIp[INET_ADDRSTRLEN];
    for (const auto &pi : m_configProxy)
    {
        if (pi.remotePort == remotePort)
        {
            localPort = pi.localPort;
            strcpy(localIp, pi.localIp);
            break;
        }
    }
    if (localPort == 0)
    {
        printf("find local port err\n");
        m_pLogger->err("find local port err");
        return -1;
    }
    int ret = tnet::tcp_generic_connect(localIp, localPort);
    if (ret == -1)
    {
        printf("connect local app fail, addr: %s: %d\n", localIp, localPort);
        m_pLogger->err("connect local app fail, addr: %s: %d", localIp, localPort);
        return -1;
    }
    return ret;
}

int Client::connectServerProxy()
{
    int fd = tnet::tcp_socket();
    if (fd == -1)
    {
        return -1;
    }
    //tnet::non_block(fd);
    int ret = tnet::connect(fd, m_serverIp, m_serverProxyPort);
    if (ret == -1)
    {
        return -1;
    }
    return fd;
}

int Client::sendHeartbeatTimerProc(long long id)
{
    MsgData heartData;
    heartData.type = MSGTYPE_HEARTBEAT;
    heartData.size = strlen(HEARTBEAT_CLIENT_MSG);

    size_t bufSize = sizeof(heartData) + strlen(HEARTBEAT_CLIENT_MSG);
    char buf[bufSize];
    memcpy(buf, &heartData, sizeof(heartData));
    memcpy(buf + sizeof(heartData), HEARTBEAT_CLIENT_MSG, strlen(HEARTBEAT_CLIENT_MSG));

    int ret = send(m_clientSocketFd, buf, bufSize, MSG_DONTWAIT);
    if (ret == -1)
    {
        if (errno != EAGAIN && errno != EWOULDBLOCK)
        {
            printf("send heartbeat err: %d\n", errno);
            m_pLogger->err("send heartbeat err: %d", errno);
        }
    }
    else
    {
        if (ret == bufSize)
        {
            printf("send heartbeat success!\n");
        }
        else
        {
            printf("send heartbeat: send buf not good!\n");
            m_pLogger->err("send heartbeat: send buf not good!");
        }
    }
    return HEARTBEAT_INTERVAL_MS;
}

void Client::setProxyPort(unsigned short proxyPort)
{
    m_serverProxyPort = proxyPort;
}

void Client::setProxyConfig(const std::vector<ProxyInfo> &pcs)
{
    for (int i = 0; i < pcs.size(); i++)
    {
        m_configProxy.push_back(pcs[i]);
    }
}

void Client::initCryptor()
{
    m_pCryptor = new Cryptor(CRYPT_CBC, (uint8_t*)m_password);
    if(m_pCryptor == nullptr)
    {
        m_pLogger->err("new Cryptor object error");
        exit(-1);
    }
}

void Client::setPassword(const char *password)
{
    strncpy(m_password, MD5(password).toStr().c_str(), PW_MAX_LEN);

    initCryptor();
}

void Client::setLogger(Logger* logger)
{
    if(logger == nullptr)
    {
        return;
    }
    m_pLogger = logger;
}

void Client::runClient()
{
    int ret;
    ret = connectServer();
    if (ret == -1)
    {
        m_pLogger->err("connect server err!");
        return;
    }
    m_pLogger->info("connect server ok");

    ret = authServer();
    if (ret == AUTH_ERR)
    {
        m_pLogger->err("auth err");
        return;
    }
    else if(ret == AUTH_WRONG)
    {
        m_pLogger->info("auth fail, wrong password");
        return;
    }
    else if(ret == AUTH_UNKNOW)
    {
        m_pLogger->info("auth fail, know reply");
        return;
    }

    // debug
    printf("===ok===\n");
    system("pause");

    ret = sendPorts();
    if (ret == -1)
    {
        m_pLogger->err("send ports err");
        return;
    }
    m_pLogger->info("send ports ok");
    long now_sec, mow_ms;
    getTime(&now_sec, &mow_ms);
    m_lastServerHeartbeatMs = now_sec * 1000 + mow_ms;

    tnet::non_block(m_clientSocketFd);
    m_reactor.registTimeEvent(0,
                              std::bind(&Client::sendHeartbeatTimerProc, this, std::placeholders::_1));
    m_reactor.registTimeEvent(HEARTBEAT_INTERVAL_MS,
                              std::bind(&Client::checkHeartbeatTimerProc, this, std::placeholders::_1));
    m_reactor.registFileEvent(m_clientSocketFd, EVENT_READABLE,
                              std::bind(&Client::clientReadProc,
                                        this, std::placeholders::_1, std::placeholders::_2));
    m_pLogger->info("client running...");
    m_reactor.eventLoop(EVENT_LOOP_ALL_EVENT);
}