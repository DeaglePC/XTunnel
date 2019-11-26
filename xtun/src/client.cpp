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

    size_t dataSize = sizeof(ports);
    uint8_t buf[MsgUtil::ensureCryptedDataSize(dataSize)];
    uint32_t cryptedDataLen = MsgUtil::packCryptedData(m_pCryptor, buf, (uint8_t*)ports, dataSize);

    int ret = send(m_clientSocketFd, buf, cryptedDataLen, 0); // block
    if (ret == -1)
    {
        printf("sendPorts err: %d\n", errno);
        m_pLogger->err("sendPorts err: %d\n", errno);
        return -1;
    }
    else if (ret == cryptedDataLen)
    {
        printf("sendPorts num: %ld\n", portNum);
        m_pLogger->info("sendPorts num: %ld", portNum);
        return portNum;
    }
    else
    {
        // should be never happen
        printf("sendPorts unknown error: %d\n", errno);
        m_pLogger->err("sendPorts unknown error: %d\n", errno);
        return -1;
    }
    
}

// send data to server
void Client::serverSafeRecv(int sfd, std::function<void(size_t dataSize)> callback)
{
    int ret;
    size_t targetSize = m_clientData.header.ensureTargetDataSize();

    ret = recv(sfd, m_clientData.recvBuf + m_clientData.recvNum,
                targetSize - m_clientData.recvNum, MSG_DONTWAIT);
    
    if (ret == -1)
    {
        if (errno != EAGAIN && EAGAIN != EWOULDBLOCK)
        {
            printf("serverSafeRecv err: %d\n", errno);
            m_pLogger->err("serverSafeRecv err: %d", errno);
            return;
        }
    }
    else if (ret == 0)
    {
        printf("clientReadProc server offline\n");
        m_pLogger->info("clientReadProc server offline");
        stopClient();
        // exit(-1);
    }
    else if (ret > 0)
    {
        m_clientData.recvNum += ret;

        if (m_clientData.recvNum == targetSize)
        {
            m_clientData.recvNum = 0;
            
            if (targetSize == sizeof(DataHeader))
            {
                memcpy(&m_clientData.header, m_clientData.recvBuf, targetSize);
            }
            else
            {
                uint32_t realDataSize = m_pCryptor->decrypt(
                    m_clientData.header.iv, 
                    (uint8_t*)m_clientData.recvBuf, 
                    targetSize
                );

                // if recv all done, we callback
                callback(realDataSize);

                // remember init datalen for next recv
                m_clientData.header.dataLen = 0;
            }
        }
    }
}

void Client::serverSafeSend(int fd, std::function<void(int fd)> callback)
{
    int ret = send(fd, &m_clientData.sendBuf, m_clientData.sendSize, MSG_DONTWAIT);

    if (ret == -1)
    {
        if (errno != EAGAIN && EAGAIN != EWOULDBLOCK)
        {
            printf("serverSafeSend err: %d\n", errno);
            m_pLogger->err("serverSafeSend err: %d\n", errno);
            // TODO do something, may reconnect server...
        }
    }
    else if (ret > 0)
    {
        m_clientData.sendSize -= ret;

        if (m_clientData.sendSize == 0)
        {
            callback(fd);
        }
        else
        {
            memmove(
                m_clientData.sendBuf, 
                m_clientData.sendBuf + ret, 
                m_clientData.sendSize
            );
        }
    }
}

void Client::clientReadProc(int fd, int mask)
{
    if (!(mask & EVENT_READABLE))
    {
        return;
    }

    serverSafeRecv(
        fd,
        std::bind(
            &Client::onClientReadDone,
            this,
            std::placeholders::_1
        )
    );
}

void Client::onClientReadDone(size_t dataSize)
{
    MsgData msgData;

    memcpy(&msgData, m_clientData.recvBuf, sizeof(MsgData));

    if (msgData.type == MSGTYPE_HEARTBEAT)
    {
        if (memcmp(m_clientData.recvBuf + sizeof(MsgData), 
                    HEARTBEAT_SERVER_MSG, msgData.size) == 0)
        {
            processHeartbeat();
        }
    }
    else if (msgData.type == MSGTYPE_NEW_PROXY)
    {
        NewProxyMsg newProxy;
        memcpy(&newProxy, m_clientData.recvBuf + sizeof(MsgData), msgData.size);

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
        // exit(-1);
        stopClient();
    }
    // printf("check heartbeat ok!%ld\n", subTimeStamp);
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
        m_pLogger->warn("proxy send buf full");
        return;
    }

    int numRecv = recv(fd, m_mapProxyConn[proxyFd].sendBuf + m_mapProxyConn[proxyFd].sendSize,
                       MAX_BUF_SIZE - m_mapProxyConn[proxyFd].sendSize, MSG_DONTWAIT);
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
        m_mapProxyConn[proxyFd].sendSize += MsgUtil::packCryptedData(
            m_pCryptor,
            (uint8_t*)m_mapProxyConn[proxyFd].sendBuf + m_mapProxyConn[proxyFd].sendSize,
            (uint8_t*)m_mapProxyConn[proxyFd].sendBuf + m_mapProxyConn[proxyFd].sendSize,
            numRecv
        );

        m_reactor.registFileEvent(
            proxyFd, 
            EVENT_WRITABLE,
            std::bind(
                &Client::proxyWriteDataProc,
                this, 
                std::placeholders::_1, 
                std::placeholders::_2
            )
        );
        
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

void Client::proxySafeRecv(
    int fd, 
    std::function<void(int fd, size_t dataSize)> callback)
{
    int ret;
    // there is not header init if data len is 0
    size_t targetSize = m_mapProxyConn[fd].header.ensureTargetDataSize();

    ret = recv(fd, m_mapProxyConn[fd].recvBuf + m_mapProxyConn[fd].recvNum,
                targetSize - m_mapProxyConn[fd].recvNum, MSG_DONTWAIT);
    if (ret == -1)
    {
        if (errno != EAGAIN && EAGAIN != EWOULDBLOCK)
        {
            printf("proxySafeRecv recv err: %d\n", errno);
            m_pLogger->err("proxySafeRecv recv err: %d", errno);
            return;
        }
    }
    else if (ret == 0)
    {
        deleteProxyConn(fd);
        deleteLocalConn(m_mapProxyConn[fd].localFd);
    }
    else if (ret > 0)
    {
        m_mapProxyConn[fd].recvNum += ret;

        if (m_mapProxyConn[fd].recvNum == targetSize)
        {
            m_mapProxyConn[fd].recvNum = 0;

            // targetSize = header size or data size
            if (targetSize == sizeof(DataHeader))
            {
                memcpy(&m_mapProxyConn[fd].header, m_mapProxyConn[fd].recvBuf, targetSize);
            }
            else
            {
                uint32_t realDataSize = m_pCryptor->decrypt(
                    m_mapProxyConn[fd].header.iv, 
                    (uint8_t*)m_mapProxyConn[fd].recvBuf, 
                    targetSize
                );

                // if recv all done, we callback
                callback(fd, realDataSize);

                // remember init datalen for next recv
                m_mapProxyConn[fd].header.dataLen = 0;
            }
        }
    }
}

void Client::proxyReadDataProc(int fd, int mask)
{
    if (!(mask & EVENT_READABLE))
    {
        return;
    }

    proxySafeRecv(
        fd,
        std::bind(
            &Client::onProxyReadDataDone,
            this,
            std::placeholders::_1, 
            std::placeholders::_2
        )
    );
}

// send to local
void Client::onProxyReadDataDone(int fd, size_t dataSize)
{
    int localFd = m_mapProxyConn[fd].localFd;

    if (m_mapLocalConn[localFd].sendSize + dataSize >= sizeof(m_mapLocalConn[localFd].sendBuf))
    {
        printf("local send buf full\n");
        m_pLogger->warn("local send buf full");
        return;
    }

    memcpy(
        m_mapLocalConn[localFd].sendBuf + m_mapLocalConn[localFd].sendSize, 
        m_mapProxyConn[fd].recvBuf, 
        dataSize
    );
    m_mapLocalConn[localFd].sendSize += dataSize;

    // duplicated regist is fine
    m_reactor.registFileEvent(
        localFd,
        EVENT_WRITABLE,
        std::bind(
            &Client::localWriteDataProc,
            this, 
            std::placeholders::_1, 
            std::placeholders::_2
        )
    );
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
    char buf[MsgUtil::ensureCryptedDataSize(sizeof(userId))];
    size_t dataSize = MsgUtil::packCryptedData(m_pCryptor, (uint8_t*)buf, (uint8_t*)&userId, sizeof(userId));

    int ret = send(porxyFd, buf, dataSize, MSG_DONTWAIT);
    if (ret != dataSize)
    {
        printf("sendProxyInfo err: %d\n", errno);
        m_pLogger->err("sendProxyInfo err: %d", errno);
        return -1;
    }

    return 0;
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

    m_clientData.sendSize = MsgUtil::packCryptedData(
        m_pCryptor, 
        (uint8_t*)m_clientData.sendBuf, 
        (uint8_t*)buf,
        bufSize
    );

    m_reactor.registFileEvent(
        m_clientSocketFd,
        EVENT_WRITABLE,
        std::bind(
            &Client::replyNewProxyProc,
            this,
            std::placeholders::_1,
            std::placeholders::_2
        )
    );
}

void Client::replyNewProxyProc(int fd, int mask)
{
    if (!(mask & EVENT_WRITABLE))
    {
        return;
    }

    serverSafeSend(
        m_clientSocketFd, 
        std::bind(
            &Client::onReplyNewProxyDone,
            this,
            std::placeholders::_1
        )
    );
}

void Client::onReplyNewProxyDone(int fd)
{
    m_reactor.removeFileEvent(fd, EVENT_WRITABLE);
    printf("onReplyNewProxyDone\n");
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

    size_t dataSize = sizeof(heartData) + strlen(HEARTBEAT_CLIENT_MSG);
    char bufData[dataSize];

    memcpy(bufData, &heartData, sizeof(heartData));
    memcpy(bufData + sizeof(heartData), HEARTBEAT_CLIENT_MSG, strlen(HEARTBEAT_CLIENT_MSG));

    uint8_t buf[MsgUtil::ensureCryptedDataSize(dataSize)];
    uint32_t cryptedDataLen = MsgUtil::packCryptedData(m_pCryptor, buf, (uint8_t*)bufData, dataSize);

    int ret = send(m_clientSocketFd, buf, cryptedDataLen, MSG_DONTWAIT);
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
        if (ret == cryptedDataLen)
        {
            // printf("send heartbeat success!\n");
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
    m_reactor.setStart();
    m_reactor.eventLoop(EVENT_LOOP_ALL_EVENT);
}

void Client::stopClient()
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
}
