#include "client.h"
#include <cstring>
#include "tnet.h"

Client::Client(const char *sip, unsigned short sport) : m_clientSocketFd(-1)
{
    if (sip == NULL)
    {
        return;
    }
    strcpy(m_serverIp, sip);
    m_serverPort = sport;
}

Client::~Client()
{
}

void Client::setProxyConfig(const std::vector<ProxyInfo> &pcs)
{
    for (int i = 0; i < pcs.size(); i++)
    {
        m_configProxy.push_back(pcs[i]);
    }
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

/*
 * 认证过程：
 * client->server: md5(password), len=32bytes
 * server->client: Y/N, len=1byte
 * return: -1: err, 0: ok, 1: wrong password
 */
int Client::authServer(const char *password)
{
    char pw[PW_MAX_LEN];
    strncpy(pw, "FAE0B27C451C728867A567E8C1BB4E53", PW_MAX_LEN); // 加密成md5
    int ret, sendCnt = 0;
    while (1)
    {
        ret = send(m_clientSocketFd, pw + sendCnt, PW_MAX_LEN - sendCnt, 0);
        if (ret > 0)
        {
            sendCnt += ret;
            if (sendCnt == PW_MAX_LEN)
            {
                break;
            }
        }
        else if (ret == -1)
        {
            printf("authServer send err: %d\n", errno);
            return AUTH_ERR;
        }
        else if (ret == 0)
        {
            return AUTH_ERR;
        }
    }
    printf("send password ok\n");
    char recvBuf;
    while (1)
    {
        ret = recv(m_clientSocketFd, &recvBuf, sizeof(recvBuf), 0);
        if (ret > 0)
        {
            if (recvBuf == 'Y')
            {
                return AUTH_OK;
            }
            else if (recvBuf == 'N')
            {
                return AUTH_WRONG;
            }
            else
            {
                return AUTH_UNKNOW;
            }
        }
        else if (ret == -1)
        {
            printf("authServer recv err: %d\n", errno);
            return AUTH_ERR;
        }
    }
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
        return -1;
    }
    else if (ret > 0)
    {
        printf("sendPorts num: %ld\n", portNum);
        return portNum;
    }
}

void Client::runClient()
{
    int ret;
    ret = sendPorts();
    if (ret == -1)
    {
        return;
    }
    tnet::non_block(m_clientSocketFd);
    m_reactor.registFileEvent(m_clientSocketFd, EVENT_READABLE,
                              std::bind(&Client::clientReadProc,
                                        this, std::placeholders::_1, std::placeholders::_2));
    m_reactor.eventLoop(EVENT_LOOP_ALL_EVENT);
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
            return;
        }
    }
    else if (ret == 0)
    {
        printf("clientReadProc server offline\n");
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
    }
    else if (m_clientData.msgData.type == MSGTYPE_NEW_PROXY)
    {
        NewProxyMsg newProxy;
        memcpy(&newProxy, m_clientData.buf, m_clientData.recvSize);
        m_clientData.recvSize = sizeof(MsgData);
        m_clientData.recvNum = 0;
        m_clientData.msgData.type = -1;
        printf("new proxy %d %d\n", newProxy.UserId, newProxy.rmeotePort);
        makeNewProxy(newProxy);
    }
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
    if(m_mapProxyConn[proxyFd].sendSize == sizeof(m_mapProxyConn[proxyFd].sendBuf))
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
        }
    }
}

void Client::proxyReadDataProc(int fd, int mask)
{
    int localFd = m_mapProxyConn[fd].localFd;
    if(m_mapLocalConn[localFd].sendSize == sizeof(m_mapLocalConn[localFd].sendBuf))
    {
        printf("local send buf full\n");
        return;
    }
    int numRecv = recv(fd, m_mapLocalConn[localFd].sendBuf + m_mapLocalConn[localFd].sendSize,
                       sizeof(m_mapLocalConn[localFd].sendBuf) - m_mapLocalConn[localFd].sendSize, MSG_DONTWAIT);
    if (numRecv == -1)
    {
        if (errno != EAGAIN && EAGAIN != EWOULDBLOCK)
        {
            printf("proxyReadDataProc recv err: %d\n", errno);
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
        }
    }
    else
    {
        if (errno != EAGAIN && EAGAIN != EWOULDBLOCK)
        {
            printf("localWriteDataProc send err:%d\n", errno);
        }
    }
}

void Client::deleteProxyConn(int fd)
{
    m_mapProxyConn.erase(fd);
    close(fd);
    m_reactor.removeFileEvent(fd, EVENT_WRITABLE | EVENT_READABLE);
    printf("deleted proxy conn: %d\n", fd);
}

void Client::deleteLocalConn(int fd)
{
    m_mapLocalConn.erase(fd);
    close(fd);
    m_reactor.removeFileEvent(fd, EVENT_WRITABLE | EVENT_READABLE);
    printf("deleted local conn: %d\n", fd);
}

int Client::sendProxyInfo(int porxyFd, int userId)
{
    int ret = send(porxyFd, &userId, sizeof(userId), MSG_DONTWAIT);
    if (ret != sizeof(userId))
    {
        printf("sendProxyInfo err: %d\n", errno);
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
        return -1;
    }
    int ret = tnet::tcp_generic_connect(localIp, localPort);
    if (ret == -1)
    {
        printf("connect local app fail, addr: %s: %d\n", localIp, localPort);
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

void Client::setProxyPort(unsigned short proxyPort)
{
    m_serverProxyPort = proxyPort;
}