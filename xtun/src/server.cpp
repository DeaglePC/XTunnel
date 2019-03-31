#include "server.h"
#include <netinet/in.h>
#include <cstring>
#include "md5.h"

Server::Server(unsigned short port, unsigned short proxyPort)
    : m_serverSocketFd(-1), m_serverPort(port), m_proxyPort(proxyPort), m_pLogger(nullptr)
{
    initServer();
}

Server::~Server()
{
    printf("~~~~~~~gg~~~~~~~~\n");
    if (m_serverSocketFd != -1)
    {
        close(m_serverSocketFd);
    }
    if (m_proxySocketFd != -1)
    {
        close(m_proxySocketFd);
    }
    std::vector<int> clients;
    for (const auto &it : m_mapClients)
    {
        clients.push_back(it.first);
    }
    for (const auto &c : clients)
    {
        deleteClient(c);
    }
}

int Server::listenControl()
{
    m_serverSocketFd = tnet::tcp_socket();
    if (m_serverSocketFd == NET_ERR)
    {
        printf("make server socker err!\n");
        return -1;
    }
    int ret = tnet::tcp_listen(m_serverSocketFd, m_serverPort);
    if (ret == NET_ERR)
    {
        printf("server listen err!\n");
        return -1;
    }
    tnet::non_block(m_serverSocketFd);
    m_reactor.registFileEvent(m_serverSocketFd, EVENT_READABLE,
                              std::bind(&Server::serverAcceptProc,
                                        this, std::placeholders::_1, std::placeholders::_2));
}

int Server::listenProxy()
{
    m_proxySocketFd = tnet::tcp_socket();
    if (m_proxySocketFd == NET_ERR)
    {
        printf("make proxy socker err!\n");
        return -1;
    }
    int ret = tnet::tcp_listen(m_proxySocketFd, m_proxyPort);
    if (ret == NET_ERR)
    {
        printf("server listen err!\n");
        return -1;
    }
    m_reactor.registFileEvent(m_proxySocketFd, EVENT_READABLE,
                              std::bind(&Server::proxyAcceptProc,
                                        this, std::placeholders::_1, std::placeholders::_2));
}

void Server::initServer()
{
    int ret = listenControl();
    if (ret == -1)
    {
        exit(-1);
    }
    ret = listenProxy();
    if (ret == -1)
    {
        exit(-1);
    }
    m_heartbeatTimerId = m_reactor.registTimeEvent(HEARTBEAT_INTERVAL_MS,
                                                   std::bind(&Server::checkHeartbeatTimerProc, this, std::placeholders::_1));
}

void Server::proxyAcceptProc(int fd, int mask)
{
    if (mask & EVENT_READABLE)
    {
        char ip[INET_ADDRSTRLEN];
        int port;
        int connfd = tnet::tcp_accept(fd, ip, INET_ADDRSTRLEN, &port);
        if (connfd == -1)
        {
            if (errno != EAGAIN && EAGAIN != EWOULDBLOCK)
            {
                printf("proxyAcceptProc accept err: %d\n", errno);
            }
            return;
        }
        printf("proxyAcceptProc new conn from %s:%d\n", ip, port);
        ProxyConnInfo pci;
        pci.recvNum = 0;
        pci.recvSize = sizeof(int);
        m_mapProxy[connfd] = pci;
        tnet::non_block(connfd);
        m_reactor.registFileEvent(connfd, EVENT_READABLE,
                                  std::bind(&Server::proxyReadUserInfoProc,
                                            this, std::placeholders::_1, std::placeholders::_2));
    }
}

void Server::proxyReadUserInfoProc(int fd, int mask)
{
    int ret = recv(fd, m_mapProxy[fd].recvBuf + m_mapProxy[fd].recvNum,
                   m_mapProxy[fd].recvSize - m_mapProxy[fd].recvNum, MSG_DONTWAIT);
    if (ret == -1)
    {
        if (errno != EAGAIN && EAGAIN != EWOULDBLOCK)
        {
            printf("proxyReadUserInfoProc err: %d\n", errno);
            return;
        }
    }
    else if (ret == 0)
    {
        deleteUser(m_mapProxy[fd].userFd);
        deleteProxyConn(fd);
    }
    else if (ret > 0)
    {
        m_mapProxy[fd].recvNum += ret;
        if (m_mapProxy[fd].recvNum == m_mapProxy[fd].recvSize)
        {
            int userFd;
            memcpy(&userFd, m_mapProxy[fd].recvBuf, m_mapProxy[fd].recvSize);
            if (m_mapUsers.find(userFd) != m_mapUsers.end())
            {
                m_mapProxy[fd].userFd = userFd;
                m_mapUsers[userFd].proxyFd = fd;
                m_reactor.registFileEvent(fd, EVENT_READABLE,
                                          std::bind(&Server::proxyReadDataProc,
                                                    this, std::placeholders::_1, std::placeholders::_2));
                m_reactor.registFileEvent(userFd, EVENT_READABLE,
                                          std::bind(&Server::userReadDataProc,
                                                    this, std::placeholders::_1, std::placeholders::_2));
                printf("start new proxy..., %d<--->%d\n", userFd, fd);
            }
            else
            {
                // delete proxy
                deleteProxyConn(fd);
            }
        }
    }
}

void Server::deleteProxyConn(int fd)
{
    m_mapProxy.erase(fd);
    close(fd);
    m_reactor.removeFileEvent(fd, EVENT_READABLE | EVENT_WRITABLE);
    printf("deleted proxy conn: %d\n", fd);
}

/*
 * 读取客户端发来的代理通道的数据,转发给user
*/
void Server::proxyReadDataProc(int fd, int mask)
{
    printf("on proxyReadDataProc\n");
    int userFd = m_mapProxy[fd].userFd;
    // 把数据放到user的发送缓冲区
    if (m_mapUsers[userFd].sendSize == sizeof(m_mapUsers[userFd].sendBuf))
    {
        printf("user send buf full\n");
        return;
    }
    int numRecv = recv(fd, m_mapUsers[userFd].sendBuf + m_mapUsers[userFd].sendSize,
                       sizeof(m_mapUsers[userFd].sendBuf) - m_mapUsers[userFd].sendSize, MSG_DONTWAIT);
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
        deleteUser(userFd);
    }
    else if (numRecv > 0)
    {
        m_mapUsers[userFd].sendSize += numRecv;
        m_reactor.registFileEvent(userFd, EVENT_WRITABLE,
                                  std::bind(&Server::userWriteDataProc,
                                            this, std::placeholders::_1, std::placeholders::_2));
        printf("proxyReadDataProc: recv from proxy: %d, user snedSize: %d\n", numRecv, m_mapUsers[userFd].sendSize);
    }
}

/*
 * 发送缓冲区的数据给user
 */
void Server::userWriteDataProc(int fd, int mask)
{
    printf("on userWriteDataProc\n");
    int numSend = send(fd, m_mapUsers[fd].sendBuf, m_mapUsers[fd].sendSize, MSG_DONTWAIT);
    if (numSend > 0)
    {
        if (numSend == m_mapUsers[fd].sendSize)
        {
            m_reactor.removeFileEvent(fd, EVENT_WRITABLE);
            // 缓冲区已经全部发送了，从开始放数据
            m_mapUsers[fd].sendSize = 0;
            printf("userWriteDataProc: send all data: %d\n", numSend);
        }
        else
        {
            // 没有全部发送完，把没发送的数据移动到前面
            size_t newSize = m_mapUsers[fd].sendSize - numSend; // 还剩多少没发送完
            m_mapUsers[fd].sendSize = newSize;
            memmove(m_mapUsers[fd].sendBuf, m_mapUsers[fd].sendBuf + numSend, newSize);
            printf("userWriteDataProc: send partial data: %d, left:%lu\n", numSend, newSize);
        }
    }
    else
    {
        if (errno != EAGAIN && EAGAIN != EWOULDBLOCK)
        {
            printf("userWriteDataProc send err:%d\n", errno);
        }
    }
}

/*
 * 读user的数据，转发给proxy通道
*/
void Server::userReadDataProc(int fd, int mask)
{
    printf("on userReadDataProc\n");
    int proxyFd = m_mapUsers[fd].proxyFd;
    if (m_mapProxy[proxyFd].sendSize == sizeof(m_mapProxy[proxyFd].sendBuf))
    {
        printf("proxy send buf full\n");
        return;
    }
    int numRecv = recv(fd, m_mapProxy[proxyFd].sendBuf + m_mapProxy[proxyFd].sendSize,
                       sizeof(m_mapProxy[proxyFd].sendBuf) - m_mapProxy[proxyFd].sendSize, MSG_DONTWAIT);
    if (numRecv == -1)
    {
        if (errno != EAGAIN && EAGAIN != EWOULDBLOCK)
        {
            printf("userReadDataProc recv err: %d\n", errno);
            return;
        }
    }
    else if (numRecv == 0)
    {
        deleteUser(fd);
        deleteProxyConn(proxyFd);
    }
    else if (numRecv > 0)
    {
        m_mapProxy[proxyFd].sendSize += numRecv;
        m_reactor.registFileEvent(proxyFd, EVENT_WRITABLE,
                                  std::bind(&Server::proxyWriteDataProc,
                                            this, std::placeholders::_1, std::placeholders::_2));
        printf("userReadDataProc: recv from user: %d, proxy snedSize: %d\n", numRecv, m_mapProxy[proxyFd].sendSize);
    }
}

/*
 * 发送缓冲区的数据给代理通道
*/
void Server::proxyWriteDataProc(int fd, int mask)
{
    printf("on proxyWriteDataProc\n");
    int numSend = send(fd, m_mapProxy[fd].sendBuf, m_mapProxy[fd].sendSize, MSG_DONTWAIT);
    if (numSend > 0)
    {
        if (numSend == m_mapProxy[fd].sendSize)
        {
            m_reactor.removeFileEvent(fd, EVENT_WRITABLE);
            m_mapProxy[fd].sendSize = 0;
            printf("proxyWriteDataProc: send all data: %d\n", numSend);
        }
        else
        {
            size_t newSize = m_mapProxy[fd].sendSize - numSend;
            m_mapProxy[fd].sendSize = newSize;
            memmove(m_mapProxy[fd].sendBuf, m_mapProxy[fd].sendBuf + numSend, newSize);
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

void Server::serverAcceptProc(int fd, int mask)
{
    if (mask & EVENT_READABLE)
    {
        char ip[INET_ADDRSTRLEN];
        int port;
        int connfd = tnet::tcp_accept(fd, ip, INET_ADDRSTRLEN, &port);
        if (connfd == -1)
        {
            if (errno != EAGAIN && EAGAIN != EWOULDBLOCK)
            {
                printf("serverAcceptProc accept err: %d\n", errno);
            }
            return;
        }
        printf("serverAcceptProc new conn from %s:%d\n", ip, port);
        m_mapClients[connfd] = ClientInfo();
        tnet::non_block(connfd);
        m_reactor.registFileEvent(connfd, EVENT_READABLE,
                                  std::bind(&Server::clientAuthProc,
                                            this, std::placeholders::_1, std::placeholders::_2));
    }
}

void Server::clientAuthProc(int fd, int mask)
{
    if (mask & EVENT_READABLE)
    {
        int ret;
        ret = recv(fd, m_mapClients[fd].authBuf + m_mapClients[fd].authRecvNum,
                   AUTH_BUF_SIZE - m_mapClients[fd].authRecvNum, MSG_DONTWAIT);
        if (ret == -1)
        {
            if (errno != EAGAIN && EAGAIN != EWOULDBLOCK)
            {
                printf("recv client auth msg err: %d\n", errno);
            }
            return;
        }
        else if (ret == 0)
        {
            deleteClient(fd);
        }
        else if (ret > 0)
        {
            m_mapClients[fd].authRecvNum += ret;
            if (m_mapClients[fd].authRecvNum == AUTH_BUF_SIZE)
            {
                if (strncmp(m_serverPassword, m_mapClients[fd].authBuf, sizeof(m_serverPassword)) == 0)
                {
                    m_reactor.registFileEvent(fd, EVENT_WRITABLE,
                                              std::bind(&Server::replyClientAuthProcY,
                                                        this, std::placeholders::_1, std::placeholders::_2));
                }
                else
                {
                    m_reactor.registFileEvent(fd, EVENT_WRITABLE,
                                              std::bind(&Server::replyClientAuthProcN,
                                                        this, std::placeholders::_1, std::placeholders::_2));
                }
            }
        }
    }
}

void Server::replyClientAuthProcY(int fd, int mask)
{
    if (mask & EVENT_WRITABLE)
    {
        replyClientAuth(fd, true);
    }
}

void Server::replyClientAuthProcN(int fd, int mask)
{
    if (mask & EVENT_WRITABLE)
    {
        replyClientAuth(fd, false);
    }
}

void Server::replyClientAuth(int fd, bool isGood)
{
    char buf;
    if (isGood)
    {
        buf = 'Y';
    }
    else
    {
        buf = 'N';
    }
    int len = sizeof(buf);
    int ret = send(fd, &buf, len, MSG_DONTWAIT);
    if (ret == -1)
    {
        if (errno != EAGAIN && EAGAIN != EWOULDBLOCK)
        {
            printf("replyClientAuthProcY err: %d\n", errno);
            deleteClient(fd);
        }
    }
    else if (ret > 0)
    {
        m_reactor.removeFileEvent(fd, EVENT_WRITABLE);
        if (!isGood)
        {
            printf("pw not good, delete client...\n");
            deleteClient(fd);
        }
        else
        {
            m_reactor.registFileEvent(fd, EVENT_READABLE,
                                      std::bind(&Server::recvClientProxyPorts,
                                                this, std::placeholders::_1, std::placeholders::_2));
        }
    }
}

void Server::recvClientProxyPorts(int fd, int mask)
{
    // 还没有开始保存端口数据
    if (m_mapClients[fd].remotePorts.size() == 0)
    {
        size_t targetNum = sizeof(unsigned short); // 端口第一个元素存着端口的数量
        int ret = recv(fd, m_mapClients[fd].recvBuf + m_mapClients[fd].recvNum,
                       targetNum - m_mapClients[fd].recvNum, MSG_DONTWAIT);
        if (ret > 0)
        {
            m_mapClients[fd].recvNum += ret;
            if (m_mapClients[fd].recvNum == ret)
            {
                unsigned short portNum = 0;
                memcpy(&portNum, m_mapClients[fd].recvBuf, targetNum);
                if (portNum > 0)
                {
                    // 给存放端口的vector分配内存
                    m_mapClients[fd].remotePorts.resize(portNum);
                }
                m_mapClients[fd].recvNum = 0;
            }
        }
        else if (ret == 0)
        {
            deleteClient(fd);
        }
        else if (ret == -1)
        {
            if (errno != EAGAIN && EAGAIN != EWOULDBLOCK)
            {
                printf("recvClientProxyPorts err: %d\n", errno);
                deleteClient(fd);
            }
        }
    }
    else
    {
        size_t targetNum = m_mapClients[fd].remotePorts.size() * sizeof(unsigned short);
        int ret = recv(fd, m_mapClients[fd].recvBuf,
                       sizeof(m_mapClients[fd].recvBuf), MSG_DONTWAIT);
        if (ret > 0)
        {
            memcpy(&m_mapClients[fd].remotePorts[0] + m_mapClients[fd].recvNum,
                   m_mapClients[fd].recvBuf, ret);
            m_mapClients[fd].recvNum += ret;
            if (m_mapClients[fd].recvNum == targetNum)
            {
                // init client
                initClient(fd);
            }
        }
        else if (ret == 0)
        {
            deleteClient(fd);
        }
        else if (ret == -1)
        {
            if (errno != EAGAIN && EAGAIN != EWOULDBLOCK)
            {
                printf("recvClientProxyPorts err: %d\n", errno);
                deleteClient(fd);
            }
        }
    }
}

void Server::initClient(int fd)
{
    listenRemotePort(fd);
    m_mapClients[fd].recvSize = sizeof(MsgData);
    m_mapClients[fd].recvNum = 0;
    updateClientHeartbeat(fd);
    m_reactor.registFileEvent(fd, EVENT_READABLE,
                              std::bind(&Server::recvClientDataProc,
                                        this, std::placeholders::_1, std::placeholders::_2));
}

int Server::listenRemotePort(int cfd)
{
    size_t len = m_mapClients[cfd].remotePorts.size();
    for (int i = 0; i < len; i++)
    {
        int fd = tnet::tcp_socket();
        if (fd == -1)
        {
            printf("listenRemotePort make socket err: %d\n", errno);
            continue;
        }
        unsigned short port = m_mapClients[cfd].remotePorts[i];
        int ret = tnet::tcp_listen(fd, port);
        if (ret == -1)
        {
            printf("listenRemotePort listen port:%d err: %d\n", port, errno);
            continue;
        }
        ListenInfo linfo;
        linfo.port = port;
        linfo.clientFd = cfd;
        m_mapListen[fd] = linfo;
        tnet::non_block(fd);
        m_reactor.registFileEvent(fd, EVENT_READABLE,
                                  std::bind(&Server::userAcceptProc,
                                            this, std::placeholders::_1, std::placeholders::_2));
        printf("listenRemotePort listening port: %d\n", port);
    }
}

void Server::userAcceptProc(int fd, int mask)
{
    if (mask & EVENT_READABLE)
    {
        char ip[INET_ADDRSTRLEN];
        int port;
        int connfd = tnet::tcp_accept(fd, ip, INET_ADDRSTRLEN, &port);
        if (connfd == -1)
        {
            if (errno != EAGAIN && EAGAIN != EWOULDBLOCK)
            {
                printf("userAcceptProc accept err: %d\n", errno);
            }
            return;
        }
        printf("userAcceptProc new conn from %s:%d\n", ip, port);
        UserInfo info;
        info.port = m_mapListen[fd].port;
        m_mapUsers[connfd] = info;
        tnet::non_block(connfd);
        sendClientNewProxy(m_mapListen[fd].clientFd, connfd, m_mapListen[fd].port);
    }
}

void Server::sendClientNewProxy(int cfd, int ufd, unsigned short remotePort)
{
    MsgData msgData;
    NewProxyMsg newProxyMsg;

    newProxyMsg.UserId = ufd;
    newProxyMsg.rmeotePort = remotePort;

    msgData.type = MSGTYPE_NEW_PROXY;
    msgData.size = sizeof(newProxyMsg);
    size_t bufSize = sizeof(msgData) + sizeof(newProxyMsg);
    char buf[bufSize];

    memcpy(buf, &msgData, sizeof(msgData));
    memcpy(buf + sizeof(msgData), &newProxyMsg, sizeof(newProxyMsg));
    int ret = send(cfd, buf, bufSize, MSG_DONTWAIT);
    if (ret != bufSize)
    {
        printf("sendClientNewProxy err: %d\n", errno);
    }
}

void Server::recvClientDataProc(int fd, int mask)
{
    int ret = recv(fd, m_mapClients[fd].recvBuf + m_mapClients[fd].recvNum,
                   m_mapClients[fd].recvSize - m_mapClients[fd].recvNum, MSG_DONTWAIT);
    printf("recvClientDataProc recv:%d\n", ret);
    if (ret == -1)
    {
        if (errno != EAGAIN && EAGAIN != EWOULDBLOCK)
        {
            printf("recvClientDataProc err: %d\n", errno);
            return;
        }
    }
    else if (ret == 0)
    {
        deleteClient(fd);
    }
    else if (ret > 0)
    {
        m_mapClients[fd].recvNum += ret;
        if (m_mapClients[fd].recvNum == m_mapClients[fd].recvSize)
        {
            processClientBuf(fd);
        }
    }
}

void Server::processClientBuf(int cfd)
{
    if (m_mapClients[cfd].msgData.type < 0)
    {
        memcpy(&m_mapClients[cfd].msgData,
               m_mapClients[cfd].recvBuf, m_mapClients[cfd].recvSize);
        m_mapClients[cfd].recvSize = m_mapClients[cfd].msgData.size;
        m_mapClients[cfd].recvNum = 0;
    }
    else if (m_mapClients[cfd].msgData.type == MSGTYPE_HEARTBEAT)
    {
        m_mapClients[cfd].recvSize = sizeof(MsgData);
        m_mapClients[cfd].recvNum = 0;
        m_mapClients[cfd].msgData.type = -1;

        if (strncmp(m_mapClients[cfd].recvBuf, HEARTBEAT_CLIENT_MSG,
                    strlen(HEARTBEAT_CLIENT_MSG)) == 0)
        {
            updateClientHeartbeat(cfd);
            sendHeartbeat(cfd);
        }
    }
    else if (m_mapClients[cfd].msgData.type == MSGTYPE_REPLY_NEW_PROXY)
    {
        ReplyNewProxyMsg rnpm;
        memcpy(&rnpm, m_mapClients[cfd].recvBuf, m_mapClients[cfd].recvSize);
        m_mapClients[cfd].recvSize = sizeof(MsgData);
        m_mapClients[cfd].recvNum = 0;
        m_mapClients[cfd].msgData.type = -1;
        processNewProxy(rnpm);
    }
}

void Server::sendHeartbeat(int cfd)
{
    MsgData heartData;
    heartData.type = MSGTYPE_HEARTBEAT;
    heartData.size = strlen(HEARTBEAT_SERVER_MSG);

    size_t bufSize = sizeof(heartData) + strlen(HEARTBEAT_SERVER_MSG);
    char buf[bufSize];
    memcpy(buf, &heartData, sizeof(heartData));
    memcpy(buf + sizeof(heartData), HEARTBEAT_SERVER_MSG, strlen(HEARTBEAT_SERVER_MSG));

    int ret = send(cfd, buf, bufSize, MSG_DONTWAIT);
    if (ret == -1)
    {
        if (errno != EAGAIN && errno != EWOULDBLOCK)
        {
            printf("send heartbeat err: %d\n", errno);
        }
    }
    else
    {
        if (ret == bufSize)
        {
            printf("send to client: %d heartbeat success!\n", cfd);
        }
        else
        {
            printf("send to client: %d heartbeat not good!\n", cfd);
        }
    }
}

void Server::updateClientHeartbeat(int cfd)
{
    long now_sec, now_ms;
    getTime(&now_sec, &now_ms);
    m_mapClients[cfd].lastHeartbeat = now_sec * 1000 + now_ms;
}

int Server::checkHeartbeatTimerProc(long long id)
{
    std::vector<int> timeoutClients;
    for (const auto &it : m_mapClients)
    {
        if (it.second.lastHeartbeat != -1)
        {
            long now_sec, now_ms;
            long long nowTimeStamp;
            getTime(&now_sec, &now_ms);
            nowTimeStamp = now_sec * 1000 + now_ms;
            long subTimeStamp = nowTimeStamp - it.second.lastHeartbeat;
            printf("check timeout: %ld\n", subTimeStamp);
            if (subTimeStamp > DEFAULT_SERVER_TIMEOUT_MS)
            {
                // delete
                timeoutClients.push_back(it.first);
            }
        }
    }
    for (const auto &it : timeoutClients)
    {
        printf("client %d is timeout\n", it);
        deleteClient(it);
    }
    return HEARTBEAT_INTERVAL_MS;
}

void Server::processNewProxy(ReplyNewProxyMsg rnpm)
{
    if (rnpm.IsSuccess)
    {
        printf("make proxy tunnel success\n");
    }
    else
    {
        printf("make proxy tunnel fail\n");
        deleteUser(rnpm.UserId);
    }
}

void Server::deleteUser(int fd)
{
    m_mapUsers.erase(fd);
    close(fd);
    m_reactor.removeFileEvent(fd, EVENT_WRITABLE | EVENT_READABLE);
    printf("deleted user:%d\n", fd);
}

void Server::setPassword(const char *password)
{
    if (password != NULL)
    {
        strncpy(m_serverPassword, MD5(password).toStr().c_str(), sizeof(m_serverPassword)); // md5加密
    }
}

void Server::deleteClient(int fd)
{
    printf("client gone!\n");
    m_reactor.removeFileEvent(fd, EVENT_READABLE | EVENT_WRITABLE);
    m_mapClients.erase(fd);
    close(fd);
    // 需要加快效率，不应每次遍历,注意删除顺序,proxy -> user -> remotelisten
    // 删除相关的proxy连接
    for (auto it = m_mapProxy.begin(); it != m_mapProxy.end();)
    {
        int ufd, cfd;
        ufd = it->second.userFd;
        cfd = findClientfdByPort(m_mapUsers[ufd].port);
        if (cfd == fd)
        {
            int pfd = it->first;
            m_reactor.removeFileEvent(pfd, EVENT_READABLE | EVENT_WRITABLE);
            close(pfd);
            it = m_mapProxy.erase(it);
            printf("delete proxy conn with this client! %d\n", pfd);
        }
        else
        {
            it++;
        }
    }
    // 删除相关的user
    for (auto it = m_mapUsers.begin(); it != m_mapUsers.end();)
    {
        int cfd = findClientfdByPort(it->second.port);
        if (cfd == fd)
        {
            int ufd = it->first;
            m_reactor.removeFileEvent(ufd, EVENT_READABLE | EVENT_WRITABLE);
            close(ufd);
            it = m_mapUsers.erase(it);
            printf("delete user conn with this client! %d\n", ufd);
        }
        else
        {
            it++;
        }
    }
    // 删除此客户端对应的公网监听的端口相关的资源
    for (auto it = m_mapListen.begin(); it != m_mapListen.end();)
    {
        if (it->second.clientFd == fd)
        {
            int remoteListenFd = it->first;
            m_reactor.removeFileEvent(remoteListenFd, EVENT_READABLE | EVENT_WRITABLE);
            close(remoteListenFd);
            it = m_mapListen.erase(it);
            printf("delete remote listen fd with this client! %d\n", remoteListenFd);
        }
        else
        {
            it++;
        }
    }
}

int Server::findClientfdByPort(unsigned short port)
{
    for (const auto &it : m_mapListen)
    {
        if (it.second.port == port)
        {
            return it.second.clientFd;
        }
    }
    return -1;
}

void Server::setLogger(Logger *logger)
{
    if (logger == nullptr)
    {
        return;
    }
    m_pLogger = logger;
}

void Server::startEventLoop()
{
    m_reactor.eventLoop(EVENT_LOOP_FILE_EVENT | EVENT_LOOP_TIMER_EVENT);
}