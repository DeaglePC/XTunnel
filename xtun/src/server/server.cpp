#include <netinet/in.h>
#include <cstring>

#include "server.h"

#include "../third_part/md5.h"


Server::Server(std::shared_ptr<Logger> &logger, unsigned short port)
    : m_serverSocketFd(-1), m_serverPort(port), m_pLogger(logger)
{
    initServer();
}

Server::~Server()
{
    if (m_serverSocketFd != -1)
    {
        close(m_serverSocketFd);
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

    printf("bye...");
    m_pLogger->info("bye...");
}

int Server::listenControl()
{
    m_serverSocketFd = tnet::tcp_socket();
    if (m_serverSocketFd == NET_ERR)
    {
        printf("make server socker err!\n");
        m_pLogger->err("make server socker err!");
        return -1;
    }

    int ret = tnet::tcp_listen(m_serverSocketFd, m_serverPort);
    if (ret == NET_ERR)
    {
        printf("server listen err!\n");
        m_pLogger->err("server listen err!");
        return -1;
    }

    tnet::non_block(m_serverSocketFd);
    m_reactor.registerFileEvent(
        m_serverSocketFd,
        EVENT_READABLE,
        std::bind(
            &Server::serverAcceptProc,
            this,
            std::placeholders::_1,
            std::placeholders::_2
        )
    );

    return 0;
}

void Server::initServer()
{
    int ret = listenControl();
    if (ret == -1)
    {
        exit(-1);
    }

    m_heartbeatTimerId = m_reactor.registerTimeEvent(
        HEARTBEAT_INTERVAL_MS,
        std::bind(
            &Server::checkHeartbeatTimerProc,
            this,
            std::placeholders::_1
        )
    );
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
            if (errno != EAGAIN && errno != EWOULDBLOCK)
            {
                printf("serverAcceptProc accept err: %d\n", errno);
                m_pLogger->err("serverAcceptProc accept err: %d", errno);
            }
            return;
        }
        printf("serverAcceptProc new conn from %s:%d\n", ip, port);
        m_pLogger->info("new client connection from %s:%d", ip, port);

        m_mapClients[connfd];
        updateClientHeartbeat(connfd);

        tnet::non_block(connfd);
        m_reactor.registerFileEvent(
            connfd,
            EVENT_READABLE,
            std::bind(
                &Server::clientAuthProc,
                this,
                std::placeholders::_1,
                std::placeholders::_2
            )
        );
    }
}

// ---------------------------------
void Server::clientSafeRecv(int cfd, const std::function<void(int cfd, size_t dataSize)>& callback)
{
    int ret;
    // there is not header init if data len is 0
    size_t targetSize = m_mapClients[cfd].header.ensureTargetDataSize();
    if (m_mapClients[cfd].isRecvBufFull() || m_userFullBuffer.isFull())
    {
        m_pLogger->warn("client recv buffer is full: %d, ", cfd);
        return;
    }

    ret = recv(cfd, m_mapClients[cfd].recvBuf + m_mapClients[cfd].recvNum,
                targetSize - m_mapClients[cfd].recvNum, MSG_DONTWAIT);
    
    if (ret == -1)
    {
        if (errno != EAGAIN && errno != EWOULDBLOCK)
        {
            printf("recv client data err: %d\n", errno);
            m_pLogger->err("recv client data err: %d\n", errno);
        }
        return;
    }
    else if (ret == 0)
    {
        deleteClient(cfd);
    }
    else if (ret > 0)
    {
        m_mapClients[cfd].recvNum += ret;

        if (m_mapClients[cfd].recvNum == targetSize)
        {
            m_mapClients[cfd].recvNum = 0;

            // targetSize = header size or data size
            if (targetSize == sizeof(DataHeader))
            {
                memcpy(&m_mapClients[cfd].header, m_mapClients[cfd].recvBuf, targetSize);
            }
            else
            {
                uint32_t realDataSize = m_pCryptor->decrypt(
                    m_mapClients[cfd].header.iv, 
                    (uint8_t*)m_mapClients[cfd].recvBuf, 
                    targetSize
                );

                // if recv all done, we callback
                callback(cfd, realDataSize);

                // remember init datalen for next recv
                m_mapClients[cfd].header.dataLen = 0;
            }
        }
    }
}

// befor use this method, ensure you have filled the buf
void Server::clientSafeSend(int cfd, const std::function<void(int cfd)>& callback)
{
    int ret = send(cfd, &m_mapClients[cfd].sendBuf, m_mapClients[cfd].sendSize, MSG_DONTWAIT);

    if (ret == -1)
    {
        if (errno != EAGAIN && errno != EWOULDBLOCK)
        {
            printf("clientSafeSend err: %d\n", errno);
            m_pLogger->err("clientSafeSend err: %d\n", errno);
            deleteClient(cfd);
        }
    }
    else if (ret > 0)
    {
        m_mapClients[cfd].sendSize -= ret;

        if (m_mapClients[cfd].sendSize == 0)
        {
            callback(cfd);
        }
        else
        {
            printf("+++++++++++++++++++++++++++++!\n");
            memmove(
                m_mapClients[cfd].sendBuf, 
                m_mapClients[cfd].sendBuf + ret, 
                m_mapClients[cfd].sendSize
            );
        }
    }
}
// -----------------------------


// =========================== auth start
void Server::clientAuthProc(int cfd, int mask)
{
    if (!(mask & EVENT_READABLE))
    {
        return;
    }

    clientSafeRecv(
        cfd, 
        std::bind(
            &Server::checkClientAuthResult, 
            this, 
            std::placeholders::_1, 
            std::placeholders::_2
        )
    );
}

void Server::checkClientAuthResult(int cfd, size_t dataSize)
{
    if (dataSize != sizeof(m_serverPassword))
    {
        printf(
            "encrpt ClientAuthResult data len not good! expect: %lu, infact: %lu\n", 
            sizeof(m_serverPassword), dataSize
        );
        return;
    }

    processClientAuthResult(
        cfd,
        strncmp(m_serverPassword, m_mapClients[cfd].recvBuf, sizeof(m_serverPassword)) == 0
    );
}

void Server::processClientAuthResult(int cfd, bool isGood)
{
    if (isGood)
    {
        m_mapClients[cfd].status = CLIENT_STATUS_PW_OK;
    }
    else
    {
        m_mapClients[cfd].status = CLIENT_STATUS_PW_WRONG;
    }

    m_mapClients[cfd].sendSize += MsgUtil::packEncryptedData(
            m_pCryptor,
            (uint8_t *) m_mapClients[cfd].currSendBufAddr(),
            (uint8_t *) AUTH_TOKEN,
            sizeof(AUTH_TOKEN)
    );

    m_reactor.registerFileEvent(
        cfd,
        EVENT_WRITABLE,
        std::bind(
            &Server::replyClientAuthProc,
            this,
            std::placeholders::_1,
            std::placeholders::_2
        )
    );
}

void Server::replyClientAuthProc(int cfd, int mask)
{
    if (!(mask & EVENT_WRITABLE))
    {
        return;
    }

    clientSafeSend(
            cfd,
            std::bind(
                    &Server::onReplyClientAuthDone,
                    this, std::placeholders::_1
            )
    );
}

void Server::onReplyClientAuthDone(int cfd)
{
    if (m_mapClients[cfd].status == CLIENT_STATUS_PW_OK)
    {
        m_reactor.removeFileEvent(cfd, EVENT_WRITABLE);
        m_reactor.registerFileEvent(
            cfd,
            EVENT_READABLE,
            std::bind(
                &Server::recvClientProxyPortsProc,
                this,
                std::placeholders::_1,
                std::placeholders::_2
            )
        );
    }
    else if(m_mapClients[cfd].status == CLIENT_STATUS_PW_WRONG)
    {
        printf("pw not good, delete client...\n");
        m_pLogger->info("password not good, delete client...");
        
        deleteClient(cfd);
    }
}
// =========================== auth end


void Server::recvClientProxyPortsProc(int cfd, int mask)
{
    if (!(mask & EVENT_READABLE))
    {
        return;
    }

    clientSafeRecv(
        cfd, 
        std::bind(
            &Server::checkClientProxyPortsResult, 
            this, 
            std::placeholders::_1, 
            std::placeholders::_2
        )
    );
}

void Server::checkClientProxyPortsResult(int cfd, size_t dataSize)
{
    unsigned short portNum = 0;

    // first 2bytes is the port number
    memcpy(&portNum, m_mapClients[cfd].recvBuf, sizeof(portNum));
    if (portNum <= 0)
    {
        deleteClient(cfd);
        return;
    }

    size_t portDataSize = portNum * sizeof(unsigned short);
    if (dataSize != portDataSize + sizeof(portNum))
    {
        printf(
            "encrpt ClientProxyPortsResult data len not good! expect: %lu, infact: %lu\n", 
            portDataSize + sizeof(portNum), dataSize
        );
        return;
    }

    // alloc mem
    m_mapClients[cfd].remotePorts.resize(portNum);
    memcpy(
        &m_mapClients[cfd].remotePorts[0], 
        m_mapClients[cfd].recvBuf + sizeof(portNum), 
        portDataSize
    );
    initClient(cfd);
}

void Server::initClient(int fd)
{
    listenRemotePort(fd);
    updateClientHeartbeat(fd);

    m_reactor.registerFileEvent(fd, EVENT_READABLE,
                                std::bind(&Server::recvClientDataProc,
                                          this, std::placeholders::_1, std::placeholders::_2));
}

int Server::listenRemotePort(int cfd)
{
    size_t len = m_mapClients[cfd].remotePorts.size();
    int num = 0;
    for (size_t i = 0; i < len; i++)
    {
        int fd = tnet::tcp_socket();
        if (fd == -1)
        {
            printf("listenRemotePort make socket err: %d\n", errno);
            m_pLogger->err("listenRemotePort make socket err: %d", errno);
            continue;
        }
        unsigned short port = m_mapClients[cfd].remotePorts[i];
        int ret = tnet::tcp_listen(fd, port);
        if (ret == -1)
        {
            printf("listenRemotePort listen port:%d err: %d\n", port, errno);
            m_pLogger->err("listenRemotePort listen port:%d err: %d", port, errno);
            continue;
        }
        num++;
        ListenInfo linfo = {0};
        linfo.port = port;
        linfo.clientFd = cfd;
        m_mapListen[fd] = linfo;
        tnet::non_block(fd);
        m_reactor.registerFileEvent(fd, EVENT_READABLE,
                                    std::bind(&Server::userAcceptProc,
                                              this, std::placeholders::_1, std::placeholders::_2));
        printf("listenRemotePort listening port: %d\n", port);
        m_pLogger->info("listenRemotePort listening port: %d", port);
    }
    return num;
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
            if (errno != EAGAIN && errno != EWOULDBLOCK)
            {
                printf("userAcceptProc accept err: %d\n", errno);
                m_pLogger->err("userAcceptProc accept err: %d", errno);
            }
            return;
        }
        printf("userAcceptProc new conn from %s:%d\n", ip, port);
        m_pLogger->info("new user connection from %s:%d", ip, port);

        m_mapUsers[connfd].port = m_mapListen[fd].port;
        m_mapUsers[connfd].cfd = m_mapListen[fd].clientFd;

        tnet::non_block(connfd);

        m_reactor.registerFileEvent(
            connfd,
            EVENT_READABLE,
            std::bind(
                &Server::userReadDataProc,
                this,
                std::placeholders::_1,
                std::placeholders::_2
            )
        );
        sendClientNewProxy(m_mapListen[fd].clientFd, connfd, m_mapListen[fd].port);
    }
}

void Server::sendClientNewProxy(int cfd, int ufd, unsigned short remotePort)
{
    MsgData msgData = {0};
    NewProxyMsg newProxyMsg = {0};

    newProxyMsg.userId = ufd;
    newProxyMsg.remotePort = remotePort;

    msgData.type = MSGTYPE_NEW_PROXY;
    msgData.size = sizeof(newProxyMsg);
    size_t bufSize = sizeof(msgData) + sizeof(newProxyMsg);
    char buf[bufSize];

    memcpy(buf, &msgData, sizeof(msgData));
    memcpy(buf + sizeof(msgData), &newProxyMsg, sizeof(newProxyMsg));

    printf("##### ufd: %d\n", ufd);
    m_mapClients[cfd].sendSize += MsgUtil::packEncryptedData(
            m_pCryptor,
            (uint8_t *) m_mapClients[cfd].currSendBufAddr(),
            (uint8_t *) buf,
            bufSize
    );

    m_reactor.registerFileEvent(
        cfd,
        EVENT_WRITABLE,
        std::bind(
            &Server::sendClientNewProxyProc,
            this,
            std::placeholders::_1,
            std::placeholders::_2
        )
    );
}

void Server::sendClientNewProxyProc(int cfd, int mask)
{
    if (!(mask & EVENT_WRITABLE))
    {
        return;
    }

    clientSafeSend(
            cfd,
            std::bind(
                    &Server::onSendClientNewProxyDone,
                    this, std::placeholders::_1
            )
    );
}

void Server::onSendClientNewProxyDone(int cfd)
{
    m_reactor.removeFileEvent(cfd, EVENT_WRITABLE);
}

void Server::recvClientDataProc(int cfd, int mask)
{
    if (!(mask & EVENT_READABLE))
    {
        return;
    }

    clientSafeRecv(
        cfd, 
        std::bind(
            &Server::processClientBuf, 
            this, 
            std::placeholders::_1, 
            std::placeholders::_2
        )
    );
}

void Server::processClientBuf(int cfd, size_t dataSize)
{
    MsgData msgData;

    memcpy(&msgData, m_mapClients[cfd].recvBuf, sizeof(MsgData));

    if (msgData.type == MSGTYPE_HEARTBEAT)
    {
        if (memcmp(m_mapClients[cfd].recvBuf + sizeof(MsgData), 
                    HEARTBEAT_CLIENT_MSG, msgData.size) == 0)
        {
            updateClientHeartbeat(cfd);
            sendHeartbeat(cfd);
        }
    }
    else if (msgData.type == MSGTYPE_REPLY_NEW_PROXY)
    {
        ReplyNewProxyMsg rnpm = {false};
        memcpy(&rnpm, m_mapClients[cfd].recvBuf + sizeof(MsgData), msgData.size);

        processNewProxy(rnpm, msgData.userId);
    }
    else if (msgData.type == MSGTYPE_CLIENT_APP_DATA)
    {
        int ufd = msgData.userId;
        if (m_mapUsers[ufd].isSendBufFull(msgData.size))
        {
            m_userFullBuffer.ufd = ufd;
            m_userFullBuffer.msgSize = msgData.size;
            m_pLogger->err("user: %d send buf is full!", ufd);
            return;
        }

        memcpy(
            m_mapUsers[ufd].currSendBufAddr(),
            m_mapClients[cfd].recvBuf + sizeof(MsgData),
            msgData.size
        );
        m_mapUsers[ufd].sendSize += msgData.size;

        // duplicated register is ok
        m_reactor.registerFileEvent(
            ufd,
            EVENT_WRITABLE,
            std::bind(
                &Server::userWriteDataProc,
                this,
                std::placeholders::_1,
                std::placeholders::_2
            )
        );
    }
    else if (msgData.type == MSGTYPE_LOCAL_DOWN)
    {
        deleteUser(msgData.userId);
    }
}

void Server::tellClientUserDown(int ufd)
{
    int cfd = m_mapUsers[ufd].cfd;

    MsgData msgData;
    msgData.type = MSGTYPE_USER_DOWN;
    msgData.userId = ufd;
    msgData.size = 0;

    m_mapClients[cfd].sendSize += MsgUtil::packEncryptedData(
            m_pCryptor,
            (uint8_t *) m_mapClients[cfd].currSendBufAddr(),
            (uint8_t *) &msgData,
            sizeof(msgData)
    );

    m_reactor.registerFileEvent(
        cfd,
        EVENT_WRITABLE,
        std::bind(
            &Server::tellClientUserDownProc,
            this,
            std::placeholders::_1,
            std::placeholders::_2
        )
    );
}

void Server::tellClientUserDownProc(int cfd, int mask)
{
    if (!(mask & EVENT_WRITABLE))
    {
        return;
    }

    clientSafeSend(
            cfd,
            std::bind(
                    &Server::onTellClientUserDownDone,
                    this,
                    std::placeholders::_1
            )
    );
}

void Server::onTellClientUserDownDone(int cfd)
{
    m_reactor.removeFileEvent(cfd, EVENT_WRITABLE);
    printf("onTellClientUserDownDone\n");
}

void Server::sendHeartbeat(int cfd)
{
    if (m_mapClients[cfd].isSendBufFull())
    {
        m_pLogger->err("client: %d send buf is full, can't send heartbeat", cfd);
        return;
    }

    MsgData heartData;
    heartData.type = MSGTYPE_HEARTBEAT;
    heartData.size = strlen(HEARTBEAT_SERVER_MSG);

    size_t dataSize = sizeof(heartData) + strlen(HEARTBEAT_SERVER_MSG);
    char bufData[dataSize];

    memcpy(bufData, &heartData, sizeof(heartData));
    memcpy(bufData + sizeof(heartData), HEARTBEAT_SERVER_MSG, strlen(HEARTBEAT_SERVER_MSG));

    m_mapClients[cfd].sendSize += MsgUtil::packEncryptedData(
            m_pCryptor,
            (uint8_t *) m_mapClients[cfd].currSendBufAddr(),
            (uint8_t *) bufData,
            dataSize
    );

    m_reactor.registerFileEvent(
        cfd,
        EVENT_WRITABLE,
        std::bind(
            &Server::writeHeartbeatDataProc,
            this,
            std::placeholders::_1,
            std::placeholders::_2
        )
    );
}

void Server::writeHeartbeatDataProc(int cfd, int mask)
{
    if (!(mask & EVENT_WRITABLE))
    {
        return;
    }

    clientSafeSend(
            cfd,
            std::bind(
                    &Server::onWriteHeartbeatDataDone,
                    this,
                    std::placeholders::_1
            )
    );
}

void Server::onWriteHeartbeatDataDone(int cfd)
{
    m_reactor.removeFileEvent(cfd, EVENT_WRITABLE);
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
            // printf("check timeout: %ld\n", subTimeStamp);
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
        m_pLogger->info("client %d is timeout", it);
        deleteClient(it);
    }
    return HEARTBEAT_INTERVAL_MS;
}

void Server::processNewProxy(const ReplyNewProxyMsg &rnpm, int uid)
{
    if (rnpm.isSuccess)
    {
        printf("make proxy tunnel success\n");
        m_pLogger->info("make proxy tunnel success");
    }
    else
    {
        printf("make proxy tunnel fail\n");
        m_pLogger->info("make proxy tunnel fail");
        deleteUser(uid);
    }
}


/*
 * 发送缓冲区的数据给user
 */
void Server::userWriteDataProc(int ufd, int mask)
{
    printf("on userWriteDataProc\n");
    auto numSend = send(ufd, m_mapUsers[ufd].sendBuf, m_mapUsers[ufd].sendSize, MSG_DONTWAIT);
    if (numSend > 0)
    {
        if (static_cast<size_t>(numSend) == m_mapUsers[ufd].sendSize)
        {
            m_reactor.removeFileEvent(ufd, EVENT_WRITABLE);
            // 缓冲区已经全部发送了，从开始放数据
            m_mapUsers[ufd].sendSize = 0;
            printf("userWriteDataProc: send all data: %ld\n", numSend);
        }
        else
        {
            // 没有全部发送完，把没发送的数据移动到前面
            size_t newSize = m_mapUsers[ufd].sendSize - numSend; // 还剩多少没发送完
            m_mapUsers[ufd].sendSize = newSize;
            memmove(m_mapUsers[ufd].sendBuf, m_mapUsers[ufd].sendBuf + numSend, newSize);
            printf("userWriteDataProc: send partial data: %ld, left:%lu\n", numSend, newSize);
        }

        if (
            m_userFullBuffer.isFull()
            && !m_mapUsers[ufd].isSendBufFull(m_mapUsers[ufd].sendSize + m_userFullBuffer.msgSize)
        )
        {
            memcpy(
                m_mapUsers[ufd].currSendBufAddr(),
                m_mapClients[m_mapUsers[ufd].cfd].recvBuf + sizeof(MsgData),
                m_userFullBuffer.msgSize
            );
            m_mapUsers[ufd].sendSize += m_userFullBuffer.msgSize;
            m_userFullBuffer.reset();
        }
    }
    else
    {
        if (errno != EAGAIN && errno != EWOULDBLOCK)
        {
            printf("userWriteDataProc send err:%d\n", errno);
            m_pLogger->err("userWriteDataProc send err:%d", errno);
        }
    }
}

/*
 * recv user data, and send to proxy tunnel with encrypted
 * send user data to client ======================== start
*/
void Server::userReadDataProc(int ufd, int mask)
{
    printf("on userReadDataProc\n");

    auto cfd = m_mapUsers[ufd].cfd;
    auto recvOffset = m_mapClients[cfd].sendSize + sizeof(MsgData);
    if (recvOffset >= MAX_BUF_SIZE)
    {
        printf("proxy send buf full\n");
        return;
    }

    int numRecv = recv(ufd, m_mapClients[cfd].sendBuf + recvOffset,
                       MAX_BUF_SIZE - recvOffset, MSG_DONTWAIT);
    if (numRecv == -1)
    {
        if (errno != EAGAIN && errno != EWOULDBLOCK)
        {
            printf("userReadDataProc recv err: %d\n", errno);
            m_pLogger->err("userReadDataProc recv err: %d\n", errno);
            return;
        }
    }
    else if (numRecv == 0)
    {
        tellClientUserDown(ufd);
        deleteUser(ufd);
    }
    else if (numRecv > 0)
    {
        MsgData msgData;
        msgData.type = MSGTYPE_CLIENT_APP_DATA;
        msgData.size = numRecv;
        msgData.userId = ufd;
        memcpy(m_mapClients[cfd].currSendBufAddr(), &msgData, sizeof(msgData));

        m_mapClients[cfd].sendSize += MsgUtil::packEncryptedData(
                m_pCryptor,
                (uint8_t *) m_mapClients[cfd].currSendBufAddr(),
                (uint8_t *) m_mapClients[cfd].currSendBufAddr(),
                numRecv + sizeof(msgData)
        );

        m_reactor.registerFileEvent(
            cfd,
            EVENT_WRITABLE,
            std::bind(
                &Server::sendUserDataProc,
                this,
                std::placeholders::_1,
                std::placeholders::_2
            )
        );
        printf("userReadDataProc: recv from user: %d, client snedSize: %lu\n", numRecv, m_mapClients[cfd].sendSize);
    }
}

void Server::sendUserDataProc(int fd, int mask)
{
    if (!(mask & EVENT_WRITABLE))
    {
        return;
    }

    clientSafeSend(
        fd,
        std::bind(
            &Server::onSendUserDataDone,
            this,
            std::placeholders::_1
        )
    );
}

void Server::onSendUserDataDone(int fd)
{
    m_reactor.removeFileEvent(fd, EVENT_WRITABLE);
    printf("onSendUserDataDone\n");
}
// send user data to client ======================== end


void Server::deleteUser(int fd)
{
    m_mapUsers.erase(fd);
    close(fd);
    m_reactor.removeFileEvent(fd, EVENT_WRITABLE | EVENT_READABLE);
    printf("deleted user:%d\n", fd);
    m_pLogger->info("deleted user:%d", fd);
}

void Server::deleteClient(int fd)
{
    printf("client gone!\n");
    m_pLogger->info("client gone!");
    m_reactor.removeFileEvent(fd, EVENT_READABLE | EVENT_WRITABLE);
    m_mapClients.erase(fd);
    close(fd);
    // 需要加快效率，不应每次遍历,注意删除顺序,user -> remotelisten
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
            m_pLogger->info("delete user conn with this client! %d", ufd);
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
            m_pLogger->info("delete remote listen fd with this client! %d\n", remoteListenFd);
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

void Server::setPassword(const char *password)
{
    if (password == nullptr)
    {
        return;
    }

    strncpy(m_serverPassword, MD5(password).toStr().c_str(), sizeof(m_serverPassword)); // md5加密

    m_pCryptor = std::make_unique<Cryptor>(CRYPT_CBC, (uint8_t*)m_serverPassword);
}

void Server::startEventLoop()
{
    m_pLogger->info("server running...");
    m_reactor.eventLoop(EVENT_LOOP_FILE_EVENT | EVENT_LOOP_TIMER_EVENT);
}