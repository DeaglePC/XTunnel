#include "tnet.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>

int tnet::tcp_socket()
{
    return socket(AF_INET, SOCK_STREAM, 0);
}

int tnet::tcp_listen(int fd, unsigned short port)
{
    sockaddr_in addr;
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    int ret;
    ret = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (ret != 0)
    {
        printf("bind err!\n");
        return NET_ERR;
    }

    ret = listen(fd, 2);
    if (ret != 0)
    {
        printf("listen err!\n");
        return NET_ERR;
    }
    return NET_OK;
}

int tnet::set_block(int fd, int non_block)
{
    int flags;
    flags = fcntl(fd, F_GETFL);
    if (flags == -1)
    {
        printf("fcntl(F_GETFL) err\n");
        return NET_ERR;
    }

    if (non_block)
    {
        flags |= O_NONBLOCK;
    }
    else
        flags &= ~O_NONBLOCK;

    if (fcntl(fd, F_SETFL, flags) == -1)
    {
        printf("fcntl(F_SETFL) err\n");
        return NET_ERR;
    }
    return NET_OK;
}

int tnet::non_block(int fd)
{
    return set_block(fd, 1);
}

int tnet::block(int fd)
{
    return set_block(fd, 0);
}

int tnet::connect(int cfd, char *addr, unsigned short port)
{
    sockaddr_in remote_addr;
    bzero(&remote_addr, sizeof(remote_addr));
    remote_addr.sin_family = AF_INET;
    remote_addr.sin_addr.s_addr = inet_addr(addr);
    remote_addr.sin_port = htons(port);

    return ::connect(cfd, (struct sockaddr *)&remote_addr, sizeof(struct sockaddr));
}

int tnet::tcp_generic_connect(char *addr, unsigned short port)
{
    int fd;
    fd = tnet::tcp_socket();
    if (fd == -1)
    {
        printf("socket err\n");
        return NET_ERR;
    }
    int ret = tnet::connect(fd, addr, port);
    if (ret == -1)
    {
        close(fd);
        return NET_ERR;
    }
    return fd;
}

// 接收fd1的数据，转发给fd2
int tnet::tcp_dispatch_data(int fd1, int fd2, char *buf, size_t max_buf_size)
{
    int recvnum, sendnum;
    recvnum = recv(fd1, buf, max_buf_size, MSG_DONTWAIT);
    if (recvnum > 0)
    {
        //printf("recv fd1: %d %s\n", recvnum, buf);
        sendnum = send(fd2, buf, recvnum, MSG_DONTWAIT);
        if (sendnum == -1)
        {
            if (errno != EAGAIN && errno != EWOULDBLOCK)
            {
                printf("send to fd2 err: %d\n", errno);
                return NET_ERR;
            }
        }
        return recvnum;
    }
    else if (recvnum == 0)
    {
        printf("fd1 gone!\n");
        return NET_SHUTDOWN;
    }
    else if (recvnum < 0)
    {
        if (errno != EAGAIN && errno != EWOULDBLOCK)
        {
            printf("recv fd1 err: %d\n", errno);
            return NET_ERR;
        }
    }
    return NET_OK;
}

int tnet::tcp_accept(int fd, char *ip, size_t ip_len, int *port)
{
    sockaddr_in cli_addr;
    socklen_t cliaddr_len = sizeof(cli_addr);
    int ret = accept(fd, (struct sockaddr *)&cli_addr, &cliaddr_len);
    if (ret == -1)
    {
        return -1;
    }
    if (ip)
    {
        inet_ntop(AF_INET, (void *)&(cli_addr.sin_addr), ip, ip_len);
    }
    if (port)
    {
        *port = ntohs(cli_addr.sin_port);
    }
    return ret;
}
