#ifndef TNET_H
#define TNET_H

#include <stddef.h>

#define NET_OK 0
#define NET_ERR -1
#define NET_SHUTDOWN -2

class tnet
{
public:
    static int tcp_socket();
    static int tcp_listen(int fd, unsigned short port);
    static int set_block(int fd, int non_block);
    static int non_block(int fd);
    static int block(int fd);
    static int connect(int cfd, char *addr, unsigned short port);
    static int tcp_generic_connect(char *addr, unsigned short port);
    static int tcp_accept(int fd, char *ip, size_t ip_len, int *port);
    static int tcp_dispatch_data(int fd1, int fd2, char *buf, size_t max_buf_size);
};


#endif // TNET_H