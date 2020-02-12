#include "epoll_demultiplexer.h"

EpollDemultiplexer::EpollDemultiplexer()
{
    m_fdEpoll = epoll_create(1024);
}

EpollDemultiplexer::~EpollDemultiplexer()
{
    close(m_fdEpoll);
}

void EpollDemultiplexer::addEvent(const EventHandlerMap &fileEvents,
                                  int fd, int mask)
{
    auto it = fileEvents.find(fd);
    int op = EPOLL_CTL_MOD;
    if (it == fileEvents.end())
    {
        op = EPOLL_CTL_ADD;
    }
    else
    {
        mask |= it->second.mask;
    }
    
    struct epoll_event ee = {0};
    ee.events = 0;
    
    if (mask & EVENT_READABLE)
    {
        ee.events |= EPOLLIN;
    }
    if (mask & EVENT_WRITABLE)
    {
        ee.events |= EPOLLOUT;
    }
    ee.data.fd = fd;
    //printf("----------fd:%d, op:%d, mask:%d\n",fd,op,mask);
    epoll_ctl(m_fdEpoll, op, fd, &ee);
}

void EpollDemultiplexer::delEvent(const EventHandlerMap &fileEvents,
                                  int fd, int mask)
{
    auto it = fileEvents.find(fd);
    if (it == fileEvents.end())
    {
        return;
    }
    struct epoll_event ee = {0};
    ee.events = 0;
    int nowMask = it->second.mask & (~mask);
    if (nowMask & EVENT_READABLE)
    {
        ee.events |= EPOLLIN;
    }
    if (nowMask & EVENT_WRITABLE)
    {
        ee.events |= EPOLLOUT;
    }
    ee.data.fd = fd;
    int op = nowMask == EVENT_NONE ? EPOLL_CTL_DEL : EPOLL_CTL_MOD;
    epoll_ctl(m_fdEpoll, op, fd, &ee);
}

int EpollDemultiplexer::pollEvent(const EventHandlerMap &fileEvents,
                                  FiredEvents &firedEvents, timeval *tvp)
{
    if (m_epollEvents.capacity() < fileEvents.size())
    {
        m_epollEvents.resize(fileEvents.size());
    }
    int ret = epoll_wait(m_fdEpoll, &m_epollEvents[0], m_epollEvents.size(),
                         tvp ? (tvp->tv_sec * 1000 + tvp->tv_usec / 1000) : -1);
    if (ret <= 0)
    {
        return 0;
    }
    if(firedEvents.capacity() < static_cast<size_t>(ret))
    {
        firedEvents.resize(ret);
    }
    for (int i = 0; i < ret; i++)
    {
        int mask = 0;
        if (m_epollEvents[i].events & EPOLLIN)
        {
            mask |= EVENT_READABLE;
        }
        if (m_epollEvents[i].events & EPOLLOUT)
        {
            mask |= EVENT_WRITABLE;
        }
        firedEvents[i].fd = m_epollEvents[i].data.fd;
        firedEvents[i].mask = mask;
    }
    return ret;
}
