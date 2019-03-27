#ifndef __EPOLL_DEMULTIPLEXER_H__
#define __EPOLL_DEMULTIPLEXER_H__

#include "event_demultiplexer.h"
#include <sys/epoll.h>
#include <unistd.h>

class EpollDemultiplexer : public EventDemultiplexer
{
  public:
    EpollDemultiplexer();
    virtual ~EpollDemultiplexer();

    virtual void addEvent(const EventHandlerMap& fileEvents, int fd, int mask);
    virtual void delEvent(const EventHandlerMap& fileEvents, int fd, int mask);
    virtual int pollEvent(const EventHandlerMap &fileEvents,
                          FiredEvents &firedEvents, timeval *tvp);

  private:
    int m_fdEpoll;
    std::vector<struct epoll_event> m_epollEvents;
};

#endif // __EPOLL_DEMULTIPLEXER_H__