#ifndef __EPOLL_DEMULTIPLEXER_H__
#define __EPOLL_DEMULTIPLEXER_H__

#include <sys/epoll.h>
#include <unistd.h>

#include "event_demultiplexer.h"


class EpollDemultiplexer : public EventDemultiplexer
{
  public:
    EpollDemultiplexer();
    virtual ~EpollDemultiplexer();

    void addEvent(const EventHandlerMap& fileEvents, int fd, int mask) override;
    void delEvent(const EventHandlerMap& fileEvents, int fd, int mask) override;
    int pollEvent(const EventHandlerMap &fileEvents,
                          FiredEvents &firedEvents, timeval *tvp) override;

  private:
    int m_fdEpoll;
    std::vector<struct epoll_event> m_epollEvents;
};

#endif // __EPOLL_DEMULTIPLEXER_H__