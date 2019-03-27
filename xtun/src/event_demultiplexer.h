#ifndef __EVENT_DEMULTIPLEXER_H__
#define __EVENT_DEMULTIPLEXER_H__

#include <sys/time.h>
#include "event.h"

class EventDemultiplexer
{
  public:
    EventDemultiplexer() {}
    virtual ~EventDemultiplexer() {}

    virtual void addEvent(const EventHandlerMap &fileEvents, int fd, int mask) = 0;
    virtual void delEvent(const EventHandlerMap &fileEvents, int fd, int mask) = 0;
    virtual int pollEvent(const EventHandlerMap &fileEvents, FiredEvents &fired_events, timeval *tvp) = 0;
};

#endif // __EVENT_DEMULTIPLEXER_H__