#ifndef __EVENT_H__
#define __EVENT_H__

#define EVENT_NONE 0
#define EVENT_READABLE 1
#define EVENT_WRITABLE 2
#define EVENT_BARRIER 4

#include <vector>
#include <map>
#include <functional>

struct FiredEvent
{
    int fd;
    int mask;
    FiredEvent(int _fd = -1, int _mask = 0) : fd(_fd), mask(_mask) {}
};

using FiredEvents = std::vector<FiredEvent>;
using FileProc = std::function<void(int fd, int mask)>;

struct FileEvent
{
    int mask;
    FileProc wFileProc;
    FileProc rFileProc;
    FileEvent(int _mask = 0): mask(_mask){}
};
using EventHandlerMap = std::map<int, FileEvent>;

#endif // __EVENT_H__