#include <cstring>

#include "select_demultiplexer.h"


SelectDemultiplexer::SelectDemultiplexer()
{
    FD_ZERO(&m_rfds);
    FD_ZERO(&m_rfds);
}

void SelectDemultiplexer::addEvent(const EventHandlerMap& fileEvents, int fd, int mask)
{
    if (mask & EVENT_READABLE)
    {
        FD_SET(fd, &m_rfds);
    }
    if (mask & EVENT_WRITABLE)
    {
        FD_SET(fd, &m_wfds);
    }
}

void SelectDemultiplexer::delEvent(const EventHandlerMap& fileEvents, int fd, int mask)
{
    if (mask & EVENT_READABLE)
    {
        FD_CLR(fd, &m_rfds);
    }
    if (mask & EVENT_WRITABLE)
    {
        FD_CLR(fd, &m_wfds);
    }
}

int SelectDemultiplexer::pollEvent(const std::map<int, FileEvent> &fileEvents, FiredEvents &firedEvents, timeval *tvp)
{
    int max_fd = fileEvents.rbegin()->first + 1;
    memcpy(&m_tmp_rfds, &m_rfds, sizeof(fd_set));
    memcpy(&m_tmp_wfds, &m_wfds, sizeof(fd_set));

    int num = select(max_fd, &m_tmp_rfds, &m_tmp_wfds, nullptr, tvp);
    if (num < 0)
    {
        return -1;
    }
    if (num == 0)
    {
        return num;
    }
    int fd, mask;
    int index = 0;
    // 避免频繁分配内存
    if(firedEvents.capacity() < static_cast<size_t>(num))
    {
        firedEvents.resize(num);
    }
    for (const auto & fileEvent : fileEvents)
    {
        fd = fileEvent.first;
        mask = fileEvent.second.mask;
        int tmpMask = 0;
        if((mask & EVENT_READABLE) && FD_ISSET(fd, &m_tmp_rfds))
        {
            tmpMask |= EVENT_READABLE;
        }
        if((mask & EVENT_WRITABLE) && FD_ISSET(fd, &m_tmp_wfds))
        {
            tmpMask |= EVENT_WRITABLE;
        }
        if(tmpMask == 0)
        {
            continue;
        }
        firedEvents[index++] = FiredEvent(fd, tmpMask);
    }
    return index;
}
