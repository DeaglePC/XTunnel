#include "reactor.h"
#include <cstdio>

Reactor::Reactor() : m_demultiplexer(nullptr), m_isStopLoop(false)
{
#ifdef __linux__
    m_demultiplexer = new EpollDemultiplexer;
#else
    m_demultiplexer = new SelectDemultiplexer;
#endif // __linux__
}

Reactor::~Reactor()
{
    if (m_demultiplexer != nullptr)
    {
        delete m_demultiplexer;
    }
}

void Reactor::registFileEvent(int fd, int mask, FileProc proc)
{
    m_demultiplexer->addEvent(m_fileEvents, fd, mask);
    auto it = m_fileEvents.find(fd);
    if (it == m_fileEvents.end())
    {
        FileEvent fe;
        fe.mask = mask;
        if (mask & EVENT_READABLE)
        {
            fe.rFileProc = proc;
        }
        if (mask & EVENT_WRITABLE)
        {
            fe.wFileProc = proc;
        }
        m_fileEvents[fd] = fe;
    }
    else
    {
        it->second.mask |= mask;
        if (mask & EVENT_READABLE)
        {
            it->second.rFileProc = proc;
        }
        if (mask & EVENT_WRITABLE)
        {
            it->second.wFileProc = proc;
        }
    }
}

void Reactor::removeFileEvent(int fd, int mask)
{
    m_demultiplexer->delEvent(m_fileEvents, fd, mask);
    auto it = m_fileEvents.find(fd);
    if (it == m_fileEvents.end())
    {
        return;
    }
    it->second.mask = it->second.mask & (~mask);
    if (it->second.mask == 0)
    {
        m_fileEvents.erase(it);
    }
}

int Reactor::processEvents(int flag)
{
    if (!(flag & EVENT_LOOP_FILE_EVENT) && !(flag & EVENT_LOOP_TIMER_EVENT))
        return 0;

    int ret, processed = 0;
    struct timeval tv, *tvp;
    TimeEvent teShortest;
    teShortest.id = -1;
    if ((flag & EVENT_LOOP_TIMER_EVENT) && !(flag & EVENT_LOOP_DONT_WAIT))
    {
        teShortest = m_timePool.getNearestTimer();
    }

    if (teShortest.id != -1)
    {
        long now_sec, now_ms;
        getTime(&now_sec, &now_ms);
        tvp = &tv;
        long long ms = (teShortest.when_sec - now_sec) * 1000 +
                       teShortest.when_ms - now_ms;
        if (ms > 0)
        {
            // 等待最近的定时器触发的时间
            tvp->tv_sec = ms / 1000;
            tvp->tv_usec = (ms % 1000) * 1000;
        }
        else
        {
            // 立刻执行
            tvp->tv_sec = 0;
            tvp->tv_usec = 0;
        }
    }
    else
    {
        if (flag & EVENT_LOOP_DONT_WAIT)
        {
            tv.tv_usec = 0;
            tv.tv_sec = 0;
            tvp = &tv;
        }
        else
        {
            // 阻塞
            tvp = NULL;
        }
    }

    if (tvp == NULL)
        printf("tvp NULL");
    else
    {
        // printf("----timeval: %ld %ld\n", tvp->tv_sec, tvp->tv_usec);
    }

    // printf("poll event!\n");
    ret = m_demultiplexer->pollEvent(m_fileEvents, m_firedEvents, tvp);

    // printf("poll event done! %d\n", ret);

    for (int i = 0; i < ret; i++)
    {
        int fd = m_firedEvents[i].fd;
        int mask = m_firedEvents[i].mask;

        if (m_fileEvents.find(fd) != m_fileEvents.end() && mask & EVENT_READABLE)
        {
            m_fileEvents[fd].rFileProc(fd, mask);
            processed++;
        }
        if (m_fileEvents.find(fd) != m_fileEvents.end() && mask & EVENT_WRITABLE)
        {
            m_fileEvents[fd].wFileProc(fd, mask);
            processed++;
        }
    }

    if (flag & EVENT_LOOP_TIMER_EVENT)
    {
        processed += m_timePool.processTimeEvents();
    }
    return processed;
}

void Reactor::eventLoop(int flag)
{
    while (!m_isStopLoop)
    {
        processEvents(flag);
    }
}

void Reactor::stopEventLoop()
{
    m_isStopLoop = true;
}

void Reactor::setStart()
{
    m_isStopLoop = false;
}

long long Reactor::registTimeEvent(long long milliseconds, TimeProc timeProc)
{
    return m_timePool.createTimeEvent(milliseconds, timeProc);
}

int Reactor::removeTimeEvent(long long id)
{
    return m_timePool.deleteTimeEvent(id);
}
