#include "timer_pool.h"

TimerPool::TimerPool() : m_timeEventNextId(1)
{
    m_lastTime = time(NULL);
}

TimerPool::~TimerPool()
{
}

void getTime(long *seconds, long *milliseconds)
{
    struct timeval tv;

    gettimeofday(&tv, NULL);
    *seconds = tv.tv_sec;
    *milliseconds = tv.tv_usec / 1000;
}

void addMillisecondsToNow(long long milliseconds, long *sec, long *ms)
{
    long cur_sec, cur_ms, when_sec, when_ms;

    getTime(&cur_sec, &cur_ms);
    when_sec = cur_sec + milliseconds / 1000;
    when_ms = cur_ms + milliseconds % 1000;
    if (when_ms >= 1000)
    {
        when_sec++;
        when_ms -= 1000;
    }
    *sec = when_sec;
    *ms = when_ms;
}

long long TimerPool::createTimeEvent(long long milliseconds, TimeProc timeProc)
{
    long long id = m_timeEventNextId++;
    TimeEvent te;
    te.id = id;
    addMillisecondsToNow(milliseconds, &te.when_sec, &te.when_ms);
    te.timeProc = timeProc;
    m_timeEvents.push_back(te);
    return id;
}

int TimerPool::deleteTimeEvent(long long id)
{
    for (auto it = m_timeEvents.begin(); it != m_timeEvents.end(); it++)
    {
        if (it->id == id)
        {
            m_timeEvents.erase(it);
            return TIMER_OK;
        }
    }
    return TIMER_ERR;
}

TimeEvent TimerPool::getNearestTimer()
{
    TimeEvent minVal;
    minVal.id = -1;
    for (auto it = m_timeEvents.begin(); it != m_timeEvents.end(); it++)
    {
        if (it == m_timeEvents.begin() || *it < minVal)
        {
            minVal = *it;
        }
    }
    return minVal;
}

int TimerPool::processTimeEvents()
{
    long now_sec, now_ms, when_sec, when_ms;
    long long id;
    int nProcessed = 0;
    time_t now = time(NULL);

    /* 上次处理的时间一定是比这次的时间戳小的，
     * 处理一种情况是把系统时间调的很大，然后又调正确 */
    if (now < m_lastTime)
    {
        for (auto it = m_timeEvents.begin(); it != m_timeEvents.end(); it++)
        {
            it->when_sec = 0;
        }
    }
    m_lastTime = now;

    for (auto it = m_timeEvents.begin(); it != m_timeEvents.end();)
    {
        getTime(&now_sec, &now_ms);
        if (now_sec > it->when_sec ||
            (now_sec == it->when_sec && now_ms >= it->when_ms))
        {
            int ret;
            id = it->id;
            ret = it->timeProc(id);
            nProcessed++;
            if (ret < 0)
            {
                it = m_timeEvents.erase(it);
            }
            else
            {
                addMillisecondsToNow(ret, &when_sec, &when_ms);
                it->when_sec = when_sec;
                it->when_ms = when_ms;
                it++;
            }
            continue;
        }
        it++;
    }
    return nProcessed;
}
