#ifndef __TIMER_POOL_H__
#define __TIMER_POOL_H__

#include <functional>
#include <list>
#include <sys/time.h>
#include <time.h> //  time(1)

#define TIMER_OK 0
#define TIMER_ERR -1

/* 需要返回下次多久后执行本函数 < 0 则不继续执行 */
using TimeProc = std::function<int(long long id)>;
struct TimeEvent
{
    long long id;
    long when_sec;
    long when_ms;
    TimeProc timeProc;

    friend bool operator<(const TimeEvent &te1, const TimeEvent &te2)
    {
        if (te1.when_sec != te2.when_sec)
        {
            return te1.when_sec < te2.when_sec;
        }
        if (te1.when_ms != te2.when_ms)
        {
            return te1.when_ms < te2.when_ms;
        }
        return false;
    }

    friend bool operator==(const TimeEvent &te1, const TimeEvent &te2)
    {
        return te1.id == te2.id;
    }
};

void getTime(long *seconds, long *milliseconds);
void addMillisecondsToNow(long long milliseconds, long *sec, long *ms);

class TimerPool
{
  private:
    long long m_timeEventNextId;
    std::list<TimeEvent> m_timeEvents;
    time_t m_lastTime;

  public:
    TimerPool();
    ~TimerPool();
    long long createTimeEvent(long long milliseconds, TimeProc timeProc);
    int deleteTimeEvent(long long id);
    TimeEvent getNearestTimer();
    int processTimeEvents();
};

#endif // __TIMER_POOL_H__