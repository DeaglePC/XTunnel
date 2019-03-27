#include "timer_pool.h"
#include <cstdio>
#include <unistd.h>

TimerPool *tp;
long long id1,id2;

int fun1(long long id)
{
    static int cnt = 0;
    printf("i am : %lld\thello world %d\n", id, cnt++);
    if(cnt == 10)
    {
        int ret = tp->deleteTimeEvent(id2);
        if(ret == 0)
        {
            printf("delete:%lld\n",id2);
        }
        ret = tp->deleteTimeEvent(2124342);
        if(ret < 0)
        {
            printf("delete:2124342 not found\n");
        }
    }
    if(cnt == 20)
    {
        return -1;
    }
    return 1000;
}

int fun2(long long id)
{
    printf("wdnmd!\n");
    return 2000;
}

int fun3(long long id)
{
    printf("qzzzzz\n");
    return 1000;
}

int main(int argc, char const *argv[])
{
    tp = new TimerPool;

    TimeEvent te = tp->getNearestTimer();
    printf("nearest:%lld %lds %ldms\n", te.id, te.when_sec, te.when_ms);

    id1 = tp->createTimeEvent(1000, fun1);
    te = tp->getNearestTimer();
    printf("nearest:%lld %lds %ldms\n", te.id, te.when_sec, te.when_ms);

    id2 = tp->createTimeEvent(800, fun2);
    te = tp->getNearestTimer();
    printf("nearest:%lld %lds %ldms\n", te.id, te.when_sec, te.when_ms);

    tp->createTimeEvent(1000, fun3);

    while(1)
    {
        int ret = tp->processTimeEvents();
        if(ret > 0)
        {
            printf("processed:%d\n\n\n", ret);
        }
        usleep(50);
    }
    
    return 0;
}
