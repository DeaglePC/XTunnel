#ifndef __REACTOR_H__
#define __REACTOR_H__

#include "event.h"
#include "event_demultiplexer.h"
#ifdef __linux__
#include "epoll_demultiplexer.h"
#else
#include "select_demultiplexer.h"
#endif // __linux__
#include "timer_pool.h"
#include <map>

#define EVENT_LOOP_DONT_WAIT 1
#define EVENT_LOOP_FILE_EVENT 2
#define EVENT_LOOP_TIMER_EVENT 4
#define EVENT_LOOP_ALL_EVENT (EVENT_LOOP_FILE_EVENT | EVENT_LOOP_TIMER_EVENT)

class Reactor
{
private:
  EventDemultiplexer *m_demultiplexer;
  EventHandlerMap m_fileEvents;
  FiredEvents m_firedEvents; // 多次结果用同一份内存
  TimerPool m_timePool;      // 定时器

  bool m_isStopLoop;

  int processEvents(int flag);

public:
  Reactor();
  ~Reactor();

  void eventLoop(int flag);
  void stopEventLoop();
  void setStart();

  void registFileEvent(int fd, int mask, FileProc proc);
  void removeFileEvent(int fd, int mask);

  long long registTimeEvent(long long milliseconds, TimeProc timeProc);
  int removeTimeEvent(long long id);
};

#endif // __REACTOR_H__