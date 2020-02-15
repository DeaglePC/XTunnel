#ifndef __REACTOR_H__
#define __REACTOR_H__

#include <map>
#include <memory>

#include "event.h"
#include "event_demultiplexer.h"
#ifdef __linux__
#include "epoll_demultiplexer.h"
#else
#include "select_demultiplexer.h"
#endif // __linux__
#include "timer.h"


#define EVENT_LOOP_DONT_WAIT 1
#define EVENT_LOOP_FILE_EVENT 2
#define EVENT_LOOP_TIMER_EVENT 4
#define EVENT_LOOP_ALL_EVENT (EVENT_LOOP_FILE_EVENT | EVENT_LOOP_TIMER_EVENT)

class Reactor
{
private:
  std::unique_ptr<EventDemultiplexer> m_demultiplexer;
  EventHandlerMap m_fileEvents;
  FiredEvents m_firedEvents; // Multiplexed memory
  Timer m_timer;

  bool m_isStopLoop;

  int processEvents(int flag);

public:
  Reactor();
  ~Reactor() = default;

  void eventLoop(int flag);
  void stopEventLoop();
  void setStart();

  void registerFileEvent(int fd, int mask, const FileProc& proc);
  void removeFileEvent(int fd, int mask);

  long long registerTimeEvent(long long milliseconds, TimeProc timeProc);
  int removeTimeEvent(long long id);
};

#endif // __REACTOR_H__