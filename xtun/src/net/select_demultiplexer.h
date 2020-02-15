#ifndef __SELECT_DEMULTIPLEXER_H__
#define __SELECT_DEMULTIPLEXER_H__

#include "event_demultiplexer.h"
#include <sys/select.h>

class SelectDemultiplexer : public EventDemultiplexer
{
public:
  SelectDemultiplexer();
  ~SelectDemultiplexer() override = default;

  void addEvent(const EventHandlerMap& fileEvents, int fd, int mask) override;
  void delEvent(const EventHandlerMap& fileEvents, int fd, int mask) override;
  int pollEvent(const EventHandlerMap &fileEvents,
                        FiredEvents &firedEvents, timeval *tvp) override;

private:
  fd_set m_rfds{};
  fd_set m_wfds{};
  fd_set m_tmp_rfds{};
  fd_set m_tmp_wfds{};
};

#endif // __SELECT_DEMULTIPLEXER_H__