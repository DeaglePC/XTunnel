#include "server.h"
#include <map>
#include <string>
#include <signal.h>

Server *g_pServer = nullptr;

int main()
{
    signal(SIGPIPE, SIG_IGN);
    g_pServer = new Server;
    g_pServer->setPassword("FAE0B27C451C728867A567E8C1BB4E53");
    g_pServer->startEventLoop();
    delete g_pServer;
    return 0;
}