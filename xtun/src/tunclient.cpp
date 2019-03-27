#include "client.h"
#include <cstdio>
#include <signal.h>
#include <vector>
#include <cstring>

std::vector<ProxyInfo> pcs;

int main(int argc, char const *argv[])
{
    signal(SIGPIPE, SIG_IGN);
    
    ProxyInfo info;
    info.localPort = 22;
    strcpy(info.localIp, "127.0.0.1");
    info.remotePort = 38438;
    pcs.push_back(info);

    ProxyInfo info1;
    info1.localPort = 23;
    strcpy(info1.localIp, "127.0.0.1");
    info1.remotePort = 38439;
    pcs.push_back(info1);

    Client *pc = new Client("127.0.0.1", 10086);
    pc->setProxyConfig(pcs);

    pc->connectServer();
    int ret = pc->authServer("");
    printf("auth: %d\n", ret);

    pc->setProxyPort(10001);
    pc->runClient();

    return 0;
}
