#include "client.h"
#include <cstdio>
#include <signal.h>
#include <vector>
#include <cstring>
#include "inifile.h"

std::vector<ProxyInfo> pcs;
Client *g_pClient = nullptr;

struct ConfigServer
{
    unsigned short serverPort;
    unsigned short proxyPort;
    std::string password;
    std::string serverIp;
} g_cfg;

void readConfig(const char* configFile)
{
    string common = "common";
    inifile::IniFile iniFile;
    int ret = iniFile.Load(configFile);
    if(ret == -1)
    {
        printf("can't open config file\n");
        exit(-1);
    }
    string serverIp, password;
    int serverPort, proxyPort;
    iniFile.GetStringValue(common, "server_ip", &serverIp);
    iniFile.GetStringValue(common, "password", &password);
    iniFile.GetIntValue(common, "server_port", &serverPort);
    iniFile.GetIntValue(common, "proxy_port", &proxyPort);

    g_cfg.password = password;
    g_cfg.serverIp = serverIp;
    g_cfg.serverPort = serverPort;
    g_cfg.proxyPort = proxyPort;

    std::vector<string> sections;
    int num = iniFile.GetSections(&sections);
    int localPort, remotePort;
    std::string localIp;
    for(int i = 0; i < num; i++)
    {
        if(sections[i] != common && sections[i].length() != 0)
        {
            ProxyInfo pi;
            iniFile.GetStringValue(sections[i], "local_ip", &localIp);
            iniFile.GetIntValue(sections[i], "remote_port", &remotePort);
            iniFile.GetIntValue(sections[i], "local_port", &localPort);

            strcpy(pi.localIp, localIp.c_str());
            pi.remotePort = remotePort;
            pi.localPort = localPort;
            pcs.push_back(pi);
            printf("---%s\n", sections[i].c_str());
        }
    }
}

void sigShutdownHandler(int sig)
{
    switch (sig)
    {
    case SIGINT:
    case SIGTERM:
        if(g_pClient != nullptr)
            delete g_pClient;
        break;
    default:
        break;
    }
    exit(0);
}

/*
 * 设置处理信号的函数
 */
void setupSignalHandlers()
{
    struct sigaction act;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    act.sa_handler = sigShutdownHandler;
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGINT, &act, NULL);
}

int main(int argc, char const *argv[])
{
    signal(SIGPIPE, SIG_IGN);
    setupSignalHandlers();
    
    readConfig("tc.ini");

    g_pClient = new Client(g_cfg.serverIp.c_str(), g_cfg.serverPort);
    if(g_pClient == nullptr)
    {
        printf("make client err\n");
        return -1;
    }
    g_pClient->setProxyConfig(pcs);
    g_pClient->setPassword(g_cfg.password.c_str());
    g_pClient->setProxyPort(g_cfg.proxyPort);
    g_pClient->runClient();

    return 0;
}
