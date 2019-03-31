#include <cstdio>
#include <signal.h>
#include <vector>
#include <cstring>
#include <unistd.h>
#include "client.h"
#include "inifile.h"
#include "logger.h"

std::vector<ProxyInfo> pcs;
Client *g_pClient = nullptr;
std::string g_strCfgFileName;
const char ERR_PARAM[] = "param is not illage\n";
Logger g_logger;
bool g_isBackground = false; // 是否后台运行

struct ConfigServer
{
    unsigned short serverPort;
    unsigned short proxyPort;
    std::string password;
    std::string serverIp;
    std::string logPath;
} g_cfg;

void readConfig(const char *configFile)
{
    string common = "common";
    inifile::IniFile iniFile;
    int ret = iniFile.Load(configFile);
    if (ret == -1)
    {
        printf("can't open config file\n");
        exit(-1);
    }
    string serverIp, password, logPath;
    int serverPort, proxyPort;
    ret = iniFile.GetStringValue(common, "server_ip", &serverIp);
    if(ret != 0)
    {
        printf("config file cann't find server_ip\n");
        exit(-1);
    }
    ret = iniFile.GetStringValue(common, "password", &password);
    if(ret != 0)
    {
        printf("config file cann't find password\n");
        exit(-1);
    }
    ret = iniFile.GetIntValue(common, "server_port", &serverPort);
    if(ret != 0)
    {
        printf("config file cann't find server_port\n");
        exit(-1);
    }
    ret = iniFile.GetIntValue(common, "proxy_port", &proxyPort);
    if(ret != 0)
    {
        printf("config file cann't find proxy_port\n");
        exit(-1);
    }
    ret = iniFile.GetStringValue(common, "log_path", &logPath);
    if(ret != 0)
    {
        printf("config file cann't find log_path\n");
        exit(-1);
    }

    g_cfg.password = password;
    g_cfg.serverIp = serverIp;
    g_cfg.serverPort = serverPort;
    g_cfg.proxyPort = proxyPort;
    g_cfg.logPath = logPath;

    std::vector<string> sections;
    int num = iniFile.GetSections(&sections);
    int localPort, remotePort;
    std::string localIp;
    for (int i = 0; i < num; i++)
    {
        if (sections[i] != common && sections[i].length() != 0)
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
        if (g_pClient != nullptr)
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

int main(int argc, char *argv[])
{
    signal(SIGPIPE, SIG_IGN);
    setupSignalHandlers();

    int op;
    while ((op = getopt(argc, argv, "c:d")) != -1)
    {
        switch (op)
        {
        case 'c':
            if(optarg == NULL)
            {
                printf(ERR_PARAM);
                exit(-1);
            }
            g_strCfgFileName = std::string(optarg);
            break;
        case 'd':
            g_isBackground = true;
            break;
        default:
            printf(ERR_PARAM);
            exit(-1);
            break;
        }
    }
    
    readConfig(g_strCfgFileName.c_str());
    if (g_isBackground)
    {
        daemon(0, 0);
    }

    g_logger.setLogPath(g_cfg.logPath.c_str());
    g_logger.setAppName("xtunc");
    g_logger.info("---------------------");
    g_logger.warn("---------------------");
    g_logger.err("---------------------");

    g_pClient = new Client(g_cfg.serverIp.c_str(), g_cfg.serverPort);
    if (g_pClient == nullptr)
    {
        printf("make client err\n");
        g_logger.err("make client err");
        return -1;
    }

    g_pClient->setLogger(&g_logger);
    g_pClient->setProxyConfig(pcs);
    g_pClient->setPassword(g_cfg.password.c_str());
    g_pClient->setProxyPort(g_cfg.proxyPort);
    g_pClient->runClient();
    delete g_pClient;

    return 0;
}
