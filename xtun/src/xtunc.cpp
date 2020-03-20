#include <cstdio>
#include <csignal>
#include <vector>
#include <cstring>
#include <unistd.h>
#include <memory>

#include "client.h"
#include "inifile.h"
#include "logger.h"


const char ERR_PARAM[] = "param is illegal\n";

std::vector<ProxyInfo> pcs;
std::unique_ptr<Client> g_pClient;

std::string g_strCfgFileName;
bool g_isBackground = false; // 是否后台运行


struct ConfigServer
{
    unsigned short serverPort{};
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
    int serverPort;
    ret = iniFile.GetStringValue(common, "server_ip", &serverIp);
    if(ret != 0)
    {
        printf("config file can't find server_ip\n");
        exit(-1);
    }
    ret = iniFile.GetStringValue(common, "password", &password);
    if(ret != 0)
    {
        printf("config file can't find password\n");
        exit(-1);
    }
    ret = iniFile.GetIntValue(common, "server_port", &serverPort);
    if(ret != 0)
    {
        printf("config file can't find server_port\n");
        exit(-1);
    }
    ret = iniFile.GetStringValue(common, "log_path", &logPath);
    if(ret != 0)
    {
        printf("config file can't find log_path\n");
        exit(-1);
    }

    g_cfg.password = password;
    g_cfg.serverIp = serverIp;
    g_cfg.serverPort = serverPort;
    g_cfg.logPath = logPath;

    std::vector<string> sections;
    int num = iniFile.GetSections(&sections);
    int localPort, remotePort;
    std::string localIp;
    for (int i = 0; i < num; i++)
    {
        if (sections[i] != common && sections[i].length() != 0)
        {
            ProxyInfo pi = {0};
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
        exit(0);
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
    struct sigaction act{};
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    act.sa_handler = sigShutdownHandler;
    sigaction(SIGTERM, &act, nullptr);
    sigaction(SIGINT, &act, nullptr);
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
            if(optarg == nullptr)
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
        }
    }
    
    readConfig(g_strCfgFileName.c_str());
    if (g_isBackground)
    {
        daemon(0, 0);
    }

    auto logger = std::make_shared<Logger>();
    logger->setLogPath(g_cfg.logPath.c_str());
    logger->setAppName("xtunc");
    logger->info("---------------------");
    logger->warn("---------------------");
    logger->err("---------------------");

    g_pClient = std::make_unique<Client>(logger, g_cfg.serverIp.c_str(), g_cfg.serverPort);
    if (g_pClient == nullptr)
    {
        printf("make client err\n");
        logger->err("make client err");
        return -1;
    }

    g_pClient->setProxyConfig(pcs);
    g_pClient->setPassword(g_cfg.password.c_str());

    size_t retryCnt = 0, sleepSec;
    while (true)
    {
        g_pClient->runClient();
        
        printf("reconnect server...  %lu\n", retryCnt);
        logger->info("reconnect server... %lu times", ++retryCnt);

        sleepSec = retryCnt < 6 ? 10 * retryCnt : 60;
        sleep(sleepSec);   // seconds
    }
}
