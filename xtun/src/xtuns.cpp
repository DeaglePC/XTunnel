#include <string>
#include <csignal>
#include <memory>

#include "server.h"
#include "inifile.h"
#include "logger.h"


const char ERR_PARAM[] = "param is not illegal\n";

std::unique_ptr<Server> g_pServer;
std::string g_strCfgFileName;
bool g_isBackground = false; // 是否后台运行


struct ConfigServer
{
    unsigned short serverPort{};
    std::string password;
    std::string logPath;
} g_cfg;


void readConfig(const char *cfgFile)
{
    inifile::IniFile iniFile;
    int ret = iniFile.Load(cfgFile);
    if (ret == -1)
    {
        printf("can't open config file\n");
        exit(-1);
    }
    string common = "common";
    int serverPort;
    string password, logPath;
    ret = iniFile.GetIntValue(common, "server_port", &serverPort);
    if (ret != 0)
    {
        printf("config file cann't find server_port\n");
        exit(-1);
    }
    ret = iniFile.GetStringValue(common, "password", &password);
    if (ret != 0)
    {
        printf("config file cann't find password\n");
        exit(-1);
    }
    ret = iniFile.GetStringValue(common, "log_path", &logPath);
    if (ret != 0)
    {
        printf("config file cann't find log_path\n");
        exit(-1);
    }

    g_cfg.password = password;
    g_cfg.serverPort = serverPort;
    g_cfg.logPath = logPath;
    //printf("pw:%s\nsp: %d\npp: %d\n", g_cfg.password.c_str(), g_cfg.serverPort, g_cfg.proxyPort);
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
            if (optarg == nullptr)
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
    logger->setAppName("xtuns");
    logger->info("-------------------------");
    logger->warn("-------------------------");
    logger->err("-------------------------");

    g_pServer = std::make_unique<Server>(logger, g_cfg.serverPort);
    g_pServer->setPassword(g_cfg.password.c_str());
    g_pServer->startEventLoop();

    return 0;
}
