#include "server.h"
#include <map>
#include <string>
#include <signal.h>
#include <fcntl.h>
#include "inifile.h"
#include "logger.h"

Server *g_pServer = nullptr;
std::string g_strCfgFileName;
const char ERR_PARAM[] = "param is not illage\n";
Logger g_logger;
bool g_isBackground = false; // 是否后台运行

struct ConfigServer
{
    unsigned short serverPort;
    unsigned short proxyPort;
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
    int serverPort, porxyPort;
    string password, logPath;
    ret = iniFile.GetIntValue(common, "server_port", &serverPort);
    if (ret != 0)
    {
        printf("config file cann't find server_port\n");
        exit(-1);
    }
    ret = iniFile.GetIntValue(common, "proxy_port", &porxyPort);
    if (ret != 0)
    {
        printf("config file cann't find proxy_port\n");
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
    g_cfg.proxyPort = porxyPort;
    g_cfg.logPath = logPath;
    //printf("pw:%s\nsp: %d\npp: %d\n", g_cfg.password.c_str(), g_cfg.serverPort, g_cfg.proxyPort);
}

void sigShutdownHandler(int sig)
{
    switch (sig)
    {
    case SIGINT:
    case SIGTERM:
        if (g_pServer != nullptr)
            delete g_pServer;
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
            if (optarg == NULL)
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
    g_logger.setAppName("xtuns");
    g_logger.info("-------------------------");
    g_logger.warn("-------------------------");
    g_logger.err("-------------------------");

    g_pServer = new Server(g_cfg.serverPort, g_cfg.proxyPort);
    if (g_pServer == nullptr)
    {
        printf("create server err\n");
        g_logger.err("create server err");
        return -1;
    }
    g_pServer->setPassword(g_cfg.password.c_str());
    g_pServer->setLogger(&g_logger);
    g_pServer->startEventLoop();

    delete g_pServer;
    return 0;
}
