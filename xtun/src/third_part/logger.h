#ifndef LOGGER_H
#define LOGGER_H

#include <stdio.h>
#include <stdarg.h>
#include <sys/timeb.h>
#include <time.h>
#include <fstream>
#include <string>
#include <mutex>

#define MAX_LOG_BUFF_SZIE 1024

//日志名称前缀 name_YYYYMMDD.log
#define INFO_LOG_NAME_PREFIFX "info"
#define WARN_LOG_NAME_PREFIFX "warn"
#define ERR_LOG_NAME_PREFIFX "err"

class Logger
{
  public:
    enum LogType
    {
        INFO,
        WARN,
        ERR
    };

  public:
    Logger();
    Logger(const char *logPath);
    ~Logger();
    void info(const char *format, ...);
    void warn(const char *format, ...);
    void err(const char *format, ...);
    void curDateTimeStr(std::string &dateStr, std::string &timeStr);
    void setLogPath(const char *logPath);
    void setAppName(const char *appName);

  private:
    std::ofstream m_osInfo;
    std::ofstream m_osWarn;
    std::ofstream m_osErr;
    std::string m_logPath;
    std::mutex m_mutex; //支持多线程
    std::string m_appName;

  private:
    void logImp(const char *prifix, const char *logBuff, std::ofstream &os);
    void checkDateAndInitOS(const std::string &curDate, const char *logName, std::ofstream &os);
    void closeAllOS();
};

#endif // LOGGER_H
