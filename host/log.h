#include <stdio.h>
#include <time.h>
#include <string.h>

#define LOG_ON 1
#define filename(x) strrchr(x,'/')?strrchr(x,'/')+1:x

#if LOG_ON
const char *LOGFILE = "log.txt";

#define LOGOUT(p) \
{                   \
    time_t timeval; \
    timeval=time(NULL); \
    FILE *log;      \
    log = fopen(LOGFILE, "a");\
    fprintf(log, "%s   -- %s   -- %s\n", filename(__FILE__), p, ctime(&timeval));\
    fclose(log);    \
}

#define LOGCLEAR() \
{                   \
    FILE *log;      \
    log = fopen(LOGFILE,"w");\
    fclose(log);    \
}
#endif