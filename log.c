/*
 * This logging module is NOT thread-safe!
 */

#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdarg.h>
#include "log.h"
#include "lisod.h"

#define LOG_BUF_SIZE 512

static FILE *log_file = NULL;

static int setup_log(const char *name)
{
    if (log_file) {
        fclose(log_file);
    }

    log_file = fopen(name, "a");
    if (!log_file) {
        perror("Fail to open log file");
        return -1;
    }
    return 0;
}


int init_log(const char *name)
{
    return setup_log(name);
}


void close_log()
{
    if (log_file) {
        fclose(log_file);
    }
}

void log_write_core(int level, const char *fmt, ...)
{
    int length = 0;
    struct tm *stm;
    char *label;
    va_list args;
    static char log_buf[LOG_BUF_SIZE];

    // time
    time_t now = time(0);
    stm = gmtime(&now);
    length += strftime(log_buf, LOG_BUF_SIZE, "%a, %d %b %Y %H:%M:%S %Z", stm);

    // label
    switch (level) {
        case _LOG_DEBUG:
            label = " [DEBUG]:";
            break;
        case _LOG_INFO:
            label = " [INFO]:";
            break;
        case _LOG_ERROR:
            label = " [ERROR]:";
            break;
        default: // no way you can get here
            break;
    }
    strcat(log_buf, label);
    length += strlen(label);

    // append string
    va_start(args, fmt);
    length += vsnprintf(log_buf + length, LOG_BUF_SIZE - length - 2, fmt, args);
    va_end(args);

    strcat(log_buf, "\n");
    length++;

    fwrite(log_buf, sizeof(char), length, log_file);
    fflush(log_file);
}