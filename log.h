#ifndef _LOG_H_
#define _LOG_H_

enum {
    _LOG_DEBUG,
    _LOG_INFO,
    _LOG_ERROR
};

void log_write_core(int level, const char *fmt, ...);
#define log_debug(x)    log_write_core(_LOG_DEBUG, x)
#define log_info(x)     log_write_core(_LOG_INFO, x)
#define log_error(x)    log_write_core(_LOG_ERROR, x)

int init_log(const char *name);
void close_log();

#endif