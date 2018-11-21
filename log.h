#ifndef _LOG_H_
#define _LOG_H_

enum {
    _LOG_DEBUG,
    _LOG_INFO,
    _LOG_ERROR
};

void log_write_core(int level, const char *fmt, ...);
#define log_debug(f_, ...)    log_write_core(_LOG_DEBUG, (f_), ##__VA_ARGS__)
#define log_info(f_, ...)     log_write_core(_LOG_INFO, (f_), ##__VA_ARGS__)
#define log_error(f_, ...)    log_write_core(_LOG_ERROR, (f_), ##__VA_ARGS__)

int init_log(const char *name);
void close_log();

#endif