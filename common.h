#include <errno.h>

#define NO_TEMP_FAILURE(stmt)                     \
    while ((stmt) == -1 && errno == EINTR); // loop when interrupted by signal

#define SERVER_VERSION "liso/1.0"