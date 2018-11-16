#include <errno.h>

#define NO_TEMP_FAILURE(stmt)                     \
    while ((stmt) == -1 && errno == EINTR); // loop when interrupted by signal
