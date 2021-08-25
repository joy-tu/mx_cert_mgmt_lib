#ifndef __MX_TIMED_DB__
#define __MX_TIMED_DB__

#include <parson.h>

enum
{
    DB_OK                   = 0,
    DB_CHANGED              = 1,

    /* error */
    DB_INVALID_PARAMETER    = -1,
    DB_OPEN_FAIL            = -2,
    DB_NAME_NOT_EXIST       = -3,
    DB_VALID_FAIL           = -4,
    DB_VERSION_MISMATCH     = -5,
    DB_FILE_NOT_EXIST       = -6,
};

int db_set(
    const char *file,
    const char *name,
    void *value,
    int type,
    void (*notify_change)(int type),
    int config_type);

int db_get(
    const char *file,
    const char *name,
    void *value,
    int type);

int db_copy(const char *target, const char *source);

int db_check(const char *file);

#endif
