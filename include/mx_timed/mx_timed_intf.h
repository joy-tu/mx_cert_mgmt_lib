#ifndef __MX_TIMED_INTF__
#define __MX_TIMED_INTF__

#include <def/mx_def.h>

#define TIMED_SOCKET_ADDR           SYSTEM_TEMP_FILES_PATH"/mx-timed.sock"

enum
{
    TIMED_OK                        = 0,
    TIMED_INVALID_PARAM             = -1,
    TIMED_UNAVAILABLE               = -2,
    TIMED_CONFIG_PARSE_FAIL         = -3,
    TIMED_CONFIG_SET_FAIL           = -4,
    TIMED_CONFIG_GET_FAIL           = -5,
    TIMED_SET_TIME_FAIL             = -6,
    TIMED_GET_TIME_FAIL             = -7,
    TIMED_CONFIGDB_INIT_FAIL        = -8,
    TIMED_UNKNOWN_ERROR             = -10,

};

enum
{
    TIMED_CFG_SNTP_ENABLE           = 0x0001,
    TIMED_CFG_SNTP_SERVER           = 0x0002,
    TIMED_CFG_SNTP_SYNC_INTERVAL    = 0x0004,
};

#define TIMED_CFG_SNTP_ALL \
    (TIMED_CFG_SNTP_ENABLE | TIMED_CFG_SNTP_SERVER | TIMED_CFG_SNTP_SYNC_INTERVAL)

enum
{
    TIMED_SNTP_DISABLED             = 0,
    TIMED_SNTP_ENABLED              = 1,
    TIMED_SNTP_DEFAULT              = TIMED_SNTP_DISABLED,
};

enum
{
    TIMED_SNTP_MIN_SYNC_INTVAL      = 1,
    TIMED_SNTP_MAX_SYNC_INTVAL      = 43200,
    TIMED_SNTP_DEFAULT_SYNC_INTVAL  = 1440,
};

typedef struct _dst
{
    int month;
    int week;
    int day;
    int hour;
} dst_t;

int timed_intf_init(void);

int timed_intf_sntp_enable_set(int enable);

int timed_intf_sntp_enable_get(int *enable);

int timed_intf_sntp_addr_set(const char *url);

int timed_intf_sntp_addr_get(char *url);

int timed_intf_sntp_sync_interval_set(int interval);

int timed_intf_sntp_sync_interval_get(int *interval);

int timed_intf_timezone_get(int *index, char *zonename, int name_len);

int timed_intf_timezone_set(int index);

int timed_intf_dst_get(int *offset, dst_t *start, dst_t *end);

int timed_intf_dst_set(int offset, dst_t *start, dst_t *end);

int timed_intf_getlocaltime(time_t *tm);

int timed_intf_setlocaltime(time_t sec);

#endif // __MX_TIMED_INTF__
