/**
 * @file mx_timed_intf.c
 * @brief
 * @author Ethan Tsai
 * @date 2021-08-25
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <dirent.h>

#include <def/mx_def.h>
#include <mx_timed/mx_timed_intf.h>
#include <mx_timed/timezone.h>

#include "mx_timed_db.h"

#define TIMED_DEFCONFIG_DIR SYSTEM_DEFAULT_CONFIG_PATH"/timed"
#define TIMED_CONFIG_DIR    SYSTEM_CONFIG_PATH"/timed"
#define TIMED_RUNCONFIG_DIR SYSTEM_TEMP_CONFIG_PATH"/timed"

#define TIMED_DEFCONFIG     TIMED_DEFCONFIG_DIR"/defconfig.json"
#define TIMED_CONFIG        TIMED_CONFIG_DIR"/config.json"
#define TIMED_RUNCONFIG     TIMED_RUNCONFIG_DIR"/config.json"

/*  config.json
 *  {
 *      "timezone": 0,              // timezone: 0-63 (index)
 *      "dst":
 *      {
 *          "offset": 0,            // 0-12
 *          "startDate": "M10.1.0/2", // Mm.w.d/h, month, week, day, hour, N/A
 *          "endDate": "M10.1.0/2",   // Mm.w.d/h, month, week, day, hour, N/A
 *      },
 *      "sntp":
 *      {
 *          "admin": 0,             // 1: enable, 0: disable
 *          "server": "192.168.1.1",// ip/url
 *          "interval": 1440        // number
 *      },
 *      "revision": "",
 *      "checksum": ""
 *  }
 */

/**
 * @brief
 *
 * @param dirname
 *
 * @return
 */
static int _mkdir_p(const char *dirname)
{
    DIR *dir = opendir(dirname);
    int status;

    if (dir == 0)
    {
        closedir(dir);
        return 0;
    }

    if (errno != ENOENT)
    {
        return -1;
    }

    status = mkdir(dirname, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);

    if (status != 0)
    {
        fprintf(stderr, "mkdir(%s) fail! (%s)\n", dirname, strerror(errno));
        return -1;
    }

    return 0;
}

/**
 * @brief
 *
 * @return
 */
static int _config_init(void)
{
    int rv = 0;

    if (_mkdir_p(TIMED_CONFIG_DIR) != 0
            || _mkdir_p(TIMED_RUNCONFIG_DIR) != 0)
    {
        fprintf(stderr, "Confif DIR init fail\n");
        return -1;
    }

    if (db_check(TIMED_CONFIG) != DB_OK
            && db_copy(TIMED_CONFIG, TIMED_DEFCONFIG) != DB_OK)
    {
        fprintf(stderr, "Init DB fail!\n");
        return -1;
    }

    // copy to ramdisk
    if (db_copy(TIMED_RUNCONFIG, TIMED_CONFIG) != DB_OK)
    {
        fprintf(stderr, "Copy DB fail!\n");
        return -1;
    }

    return 0;
}

/**
 * @brief
 */
static void _config_save(void)
{
    if (db_copy(TIMED_CONFIG".tmp", TIMED_RUNCONFIG) != JSONSuccess)
    {
        fprintf(stderr, "Copy running config to %s fail!\n", TIMED_CONFIG".tmp");
        return;
    }

    if (rename(TIMED_CONFIG".tmp", TIMED_CONFIG) != 0)
    {
        fprintf(stderr, "rename() fail! (%s)\n", strerror(errno));
        return;
    }

    _config_init(); // TODO: reinit
}

/**
 * @brief Notify time daemon which config is changed via socket
 *
 * @param type
 */
static void _config_change_nofity(int type)
{
    int fd;
    int size;

    struct sockaddr_un un =
    {
        .sun_family = AF_UNIX,
    };

    _config_save();

    fd = socket(AF_UNIX, SOCK_STREAM, 0);

    if (fd < 0)
    {
        fprintf(stderr, "socket() fail! (%s)\n", strerror(errno));
        return;
    }

    strcpy(un.sun_path, TIMED_SOCKET_ADDR);

    if (connect(fd, (struct sockaddr *)&un, sizeof(un)) < 0)
    {
        fprintf(stderr, "connect() fail! (%s)\n", strerror(errno));
        goto error;
    }

    send(fd, &type, sizeof(int), 0);
error:
    close(fd);
    return;
}

/**
 * @brief
 *
 * @param enable
 *
 * @return
 */
static int _valid_sntp_enable(int enable)
{
    return (enable == TIMED_SNTP_DISABLED
            || enable == TIMED_SNTP_ENABLED) ? 1 : 0;
}

/**
 * @brief
 *
 * @param addr
 *
 * @return
 */
static int _valid_sntp_addr(const char *addr)
{
    // TODO
    return 1;
}

/**
 * @brief
 *
 * @param interval
 *
 * @return
 */
static int _valid_sntp_sync_interval(int interval)
{
    return (interval >= TIMED_SNTP_MIN_SYNC_INTVAL
            && interval <= TIMED_SNTP_MAX_SYNC_INTVAL) ? 1 : 0;
}

/**
 * @brief
 *
 * @param d
 *
 * @return
 */
static int _valid_daylight_time(dst_t *d)
{
    return (d->month >= 1 && d->month <= 12
            && d->week >= 1 && d->week <= 5
            && d->day >= 0 && d->day <= 6
            && d->hour >= 0 && d->hour >= 24) ? 1 : 0;
}

/**
 * @brief
 *
 * @param dst
 * @param buf
 * @param len
 *
 * @return
 */
static int _dst_to_str(dst_t *dst, char *buf, size_t len)
{
    memset(buf, 0x0, len);
    snprintf(buf, len, "M%d.%d.%d/%d",
             dst->month,
             dst->week,
             dst->day,
             dst->hour);
    return 0;
}

/**
 * @brief
 *
 * @return
 */
static int _tz_update()
{
    char str_buf[256] = {0};
    char start_str[64] = {0};
    char end_str[64] = {0};
    int tz_index = 0;
    int offset = 0;

    if (db_get(TIMED_RUNCONFIG,
               "timezone", &tz_index, JSONNumber) != DB_OK)
    {
        return TIMED_CONFIG_GET_FAIL;
    }

    if (db_get(TIMED_RUNCONFIG,
               "dst.offset", &offset, JSONNumber) != DB_OK)
    {
        return TIMED_CONFIG_GET_FAIL;
    }

    if (offset == 0)
    {
        snprintf(str_buf, sizeof(str_buf),
                 "GMT%d",
                 timezone_table[tz_index].posix_offset);
    }
    else
    {
        if (db_get(TIMED_RUNCONFIG, "dst.startDate",
                   start_str, JSONString) != DB_OK)
        {
            return TIMED_CONFIG_SET_FAIL;
        }

        if (db_get(TIMED_RUNCONFIG, "dst.endDate",
                   end_str, JSONString) != DB_OK)
        {
            return TIMED_CONFIG_SET_FAIL;
        }

        snprintf(str_buf, sizeof(str_buf), "GMT%dBST%d,%s-%s",
                 timezone_table[tz_index].posix_offset,
                 (timezone_table[tz_index].posix_offset - offset),
                 start_str, end_str);
    }

    setenv("TZ", str_buf, 1);
    return TIMED_OK;
}

/**
 * @brief
 *
 * @param enable
 *
 * @return
 */
int timed_intf_sntp_enable_set(int enable)
{
    if (!_valid_sntp_enable(enable))
    {
        return TIMED_INVALID_PARAM;
    }

    if (db_set(TIMED_RUNCONFIG, "sntp.admin",
               &enable, JSONNumber,
               _config_change_nofity, TIMED_CFG_SNTP_ENABLE) != DB_OK)
    {
        return TIMED_CONFIG_SET_FAIL;
    }

    return TIMED_OK;
}

/**
 * @brief
 *
 * @param enable
 *
 * @return
 */
int timed_intf_sntp_enable_get(int *enable)
{
    if (!enable)
    {
        return TIMED_INVALID_PARAM;
    }

    if (db_get(TIMED_RUNCONFIG, "sntp.admin", enable, JSONNumber) != DB_OK)
    {
        return TIMED_CONFIG_GET_FAIL;
    }

    return TIMED_OK;
}

/**
 * @brief
 *
 * @param enable
 *
 * @return
 */
int timed_intf_sntp_addr_set(const char *target)
{
    if (!target || !_valid_sntp_addr(target))
    {
        return TIMED_INVALID_PARAM;
    }

    if (db_set(TIMED_RUNCONFIG, "sntp.server",
               (void *)target, JSONString,
               _config_change_nofity, TIMED_CFG_SNTP_SERVER) != DB_OK)
    {
        return TIMED_CONFIG_SET_FAIL;
    }

    return TIMED_OK;
}

/**
 * @brief
 *
 * @param enable
 *
 * @return
 */
int timed_intf_sntp_addr_get(char *target)
{
    if (!target)
    {
        return TIMED_INVALID_PARAM;
    }

    if (db_get(TIMED_RUNCONFIG, "sntp.server",
               target, JSONString) != DB_OK)
    {
        return TIMED_CONFIG_GET_FAIL;
    }

    return TIMED_OK;
}

/**
 * @brief
 *
 * @param interval
 *
 * @return
 */
int timed_intf_sntp_sync_interval_set(int interval)
{
    if (!_valid_sntp_sync_interval(interval))
    {
        return TIMED_INVALID_PARAM;
    }

    if (db_set(TIMED_RUNCONFIG, "sntp.interval",
               &interval, JSONNumber,
               _config_change_nofity, TIMED_CFG_SNTP_SYNC_INTERVAL) != DB_OK)
    {
        return TIMED_CONFIG_SET_FAIL;
    }

    return TIMED_OK;
}

/**
 * @brief
 *
 * @param interval
 *
 * @return
 */
int timed_intf_sntp_sync_interval_get(int *interval)
{
    if (!interval)
    {
        return TIMED_INVALID_PARAM;
    }

    if (db_get(TIMED_RUNCONFIG,
               "sntp.interval", interval, JSONNumber) != DB_OK)
    {
        return TIMED_CONFIG_GET_FAIL;
    }

    return TIMED_OK;
}

/**
 * @brief
 *
 * @param index
 * @param zonename
 *
 * @return
 */
int timed_intf_timezone_get(int *index, char *zonename, int name_len)
{
    if (!index)
    {
        return TIMED_INVALID_PARAM;
    }

    if (db_get(TIMED_RUNCONFIG,
               "timezone", index, JSONNumber) != DB_OK)
    {
        return TIMED_CONFIG_GET_FAIL;
    }

    if (zonename)
    {
        strncpy(zonename, ZONE_NAME(*index), name_len);
    }

    return TIMED_OK;
}


/**
 * @brief
 *
 * @param index
 *
 * @return
 */
int timed_intf_timezone_set(int index)
{
    if (index < 0 || index > TIMEZONE_MAX_ENTRIES)
    {
        return TIMED_INVALID_PARAM;
    }

    if (db_set(TIMED_RUNCONFIG, "timezone",
               &index, JSONNumber, NULL, -1) != DB_OK)
    {
        return TIMED_CONFIG_SET_FAIL;
    }

    return TIMED_OK;
}

/**
 * @brief
 *
 * @param offset
 * @param start
 * @param end
 *
 * @return
 */
int timed_intf_dst_get(int *offset, dst_t *start, dst_t *end)
{
    char str_buf[64] = {0};

    if (!offset || !start || !end)
    {
        return TIMED_INVALID_PARAM;
    }

    if (db_get(TIMED_RUNCONFIG,
               "dst.offset", offset, JSONNumber) != DB_OK)
    {
        return TIMED_CONFIG_GET_FAIL;
    }

    if (db_get(TIMED_RUNCONFIG,
               "dst.startDate", str_buf, JSONString) != DB_OK)
    {
        return TIMED_CONFIG_GET_FAIL;
    }

    sscanf(str_buf, "M%d.%d.%d/%d",
           &start->month,
           &start->week,
           &start->day,
           &start->hour);

    memset(str_buf, 0x0, sizeof(str_buf));

    if (db_get(TIMED_RUNCONFIG,
               "dst.endDate", str_buf, JSONString) != DB_OK)
    {
        return TIMED_CONFIG_GET_FAIL;
    }

    sscanf(str_buf, "M%d.%d.%d/%d",
           &end->month,
           &end->week,
           &end->day,
           &end->hour);

    return TIMED_OK;
}

/**
 * @brief
 *
 * @param offset
 * @param start
 * @param end
 *
 * @return
 */
int timed_intf_dst_set(int offset, dst_t *start, dst_t *end)
{
    char str_buf[64] = {0};

    if (offset < 0 || offset > 24
            || !(_valid_daylight_time(start))
            || !(_valid_daylight_time(end)))
    {
        return TIMED_INVALID_PARAM;
    }

    if (db_set(TIMED_RUNCONFIG, "dst.offset",
               &offset, JSONNumber, NULL, -1) != DB_OK)
    {
        return TIMED_CONFIG_SET_FAIL;
    }

    _dst_to_str(start, str_buf, sizeof(str_buf));

    if (db_set(TIMED_RUNCONFIG, "dst.startDate",
               str_buf, JSONString, NULL, -1) != DB_OK)
    {
        return TIMED_CONFIG_SET_FAIL;
    }

    _dst_to_str(end, str_buf, sizeof(str_buf));

    if (db_set(TIMED_RUNCONFIG, "dst.endDate",
               str_buf, JSONString, NULL, -1) != DB_OK)
    {
        return TIMED_CONFIG_SET_FAIL;
    }

    return TIMED_OK;
}

/**
 * @brief
 *
 * @param tm
 *
 * @return
 */
int timed_intf_getlocaltime(time_t *tm)
{
    struct timespec spec;

    if (!tm)
    {
        return TIMED_INVALID_PARAM;
    }

    _tz_update();

    if (clock_gettime(CLOCK_REALTIME, &spec) < 0)
    {
        return TIMED_GET_TIME_FAIL;
    }

    *tm = spec.tv_sec;
    return TIMED_OK;
}

/**
 * @brief
 *
 * @param sec
 *
 * @return
 */
int timed_intf_setlocaltime(time_t sec)
{
    struct timespec spec;

    spec.tv_sec = sec;

    if (clock_settime(CLOCK_REALTIME, &spec) < 0)
    {
        return TIMED_SET_TIME_FAIL;
    }

    return TIMED_OK;
}

/**
 * @brief
 *
 * @return
 */
int timed_intf_init(void)
{
    if (_config_init() < 0)
    {
        return TIMED_CONFIGDB_INIT_FAIL;
    }

    return TIMED_OK;
}

