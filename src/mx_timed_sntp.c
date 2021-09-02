/**
 * @file mx_timed_sntp.c
 * @brief
 * @author Ethan Tsai
 * @date 2021-09-02
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "mx_timed_event.h"
#include "mx_timed_notifier.h"

#include "mx_timed/mx_timed_intf.h"

#define OFFSET_1970_JAN_1       2208988800L

#define NTP_VER3                3
#define NTP_MODE_CLIENT         3
#define NTP_MODE_SERVER         4

#define NTP_STRATUM_UNSPECIFIED 0

#define TIMED_SNTP_DELAY_START  3 // seconds

//#define DBG_TRACE
#ifdef DBG_TRACE
#define TRACE(...) \
    { \
        printf("%s:%d ",__func__,__LINE__); \
        printf(__VA_ARGS__); \
        printf("\n"); \
    }
#else
#define TRACE(...)
#endif

enum
{
    TIMED_SNTP_IDLE = 0,
    TIMED_SNTP_START,
    TIMED_SNTP_SUCCESS,
    TIMED_SNTP_FAIL,
};

typedef struct timestamp
{
    uint32_t    sec;
    uint32_t    frac;
} timestamp_t;

struct sntp_pkt
{
    uint8_t     mode: 3;
    uint8_t     vn: 3;
    uint8_t     li: 2;
    uint8_t     stratum;
    uint8_t     poll;
    uint8_t     precision;
    uint32_t    root_delay;
    uint32_t    root_dispersion;
    uint32_t    ref_id;
    timestamp_t ref;
    timestamp_t origin;
    timestamp_t rx;
    timestamp_t tx;
} __packed;

#define SNTP_URI_MAX_LEN    128

struct sntp_ctx
{
    uint8_t dest[SNTP_URI_MAX_LEN];
    int interval;
    int timeout;
    time_t timebase;
    uint8_t enable;

    int fd;
    int timer_id;
    int state;
    int tx;
    int rx;
    int tx_fail;
    int rx_fail;
};

struct sntp_ctx gCtx =
{
    .timeout    = 5,
    .timebase   = 0,
    .enable     = 0,
    .fd         = -1,
    .timer_id   = 0,
    .state      = TIMED_SNTP_IDLE,
    .tx         = 0,
    .tx_fail    = 0,
    .rx         = 0,
    .rx_fail    = 0,
};

static void sntp_dump(struct sntp_pkt *pkt)
{
    printf("\nRecieved SNTP packet\n");
    printf("li:         %x\n", pkt->li);
    printf("vn:         %x\n", pkt->vn);
    printf("mode:       %x\n", pkt->mode);
    printf("stratum:    %x\n", pkt->stratum);
    printf("poll:       %x\n", pkt->poll);
    printf("precision:  %x\n", pkt->precision);
    printf("root delay: %x\n", ntohl(pkt->root_delay));
    printf("root disp:  %x\n", ntohl(pkt->root_dispersion));
    printf("ref id:     %x\n", ntohl(pkt->ref_id));
    printf("timestamp\n");
    printf("ref:        %x/%x\n", ntohl(pkt->ref.sec), pkt->ref.frac);
    printf("ori:        %x/%x\n", ntohl(pkt->origin.sec), pkt->origin.frac);
    printf("rx:         %x/%x\n", ntohl(pkt->rx.sec), pkt->rx.frac);
    printf("tx:         %x/%x\n", ntohl(pkt->tx.sec), pkt->tx.frac);
}

static int sntp_parse(struct sntp_pkt *pkt, time_t base, time_t *secs)
{
    uint32_t  t;

    //sntp_dump(pkt);

    if (pkt->mode != NTP_MODE_SERVER)
    {
        return -1;
    }

    if (pkt->stratum == NTP_STRATUM_UNSPECIFIED)
    {
        return -1;
    }

    if (htonl(base + OFFSET_1970_JAN_1) != pkt->origin.sec)
    {
        return -1;
    }

    t = ntohl(pkt->tx.sec);

    if (t & 0x80000000)
    {
        if (t >= OFFSET_1970_JAN_1)
        {
            t = (t - OFFSET_1970_JAN_1);
        }
        else
        {
            return -1;
        }
    }
    else
    {
        t = t + 0x100000000ULL - OFFSET_1970_JAN_1;
    }

    if (secs)
    {
        *secs = t;
    }

    return 0;
}

static int sntp_recv(int fd, time_t base, time_t *recv_time)
{
    struct sntp_pkt pkt = { 0 };
    int nbytes = 0;

    nbytes = recv(fd, &pkt, sizeof(struct sntp_pkt), 0);

    if (nbytes < 0)
    {
        fprintf(stderr, "recv() fail (%s)\n", strerror(errno));
        return -1;
    }
    else if (nbytes == 0)
    {
        // disconnect
        return -1;
    }
    else if (nbytes != sizeof(struct sntp_pkt))
    {
        return -1;
    }

    if (sntp_parse(&pkt, base, recv_time) < 0)
    {
        fprintf(stderr, "sntp_parse() fail!\n");
        return -1;
    }

    return 0;
}

static int sntp_send(int fd, time_t base)
{
    int ret = 0;
    int nbytes = 0;

    struct sntp_pkt pkt =
    {
        .li = 0,
        .vn = NTP_VER3,
        .mode = NTP_MODE_CLIENT,
        .tx.sec = htonl(base + OFFSET_1970_JAN_1),
    };

    //sntp_dump(&pkt);

    if ((nbytes = send(fd, &pkt, sizeof(struct sntp_pkt), 0)) < 0)
    {
        fprintf(stderr, "send() fail! (%s)\n", strerror(errno));
        return -1;
    }

    if (nbytes != sizeof(struct sntp_pkt))
    {
        return -1;
    }

    return 0;
}

static int sntp_connect(struct addrinfo *p)
{
    int fd;

    if ((fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) < 0)
    {
        fprintf(stderr, "socket() fail! (%s)\n", strerror(errno));
        return -1;
    }

    if (connect(fd, p->ai_addr, p->ai_addrlen) < 0)
    {
        fprintf(stderr, "connect() fail (%s)\n", strerror(errno));
        return -1;
    }

    return fd;
}

static int sntp_init(const char *dest)
{
    struct addrinfo *servinfo, *p;
    struct addrinfo hints =
    {
        .ai_family = AF_INET,
        .ai_socktype = SOCK_DGRAM,
        .ai_protocol = IPPROTO_UDP,
    };
    int fd, rv;

    rv = getaddrinfo(dest, "ntp", &hints, &servinfo);

    if (rv != 0)
    {
        fprintf(stderr, "getaddrinfo() fail %s (%s)\n", dest, gai_strerror(rv));
        return -1;
    }

    for (p = servinfo; p != NULL; p = p->ai_next)
    {
        if ((fd = sntp_connect(p)) > 0)
        {
            break;
        }
    }

    if (!p)
    {
        return -1;
    }

    return fd;
}

void _timed_sntp_timeout_handler(int fd)
{
    TRACE("fd %d", fd);

    close(fd);
    gCtx.fd = -1;
    gCtx.state = TIMED_SNTP_FAIL;
}

void _timed_sntp_recv(int fd, int op)
{
    time_t recv_time;
    int state;

    TRACE("fd %d op %d", fd, op);

    if (op != EVENT_OP_READ)
    {
        return;
    }

    if (sntp_recv(fd, gCtx.timebase, &recv_time) == 0)
    {
        TRACE("recv time %s\n", ctime(&recv_time));
        state = TIMED_SNTP_SUCCESS;
        gCtx.rx++;

        timed_intf_setlocaltime(recv_time);
    }
    else
    {
        state = TIMED_SNTP_FAIL;
        gCtx.rx_fail++;
    }

    close(fd);

    if (state != gCtx.state)
    {
        gCtx.state = state;

        /* notify */
        mx_timed_event_notify(
            (gCtx.state == TIMED_SNTP_SUCCESS) ?
            MX_TIMED_EVENT_NOTIFY_NTP_OK :
            MX_TIMED_EVENT_NOTIFY_NTP_FAIL);
        TRACE("notify");
    }

    TRACE("leave");
}

void _timed_sntp_start(int timer_id)
{
    time_t base;
    int fd;

    TRACE("timer_id %d", timer_id);

    fd = sntp_init(gCtx.dest);

    if (fd < 0)
    {
        gCtx.state = TIMED_SNTP_FAIL;
        return;
    }

    time(&base);

    if (sntp_send(fd, base) < 0)
    {
        gCtx.state = TIMED_SNTP_FAIL;
        gCtx.tx_fail++;
        return;
    }

    gCtx.tx++;

    gCtx.timebase = base;
    gCtx.fd = fd;

    event_register(fd, EVENT_OP_READ, gCtx.timeout,
                   _timed_sntp_recv,
                   _timed_sntp_timeout_handler);

    TRACE("leave");
}

/**
 * @brief
 *
 * @return
 */
int timed_sntp_stop(void)
{
    TRACE("enter");

    if (gCtx.state != TIMED_SNTP_IDLE)
    {
        event_deregister(gCtx.fd);
        close(gCtx.fd);
    }

    event_timer_deregister(gCtx.timer_id);

    gCtx.timebase = 0;
    gCtx.fd = -1;
    gCtx.timer_id = 0;
    gCtx.state = TIMED_SNTP_IDLE;
    gCtx.tx = 0;
    gCtx.rx = 0;
    gCtx.tx_fail = 0;
    gCtx.rx_fail = 0;

    TRACE("leave");
}

/**
 * @brief
 *
 * @return
 */
int timed_sntp_restart(void)
{
    int timer_id;

    TRACE("enter");

    if (gCtx.state != TIMED_SNTP_IDLE)
    {
        timed_sntp_stop();
    }

    timer_id = event_timer_register(TIMED_SNTP_DELAY_START,
                                    gCtx.interval, _timed_sntp_start);
    gCtx.timer_id = timer_id;
    gCtx.state = TIMED_SNTP_START;

    TRACE("leave");
    return 0;
}

/**
 * @brief
 *
 * @param dest
 * @param timeout
 * @param interval
 *
 * @return
 */
int timed_sntp_config_update(int mask)
{
    int restart = 0;

    TRACE("enter");

    if (mask & TIMED_CFG_SNTP_ENABLE)
    {
        int enable;

        if (timed_intf_sntp_enable_get(&enable) == TIMED_OK
                && enable != gCtx.enable)
        {
            gCtx.enable = enable;
            restart = 1;
        }
    }

    if (mask & TIMED_CFG_SNTP_SERVER)
    {
        uint8_t server[SNTP_URI_MAX_LEN] = {0};

        if (timed_intf_sntp_addr_get(server) == TIMED_OK
                && strcmp(server, gCtx.dest))
        {
            strncpy(gCtx.dest, server, strlen(server));
            restart = 1;
        }
    }

    if (mask & TIMED_CFG_SNTP_SYNC_INTERVAL)
    {
        int interval;

        if (timed_intf_sntp_sync_interval_get(&interval) == TIMED_OK
                && interval != gCtx.interval)
        {
            gCtx.interval = interval;

            if (gCtx.timer_id)
            {
                /*
                 * Update the interval and effect in the next round.
                 */
                event_timer_update(gCtx.timer_id, interval, NULL);
            }
        }
    }

    if (restart)
    {
        timed_sntp_restart();
    }

    TRACE("leave");
    return 0;
}

