/**
 * @file mx_timed_event.c
 * @brief Moxa time daemon
 * @copyright Copyright (C) MOXA Inc. All rights reserved.
 * @license This software is distributed under the terms of the MOXA License.
 * See the file COPYING-MOXA for details.
 * @author Ethan Tsai
 * @date 2021-08-04
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <sys/select.h>

#include "mx_timed_list.h"
#include "mx_timed_event.h"

#define MIN(_x, _y) (_x > _y) ? (_y) : (_x)
#define MAX(_x, _y) (_x > _y) ? (_x) : (_y)

LIST_HEAD(event_list);

LIST_HEAD(timer_list);

struct event_timer_node
{
    time_t  timeout;
    time_t  interval;
    void (*timeout_handler)(int);
    int     timer_id;

    struct list_head list;
};

struct event_node
{
    time_t  timeout;
    void (*timeout_handler)(int);
    int     fd;
    void (*callback)(int, int);
    uint16_t op;

    struct list_head list;
};

#define EVENT_ENTRY(_e) \
    list_entry(_e, struct event_node, list)

#define EVENT_TIMER_ENTRY(_e) \
    list_entry(_e, struct event_timer_node, list)

/**
 * @brief Alloc a event node
 *
 * @return
 */
static inline struct event_node *_event_node_alloc()
{
    return (struct event_node *)calloc(1, sizeof(struct event_node));
}

/**
 * @brief Free event node
 *
 * @param node
 */
static inline void _event_node_free(struct event_node *node)
{
    return free(node);
}

/**
 * @brief Alloc a event timer node
 *
 * @return
 */
static inline struct event_timer_node *_event_timer_node_alloc()
{
    return (struct event_timer_node *)calloc(1, sizeof(struct event_timer_node));
}

/**
 * @brief Free event timer node
 *
 * @param node
 */
static inline void _event_timer_node_free(struct event_timer_node *node)
{
    return free(node);
}

/**
 * @brief Callback function for searching event by fd
 *
 * @param pos
 * @param param
 *
 * @return
 */
static int _search_event_by_fd(struct list_head *pos, void *param)
{
    struct event_node *event = NULL;

    event = list_entry(pos, struct event_node, list);

    if (event->fd == *(int *)param)
    {
        return 1;
    }

    return 0;
}

/**
 * @brief Callback function for searching timer by timer id
 *
 * @param pos
 * @param param
 *
 * @return
 */
static int _search_timer_by_id(struct list_head *pos, void *param)
{
    struct event_timer_node *timer = NULL;

    timer = list_entry(pos, struct event_timer_node, list);

    if (timer->timer_id == *(int *)param)
    {
        return 1;
    }

    return 0;
}

/**
 * @brief Register an event to event service
 *
 * @param fd
 * @param op
 * @param timeout
 * @param callback
 * @param timeout_handler
 *
 * @return
 */
int event_register(
    int fd, uint8_t op, time_t timeout,
    void (*callback)(int, int),
    void (*timeout_handler)(int)
)
{
    struct event_node *event = _event_node_alloc();

    if (!event)
    {
        return -1;
    }

    event->fd = fd;

    if (timeout)
    {
        event->timeout = timeout + time(NULL);
    }
    else
    {
        event->timeout = 0;
    }

    event->callback = callback;
    event->timeout_handler = timeout_handler;
    event->op = op;

    list_push(&event->list, &event_list);
    return 0;
}

/**
 * @brief Deregister event by fd
 *
 * @param fd
 *
 * @return
 */
int event_deregister(int fd)
{
    struct event_node *event = NULL;
    struct list_head *list = NULL;

    list = list_search(&event_list, (void *)&fd, _search_event_by_fd);

    if (!list)
    {
        return -1;
    }

    list_del(list);

    event = list_entry(list, struct event_node, list);

    event->fd = -1;
    event->timeout = 0;
    event->callback = NULL;
    event->timeout_handler = NULL;
    event->op = 0;

    _event_node_free(event);
    return 0;
}

/**
 * @brief Generate unique timer id
 *
 * @return
 */
static int _timer_id_generate()
{
    // TODO
    static int id = 0;
    return ++id;
}

/**
 * @brief Register a timer
 *
 * @param initial: timeout (secs)
 * @param interval: repeat interval
 * @param timeout_handler
 *
 * @return
 */
int event_timer_register(
    time_t initial, time_t interval,
    void (*timeout_handler)(int)
)
{
    struct event_timer_node *timer = _event_timer_node_alloc();
    int id = _timer_id_generate();

    if (!timer)
    {
        return -1;
    }

    timer->timeout = initial + time(NULL);
    timer->interval = interval;
    timer->timeout_handler = timeout_handler;
    timer->timer_id = id;

    list_push(&timer->list, &timer_list);
    return id;
}

/**
 * @brief
 *
 * @param interval
 * @param timeout_handler
 *
 * @return
 */
int event_timer_update(
    int timer_id,
    time_t interval,
    void (*timeout_handler)(int)
)
{
    struct event_timer_node *timer = NULL;
    struct list_head *list = NULL;

    list = list_search(&timer_list, (void *)&timer_id, _search_timer_by_id);

    if (!list)
    {
        return -1;
    }

    timer = list_entry(list, struct event_timer_node, list);

    if (interval)
    {
        timer->interval = interval;
    }

    if (timeout_handler)
    {
        timer->timeout_handler = timeout_handler;
    }
}

/**
 * @brief Deregister a timer from timer list
 *
 * @param timer_id
 *
 * @return
 */
int event_timer_deregister(int timer_id)
{
    struct event_timer_node *timer = NULL;
    struct list_head *list = NULL;

    list = list_search(&timer_list, (void *)&timer_id, _search_timer_by_id);

    if (!list)
    {
        return -1;
    }

    list_del(list);

    timer = list_entry(list, struct event_timer_node, list);

    timer->timeout_handler = NULL;
    timer->timer_id = 0;

    _event_timer_node_free(timer);
    return 0;
}

/**
 * @brief Restart to poll event
 *
 * @return
 */
static int _event_reset(
    fd_set *read_fds, fd_set *write_fds, fd_set *except_fds,
    struct timeval *tv, int *nfds)
{
    struct list_head *pos = NULL;
    struct list_head *next = NULL;

    time_t next_timeout = 0x7FFFFFFF;

    /* reset fds */
    FD_ZERO(read_fds);
    FD_ZERO(write_fds);
    FD_ZERO(except_fds);

    /* update fds */
    list_for_each_safe(pos, next, &event_list)
    {
        struct event_node *event = EVENT_ENTRY(pos);

        if (event->op & EVENT_OP_READ)
        {
            FD_SET(event->fd, read_fds);
        }

        if (event->op & EVENT_OP_WRITE)
        {
            FD_SET(event->fd, write_fds);
        }

        if (event->op & EVENT_OP_EXCEPT)
        {
            FD_SET(event->fd, except_fds);
        }

        *nfds = MAX(*nfds, event->fd);

        if (event->timeout)
        {
            next_timeout = MIN(next_timeout, event->timeout);
        }
    }

    list_for_each_safe(pos, next, &timer_list)
    {
        struct event_timer_node *timer = EVENT_TIMER_ENTRY(pos);
        next_timeout = MIN(next_timeout, timer->timeout);
    }

    /* update next timeout */
    if (next_timeout)
    {
        tv->tv_sec = (next_timeout - time(NULL));
        tv->tv_usec = 0;
    }

    return 0;
}

/**
 * @brief Handle event timeout
 *
 * @return
 */
static int _event_timeout_handler()
{
    struct list_head *pos = NULL;
    struct list_head *next = NULL;
    time_t now = time(NULL);

    /* check timer list */
    list_for_each_safe(pos, next, &timer_list)
    {
        struct event_timer_node *timer = EVENT_TIMER_ENTRY(pos);

        if (timer->timeout <= now
                && timer->timeout_handler)
        {
            timer->timeout_handler(timer->timer_id);

            if (timer->interval)
            {
                timer->timeout = (now + timer->interval);
            }
            else
            {
                event_timer_deregister(timer->timer_id);
            }
        }
    }

    /* check event list */
    list_for_each_safe(pos, next, &event_list)
    {
        struct event_node *event = EVENT_ENTRY(pos);

        if (event->timeout <= now
                && event->timeout_handler)
        {
            event->timeout_handler(event->fd);

            if ((event->op & EVENT_OP_ALWAYS) == 0)
            {
                event_deregister(event->fd);
            }
        }
    }

    return 0;
}

/**
 * @brief Handle event read/write
 *
 * @return
 */
static int _event_handler(
    fd_set *read_fds, fd_set *write_fds, fd_set *except_fds)
{
    struct event_node *event = NULL;
    struct list_head *pos = NULL;
    struct list_head *next = NULL;

    list_for_each_safe(pos, next, &event_list)
    {
        int op = 0;
        event = EVENT_ENTRY(pos);

        if (!event->callback)
        {
            event_deregister(event->fd);
            continue;
        }

        if (FD_ISSET(event->fd, read_fds)
                && (event->op & EVENT_OP_READ))
        {
            op |= EVENT_OP_READ;
        }

        if (FD_ISSET(event->fd, write_fds)
                && (event->op & EVENT_OP_WRITE))
        {
            op |= EVENT_OP_WRITE;
        }

        if (FD_ISSET(event->fd, except_fds)
                && (event->op & EVENT_OP_EXCEPT))
        {
            op |= EVENT_OP_EXCEPT;
        }

        event->callback(event->fd, op);

        if (!(event->op & EVENT_OP_ALWAYS))
        {
            event_deregister(event->fd);
        }
    }

    return 0;
}

/**
 * @brief event loop service
 */
void event_loop_run(void)
{
    fd_set readfds;
    fd_set writefds;
    fd_set exceptfds;
    struct timeval timeout;
    struct timeval *pTimeout;

    int nfds = 0;
    int rv = 0;

    while (1)
    {
        _event_reset(&readfds, &writefds, &exceptfds, &timeout, &nfds);

        pTimeout = (timeout.tv_sec) ? &timeout : NULL;

        rv = select(nfds + 1, &readfds, &writefds, &exceptfds, pTimeout);

        _event_timeout_handler();

        if (rv <= 0)
        {
            continue;
        }

        _event_handler(&readfds, &writefds, &exceptfds);
    }
}
