#ifndef __MX_TIMED_EVENT__
#define  __MX_TIMED_EVENT__

#include <stdint.h>

enum
{
    EVENT_OP_READ   = 0x01,
    EVENT_OP_WRITE  = 0x02,
    EVENT_OP_EXCEPT = 0x04,
    EVENT_OP_ALWAYS = 0x80,
};

int event_register(
    int fd, uint8_t op, time_t timeout,
    void (*callback)(int, int),
    void (*timeout_handler)(int));

int event_deregister(int fd);

int event_timer_register(
    time_t initial, time_t interval,
    void (*timeout_handler)(int));

int event_timer_update(
    int timer_id, time_t interval,
    void (*timeout_handler)(int));

int event_timer_deregister(int timer_id);

void event_loop_run(void);

#endif //__MX_TIMED_EVENT__
