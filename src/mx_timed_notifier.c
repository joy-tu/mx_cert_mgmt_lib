#include <stdio.h>
#include <time.h>

#include <mx_event/mx_event_list.h>
#include <mx_event/mx_event_agent.h>

#include "mx_timed_notifier.h"

int mx_timed_event_notify(int type)
{
    event_ret ret;
    event_ctx *ctx = NULL;
    char *topic;

    if (type == MX_TIMED_EVENT_NOTIFY_NTP_OK)
    {
        topic = EVENT_SYSTEM_NTP_CONNECT_SUCCESS;
    }
    else if (type == MX_TIMED_EVENT_NOTIFY_NTP_FAIL)
    {
        topic = EVENT_SYSTEM_NTP_UPDATE_FAIL;
    }
    else
    {
        return -1;
    }

    /* create event context */
    if ((ret = event_create(&ctx, NULL, NULL)) != EVENT_OK)
    {
        printf("event_create failed(%d)\n", ret);
        return -1;
    }

    /* notify an event */
    event_content_notify notify_content =
    {
        .topic = topic,
        .timestamp = time(NULL),
    };

    if ((ret = event_notify(ctx, &notify_content)) != EVENT_OK)
    {
        printf("event_notify failed(%d)\n", ret);
        event_destroy(ctx);
        return -1;
    }

    event_destroy(ctx);
    return 0;
}
