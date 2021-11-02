#include <stdio.h>
#include <time.h>

#include <mx_event/mx_event_list.h>
#include <mx_event/mx_event_agent.h>

#include "mx_cert_mgmt_event.h"

int mx_cert_event_notify(int type)
{
    event_ret ret;
    event_ctx *ctx = NULL;
    char *topic;

    if (type == MX_CERT_EVENT_NOTIFY_ROOTCA_WILL_EXPIRE) {
        topic = EVENT_CERT_ROOT_CA_WILL_EXPIRE ;
    } else if (type == MX_CERT_EVENT_NOTIFY_ROOTCA_EXPIRE) {
        topic = EVENT_CERT_ROOT_CA_EXPIRED ;
    } else if (type == MX_CERT_EVENT_NOTIFY_ENDCERT_WILL_EXPIRE) {
        topic = EVENT_CERT_END_ENTITY_CERT_WILL_EXPIRE ;
    } else if (type == MX_CERT_EVENT_NOTIFY_ENDCERT_EXPIRE) {
        topic = EVENT_CERT_END_ENTITY_CERT_EXPIRED ;
    } else if (type == MX_CERT_EVENT_NOTIFY_CERT_IMPORTED) {
        topic = EVENT_CERT_CERT_HAS_BEEN_IMPORTED ;
    } else if (type == MX_CERT_EVENT_NOTIFY_CERT_DELETED) {
        topic = EVENT_CERT_CERT_HAS_BEEN_DELETED ;
    } else if (type == MX_CERT_EVENT_NOTIFY_CERT_REGEN) {
        topic = EVENT_CERT_CERT_HAS_BEEN_REGENERATED ;
    } else {
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
        .source = "127.0.0.1",
        .message = "MX-CERT message",
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
