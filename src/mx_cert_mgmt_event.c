#include <stdio.h>
#include <time.h>

#include <mx_event/mx_event_list.h>
#include <mx_event/mx_event_agent.h>

#include "mx_cert_mgmt_event.h"
#include <rest/rest_parser.h>
int mx_cert_event_notify(int type)
{
    event_ret ret;
    event_ctx *ctx = NULL;
    char *topic;
    char *message;
#define REST_SOURCE_MAX_LEN    64

    REST_INPUT_INFO user_info = {0};
    char source[REST_SOURCE_MAX_LEN + 1] = {0};    
    
    if (type == MX_CERT_EVENT_NOTIFY_ROOTCA_WILL_EXPIRE) {
        topic = EVENT_CERT_ROOT_CA_WILL_EXPIRE ;
        message = "ROOTCA will expire";
    } else if (type == MX_CERT_EVENT_NOTIFY_ROOTCA_EXPIRE) {
        topic = EVENT_CERT_ROOT_CA_EXPIRED ;
        message = "ROOTCA expired";
    } else if (type == MX_CERT_EVENT_NOTIFY_ENDCERT_WILL_EXPIRE) {
        topic = EVENT_CERT_END_ENTITY_CERT_WILL_EXPIRE ;
        message = "Certificate will expire";
    } else if (type == MX_CERT_EVENT_NOTIFY_ENDCERT_EXPIRE) {
        topic = EVENT_CERT_END_ENTITY_CERT_EXPIRED ;
        message = "Certificate expired";
    } else if (type == MX_CERT_EVENT_NOTIFY_CERT_IMPORTED) {
        topic = EVENT_CERT_CERT_HAS_BEEN_IMPORTED ;
        message = "Certificate imported";
    } else if (type == MX_CERT_EVENT_NOTIFY_CERT_DELETED) {
        topic = EVENT_CERT_CERT_HAS_BEEN_DELETED;
        message = "Certificate deleted";
    } else if (type == MX_CERT_EVENT_NOTIFY_CERT_REGEN) {
        topic = EVENT_CERT_CERT_HAS_BEEN_REGENERATED ;
        message = "Certificate regenerated";
    } else {
        return -1;
    }
    /* create event context */
    if ((ret = event_create(&ctx, NULL, NULL)) != EVENT_OK) {
        printf("event_create failed(%d)\n", ret);
        
        return -1;
    }
    /* notify an event */
    if (rest_get_input_data_info(&user_info) != REST_OK) {
        printf("rest_get_input_data_info failed\n");

        return -1;
    }
    snprintf(source, sizeof(source),
         "%s %s",
         user_info.user_name,
         user_info.user_ip);
    event_content_notify notify_content =
    {
        .topic = topic,
        .source = source,
        .message = message,
        .timestamp = 0,
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
