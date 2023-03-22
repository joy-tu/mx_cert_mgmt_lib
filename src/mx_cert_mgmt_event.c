#include <stdio.h>
#include <time.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
#include <mx_cert_mgmt/conf.h>
#if (USE_MX_EVENT_AGENT) /* USE_MX_EVENT_AGENT */
#include <mx_event/mx_event_list.h>
#include <mx_event/mx_event_agent.h>
#include <mx_net/mx_net.h>
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
    if (type == MX_CERT_EVENT_NOTIFY_ROOTCA_WILL_EXPIRE ||
        type == MX_CERT_EVENT_NOTIFY_ROOTCA_EXPIRE ||
        type == MX_CERT_EVENT_NOTIFY_ENDCERT_WILL_EXPIRE ||
        type == MX_CERT_EVENT_NOTIFY_ENDCERT_EXPIRE) {
        int inter, i;
        uint32_t ip;
        char active_ip[32] = {0};
        struct sockaddr_in addr_in;
        uint32_t my_ip[4];
#if USE_MX_NET        
        inter = net_max_interfaces();
        if (inter > 0) {
            for (i = 0; i < inter; i++) {
                net_get_my_ip(i, &my_ip[i]);
            }
            addr_in.sin_addr.s_addr = my_ip[0];
            strncpy(active_ip, inet_ntoa(addr_in.sin_addr), sizeof(active_ip));
        } else { /* for docker */
            if (net_get_my_ip_by_ifname("eth0", &ip) == 0) {
                /* ok */
            } else {
                /* fail */
            }
            addr_in.sin_addr.s_addr = ip;
            strncpy(active_ip, inet_ntoa(addr_in.sin_addr), sizeof(active_ip));
            printf("active_ip = %s\r\n", active_ip);
        }
        snprintf(source, sizeof(source),
             "%16s %16s",
             "Host", 
             active_ip);  
#endif             
    } else {
        if (rest_get_input_data_info(&user_info) != REST_OK) {
            printf("rest_get_input_data_info failed\n");

            return -1;
        }
        snprintf(source, sizeof(source),
             "%16s %16s",
             user_info.user_name,
             user_info.user_ip);    
    }
    

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
#endif /* USE_MX_EVENT_AGENT */
