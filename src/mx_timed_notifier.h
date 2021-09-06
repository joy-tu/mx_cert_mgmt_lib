#ifndef __MX_EVENT_AGENT__
#define __MX_EVENT_AGENT__


enum
{
    MX_TIMED_EVENT_NOTIFY_NTP_OK = 0,
    MX_TIMED_EVENT_NOTIFY_NTP_FAIL,
};

int mx_timed_event_notify(int type);

#endif //__MX_EVENT_AGENT__
