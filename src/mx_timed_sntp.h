#ifndef __MX_TIMED_SNTP__
#define __MX_TIMED_SNTP__

struct sntp_ctx;

int timed_sntp_stop(void);

int timed_sntp_restart(void);

int timed_sntp_config_update(int op);

#endif //__MX_TIMED_SNTP__
