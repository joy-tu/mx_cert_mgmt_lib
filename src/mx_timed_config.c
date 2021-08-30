/**
 * @file mx_timed_config.c
 * @brief
 * @author Ethan Tsai
 * @version
 * @date 2021-08-20
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <string.h>
#include <errno.h>

#include "mx_timed/mx_timed_intf.h"
#include "mx_timed_event.h"

static int config_fd = -1;

static void _recv_handler(int fd, int op)
{
    int data;
    int n;

    if(fd <= 0)
    {
        return;
    }

    if(op != EVENT_OP_READ)
    {
        return;
    }

    n = recv(fd, &data, sizeof(int), 0);

    if(n <= 0)
    {
        event_deregister(fd);
        close(fd);
        return;
    }

    // config change trigger
}

static void _connect_handler(int fd, int op)
{
    int rfd = 0;

    if(fd <= 0)
    {
        return;
    }

    if(op != EVENT_OP_READ)
    {
        return;
    }

    rfd = accept(fd, NULL, NULL);
    if(rfd < 0)
    {
        return;
    }

    event_register(rfd, EVENT_OP_READ, 0, _recv_handler, NULL);
}

static int _init_listener()
{
    struct sockaddr_un un = {
        .sun_family = AF_UNIX,
    };

    config_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if(config_fd < 0)
    {
        fprintf(stderr, "error in %s:%d %s\n",__func__,__LINE__,strerror(errno));
        return -1;
    }

    strcpy(un.sun_path, TIMED_SOCKET_ADDR);
    unlink(TIMED_SOCKET_ADDR);

    if(bind(config_fd, (struct sockaddr *)&un, sizeof(un)) < 0)
    {
        fprintf(stderr, "error in %s:%d %s\n",__func__,__LINE__,strerror(errno));
        close(config_fd);
        return -1;
    }

    if(listen(config_fd, 1) < 0)
    {
        fprintf(stderr, "error in %s:%d %s\n",__func__,__LINE__,strerror(errno));
        close(config_fd);
        return -1;
    }

    event_register(config_fd, EVENT_OP_READ, 0, _connect_handler, NULL);
    return 0;
}

static int _deinit_listener(void)
{
    event_deregister(config_fd);
    close(config_fd);
    return 0;
}

/**
 * @brief
 *
 * @return
 */
int timed_config_init()
{
    _init_listener();

    if(timed_intf_init() != TIMED_OK)
    {
        return -1;
    }
    return 0;
}

/**
 * @brief
 *
 * @return
 */
int timed_config_deinit()
{
    _deinit_listener();
    return 0;
}
