/**
 * @file mx_timed.c
 * @brief Moxa time daemon
 * @copyright Copyright (C) MOXA Inc. All rights reserved.
 * @license This software is distributed under the terms of the MOXA License. See the file COPYING-MOXA for details.
 * @author Ethan Tsai
 * @date 2021-08-04
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "mx_timed_event.h"
#include "mx_timed_config.h"
#include "mx_timed/mx_timed_intf.h"

void timed_main(void)
{
    if (timed_config_init() != 0)
    {
        fprintf(stderr, "mx_timed init config fail!\n");
        return;
    }

    event_loop_run();

    timed_config_deinit();
    return;
}
