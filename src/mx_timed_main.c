/**
 * @file mx_timed_main.c
 * @brief Moxa time daemon application
 * @copyright Copyright (C) MOXA Inc. All rights reserved.
 * @license This software is distributed under the terms of the MOXA License. See the file COPYING-MOXA for details.
 * @author Ethan Tsai
 * @date 2021-08-04
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <sysexits.h>

#include "mx_timed.h"

static const char *optstring = "vh";

static struct option opts[] =
{
    { "version",    0, NULL, 'v'},
    { "help",       0, NULL, 'h'},
    { NULL,         0, NULL, 0},
};

static void _printf_version(void)
{
    fprintf(stdout, "Moxa Time Daemon Version %s\n", MX_TIMED_VERSION);
}

static void _printf_help(void)
{
    fprintf(stdout,
            "Usage: mx-timed [option]\n"
            "Usage: mx-timed \n"
            "\n"
            "Options:\n"
            "      --version            display version information and exit\n"
            "      --help               display this help and exit\n"
           );

}

/**
 * @brief
 *
 * @param argc
 * @param argv[]
 *
 * @return
 */
int main(int argc, char *argv[])
{
    int c = 0;

    while ((c = getopt_long(argc, argv, optstring, opts, NULL)) != -1)
    {
        switch (c)
        {
        case 'v':
            _printf_version();
            return EX_OK;

        case 'h':
            _printf_help();
            return EX_OK;

        default:
            return EXIT_FAILURE;
        }
    }

    /* run main */
    timed_main();

    return EX_OK;
}
