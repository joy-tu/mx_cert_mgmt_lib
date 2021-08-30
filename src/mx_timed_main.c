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

static const char *optstring = "vhc:d:";

static struct option opts[] = {
    { "version",    0, NULL, 'v'},
    { "help",       0, NULL, 'h'},
    { "config",     1, NULL, 'c'},
    { "defconfig",  1, NULL, 'd'},
};

static void _printf_version(void)
{
    fprintf(stdout, "Moxa Time Daemon Version %s\n", MX_TIMED_VERSION);
}

static void _printf_help(void)
{
    fprintf(stdout,
            "Usage: mx-timed [option]\n"
            "Usage: mx-timed -d default_config_path -c config_path\n"
            "\n"
            "Options:\n"
            "      --config             specify the path of configuration file\n"
            "      --defconfig          specify the path of default configuration file\n"
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
    char *config_path = NULL;
    char *defconfig_path = NULL;
    int c = 0;

    while((c = getopt_long(argc, argv, optstring, opts, NULL)) != -1)
    {
        switch(c)
        {
            case 'v':
                _printf_version();
                return EX_OK;
            case 'h':
                _printf_help();
                return EX_OK;
            case 'c':
                config_path = optarg;
                break;
            case 'd':
                defconfig_path = optarg;
                break;
            default:
                return EXIT_FAILURE;
        }
    }

    if(!config_path || !defconfig_path)
    {
        fprintf(stderr, "mx-timed: Missing path of config or defconfig\n");
        return EX_CONFIG;
    }

    // run main
    timed_main();

    return EX_OK;
}
