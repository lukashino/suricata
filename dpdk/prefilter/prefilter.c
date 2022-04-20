/* Copyright (C) 2022 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Lukas Sismis <sismis@cesnet.com>
 *
 */

#define _POSIX_C_SOURCE 200809L
#define CLS             64 // sysconf(_SC_LEVEL1_DCACHE_LINESIZE)
#include <getopt.h>

#include "prefilter.h"
#include "util-prefilter.h"
#include "logger.h"
#include "logger-basic.h"

#include "dev-conf.h"
#include "dev-conf-suricata.h"
#include "lcores-manager.h"
#include "stats.h"

struct prefilter_args {
    char *conf_path;
    LogLevelEnum log_lvl;
};

static void EalInit(int *argc, char ***argv)
{
    int args;

    rte_log_set_global_level(RTE_LOG_WARNING);
    args = rte_eal_init(*argc, *argv);
    if (args < 0) {
        fprintf(stderr, "rte_eal_init() has failed: %d\n", args);
        exit(EXIT_FAILURE);
    }
    *argc -= args;
    *argv += args;

    if (rte_eal_process_type() != RTE_PROC_PRIMARY) {
        fprintf(stderr, "invalid process type, primary required\n");
        rte_eal_cleanup();
        exit(EXIT_FAILURE);
    }
}

static void PrintUsage()
{
    printf("\t-c <path>                            : path to configuration file\n");
    printf("\t--config-path <path>                            : path to configuration file\n");
    printf("\t-l <log-level>                            : level of logs\n");
    printf("\t--log-level <log-level>                            : level of logs\n");
}

static int ArgsParse(int argc, char *argv[], struct prefilter_args *args)
{
    int opt;

    // clang-format off
struct option long_opts[] = {
#ifdef HAVE_DPDK
{"config-path", required_argument, 0, 0},
{"log-level", required_argument, 0, 0},
#endif
};
    // clang-format on

    /* getopt_long stores the option index here. */
    int option_index = 0;

    char short_opts[] = "c:l:";

    while ((opt = getopt_long(argc, argv, short_opts, long_opts, &option_index)) != -1) {
        switch (opt) {
            case 0:
                if (strcmp((long_opts[option_index]).name, "config-path") == 0) {
                    args->conf_path = optarg;
                    break;
                } else if (strcmp((long_opts[option_index]).name, "log-level") == 0) {
                    args->log_lvl = LoggerGetLogLevelFromString(optarg);
                    break;
                }
                PrintUsage();
                return -EXIT_FAILURE;
            case 'c':
                args->conf_path = optarg;
                break;
            case 'l':
                args->log_lvl = LoggerGetLogLevelFromString(optarg);
                break;
            default:
                PrintUsage();
                return -EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;
}

int main(int argc, char *argv[])
{
    int ret;
    struct resource_ctx ctx = { 0 };
    struct prefilter_args args = {
        .conf_path = NULL,
        .log_lvl = PF_INFO,
    };

    EalInit(&argc, &argv);
    ret = ArgsParse(argc, argv, &args);
    if (ret != 0)
        goto cleanup;

    SignalInit();

    LoggerInit(logger_basic_ops, args.log_lvl);

    //    dev_conf_suricata_ops
    DevConfInit(dev_conf_suricata_ops);
    ret = DevConfConfigureBy((void *)args.conf_path);
    if (ret != 0) {
        goto cleanup;
    }
    Log().info("Configured");

    ret = DevConfRingsInit(&ctx);
    if (ret != 0)
        goto cleanup;

    ret = PFStatsInit(&ctx.app_stats);
    if (ret != 0)
        goto cleanup;

    ret = LcoreManagerRunWorkers(ctx.app_stats);
    if (ret != 0)
        goto cleanup;

cleanup:
    rte_eal_mp_wait_lcore();
    PFStatsExitLog(ctx.app_stats);

    for (int i = 0; i < ctx.main_rings_cnt; i++) {
        if (ctx.main_rings != NULL) {
            struct main_ring *mr = &ctx.main_rings[i];
            for (int j = 0; j < mr->ring_from_pf_arr_len; j++) {
                if (mr->ring_from_pf_arr[j] != NULL) {
                    rte_ring_free(mr->ring_from_pf_arr[j]);
                }
            }

            for (int j = 0; j < mr->ring_to_pf_arr_len; j++) {
                if (mr->ring_to_pf_arr[j] != NULL) {
                    rte_ring_free(mr->ring_to_pf_arr[j]);
                }
            }
        }
    }
    PFStatsDeinit(ctx.app_stats);
    DevConfDeinit();
    rte_eal_cleanup();

    return ret;
}