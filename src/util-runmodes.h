/* Copyright (C) 2011 Open Information Security Foundation
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

/** \file
 *
 *  \author Eric Leblond <eric@regit.org>
 */

#ifndef SURICATA_UTIL_RUNMODES_H
#define SURICATA_UTIL_RUNMODES_H

typedef void *(*ConfigIfaceParserFunc) (const char *);
typedef void *(*ConfigIPSParserFunc) (int);
typedef uint16_t (*ConfigIfaceThreadsCountFunc)(void *);

typedef struct ThreadVars_ ThreadVars;
/**
 * Optional hook invoked for each per-device capture worker thread just before spawning.
 *
 * Allows a runmode to set capture-method specific thread fields (e.g. custom spawn/join/exit).
 */
typedef void (*RunModeThreadVarsSetupFunc)(
        ThreadVars *tv, const char *live_dev, void *iface_conf, uint16_t thread_id, void *data);

int RunModeSetLiveCaptureAuto(ConfigIfaceParserFunc configparser,
                              ConfigIfaceThreadsCountFunc ModThreadsCount,
                              const char *recv_mod_name,
                              const char *decode_mod_name, const char *thread_name,
                              const char *live_dev);

int RunModeSetLiveCaptureAutoFp(ConfigIfaceParserFunc configparser,
        ConfigIfaceThreadsCountFunc ModThreadsCount, const char *recv_mod_name,
        const char *decode_mod_name, const char *thread_name, const char *live_dev);

int RunModeSetLiveCaptureSingle(ConfigIfaceParserFunc configparser,
                              ConfigIfaceThreadsCountFunc ModThreadsCount,
                              const char *recv_mod_name,
                              const char *decode_mod_name, const char *thread_name,
                              const char *live_dev);

int RunModeSetLiveCaptureWorkers(ConfigIfaceParserFunc configparser,
        ConfigIfaceThreadsCountFunc ModThreadsCount, const char *recv_mod_name,
        const char *decode_mod_name, const char *thread_name, const char *live_dev);

int RunModeSetLiveCaptureSingleWithSetup(ConfigIfaceParserFunc configparser,
        ConfigIfaceThreadsCountFunc ModThreadsCount, const char *recv_mod_name,
        const char *decode_mod_name, const char *thread_name, const char *live_dev,
        RunModeThreadVarsSetupFunc setup_cb, void *setup_cb_data);

int RunModeSetLiveCaptureWorkersWithSetup(ConfigIfaceParserFunc configparser,
        ConfigIfaceThreadsCountFunc ModThreadsCount, const char *recv_mod_name,
        const char *decode_mod_name, const char *thread_name, const char *live_dev,
        RunModeThreadVarsSetupFunc setup_cb, void *setup_cb_data);

int RunModeSetIPSAutoFp(ConfigIPSParserFunc ConfigParser,
                        const char *recv_mod_name,
                        const char *verdict_mod_name,
                        const char *decode_mod_name);

int RunModeSetIPSWorker(ConfigIPSParserFunc ConfigParser,
                        const char *recv_mod_name,
                        const char *verdict_mod_name,
                        const char *decode_mod_name);

char *RunmodeAutoFpCreatePickupQueuesString(int n);

#endif /* SURICATA_UTIL_RUNMODES_H */
