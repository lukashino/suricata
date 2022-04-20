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
#define _POSIX_SOURCE
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include "util-prefilter.h"

static volatile int g_should_stop = 0;

static void SignalStop(int sig)
{
    switch (sig) {
        case SIGINT:
        case SIGTERM:
            g_should_stop = 1;
            break;
        default:
            break;
    }
}

static void SignalBrokenPmd(int sig)
{
    int ret;
#define HINT "segfault, try --no-pci or start as root\n"

    if (sig != SIGSEGV)
        return;

    ret = (int)write(STDERR_FILENO, HINT, sizeof(HINT) - 1);
    if (ret <= 0)
        fprintf(stderr, "write function failed: %s\n", strerror(errno));
    signal(sig, SIG_DFL);
    kill(getpid(), sig);
}

int ShouldStop(void)
{
    return g_should_stop;
}

void SignalInit(void)
{
    signal(SIGSEGV, &SignalBrokenPmd);
    signal(SIGSEGV, SIG_DFL);
    signal(SIGINT, &SignalStop);
    signal(SIGTERM, &SignalStop);
}

void StopWorkers(void)
{
    g_should_stop = 1;
}
