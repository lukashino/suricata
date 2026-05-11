/* Copyright (C) 2026 Open Information Security Foundation
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
 * \author Lukas Sismis <lsismis@oisf.net>
 *
 * Pthread implementation of the threading backend.
 */

#include "suricata-common.h"
#include "threadvars.h"
#include "tm-threads.h"
#include "util-threading-backend.h"
#include "util-threading-pthread.h"
#include "util-debug.h"

extern uint64_t threading_set_stack_size;

static void PthreadThreadSpawn(ThreadVars *tv)
{
    pthread_attr_t attr;

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

    if (threading_set_stack_size) {
        SCLogDebug("Setting per-thread stack size to %" PRIu64, threading_set_stack_size);
        if (pthread_attr_setstacksize(&attr, (size_t)threading_set_stack_size)) {
            FatalError("Unable to increase stack size to %" PRIu64 " in thread attributes",
                    threading_set_stack_size);
        }
    }

    pthread_t *t = (pthread_t *)&tv->thread_id;
    int rc = pthread_create(t, &attr, tv->tm_func, (void *)tv);
    if (rc) {
        FatalError("Unable to create thread %s with pthread_create(): retval %d: %s", tv->name, rc,
                strerror(errno));
    }

#if DEBUG && HAVE_PTHREAD_GETATTR_NP
    if (threading_set_stack_size) {
        if (pthread_getattr_np(*t, &attr) == 0) {
            size_t stack_size;
            void *stack_addr;
            pthread_attr_getstack(&attr, &stack_addr, &stack_size);
            SCLogDebug("stack: %p;  size %" PRIu64, stack_addr, (uintmax_t)stack_size);
        } else {
            SCLogDebug("Unable to retrieve current stack-size for display; return code from "
                       "pthread_getattr_np() is %" PRId32,
                    rc);
        }
    }
#endif

    pthread_attr_destroy(&attr);
}

static void PthreadThreadJoin(ThreadVars *tv)
{
    /* Join the thread and flag as dead, unless the thread ID is 0 as
     * its not a thread created by Suricata. */
    if (tv->thread_id != 0) {
        pthread_join((pthread_t)tv->thread_id, NULL);
    }
}

static const ThreadingBackend pthread_backend = {
    .name = "pthread",
    .Spawn = PthreadThreadSpawn,
    .Join = PthreadThreadJoin,
};

void PthreadThreadingBackendRegister(void)
{
    ThreadingBackendRegister(&pthread_backend);
}
