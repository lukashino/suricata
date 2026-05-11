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
 * Threading backend registry and selection. Keeps a small static set of
 * available backends and tracks the currently active one.
 */

#include "suricata-common.h"
#include "util-threading-backend.h"
#include "util-threading-pthread.h"
#include "util-debug.h"

#define THREADING_BACKEND_MAX 4

static const ThreadingBackend *threading_backends[THREADING_BACKEND_MAX];
static size_t threading_backends_count;
static const ThreadingBackend *active_backend;

void ThreadingBackendRegister(const ThreadingBackend *backend)
{
    if (backend == NULL || backend->name == NULL || backend->Spawn == NULL ||
            backend->Join == NULL) {
        FatalError("Invalid threading backend registration");
    }

    for (size_t i = 0; i < threading_backends_count; i++) {
        if (strcmp(threading_backends[i]->name, backend->name) == 0) {
            return; /* already registered */
        }
    }

    if (threading_backends_count >= THREADING_BACKEND_MAX) {
        FatalError("Too many threading backends registered");
    }

    threading_backends[threading_backends_count++] = backend;
}

void ThreadingBackendSelect(const char *name)
{
    if (name == NULL) {
        FatalError("ThreadingBackendSelect called with NULL name");
    }

    for (size_t i = 0; i < threading_backends_count; i++) {
        if (strcmp(threading_backends[i]->name, name) == 0) {
            active_backend = threading_backends[i];
            SCLogDebug("Selected threading backend \"%s\"", name);
            return;
        }
    }

    FatalError("Unknown threading backend \"%s\"", name);
}

const ThreadingBackend *ThreadingBackendGet(void)
{
    if (active_backend == NULL) {
        FatalError("Threading backend not initialized");
    }
    return active_backend;
}

void ThreadingBackendInit(void)
{
    PthreadThreadingBackendRegister();
    ThreadingBackendSelect("pthread");
}
