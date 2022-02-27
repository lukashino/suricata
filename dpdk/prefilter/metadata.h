#ifndef METADATA_H
#define METADATA_H

#define _DEFAULT_SOURCE 1 // for time.h
#define __rtems__       1 // for time.h
#define __USE_MISC      1 // for time.h
#include <sys/time.h>

#define PCRE2_CODE_UNIT_WIDTH 8
#include <netinet/in.h>
#include <stdbool.h>
#include <string.h>

#include "suricata-common.h"
#include "conf.h"
#include "conf-yaml-loader.h"
#include "util-atomic.h"
#include "tm-threads-common.h"
#include "threads.h"
#include "util-device.h"
#include "util-debug.h"
#include "util-dpdk.h"
#include "util-dpdk-bypass.h"
#include "runmode-dpdk.h"
#include "source-dpdk.h"
#include "decode.h"

#endif // METADATA_H