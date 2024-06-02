/* Copyright (C) 2010-2016 Open Information Security Foundation
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
 *
 *  CPU affinity related code and helper.
 */

#include "suricata-common.h"
#define _THREAD_AFFINITY
#include "util-affinity.h"
#include "conf.h"
#include "runmodes.h"
#include "util-cpu.h"
#include "util-byte.h"
#include "util-debug.h"

ThreadsAffinityType thread_affinity[MAX_CPU_SET] = {
    {
        .name = "receive-cpu-set",
        .mode_flag = EXCLUSIVE_AFFINITY,
        .prio = PRIO_MEDIUM,
        .lcpu = {0},
    },
    {
        .name = "worker-cpu-set",
        .mode_flag = EXCLUSIVE_AFFINITY,
        .prio = PRIO_MEDIUM,
        .lcpu = {0},
    },
    {
        .name = "verdict-cpu-set",
        .mode_flag = BALANCED_AFFINITY,
        .prio = PRIO_MEDIUM,
        .lcpu = {0},
    },
    {
        .name = "management-cpu-set",
        .mode_flag = BALANCED_AFFINITY,
        .prio = PRIO_MEDIUM,
        .lcpu = {0},
    },

};

int thread_affinity_init_done = 0;

/**
 * \brief find affinity by its name
 * \retval a pointer to the affinity or NULL if not found
 */
ThreadsAffinityType * GetAffinityTypeFromName(const char *name)
{
    int i;
    for (i = 0; i < MAX_CPU_SET; i++) {
        if (!strcmp(thread_affinity[i].name, name)) {
            return &thread_affinity[i];
        }
    }
    return NULL;
}

static ThreadsAffinityType *AllocAndInitAffinityType(const char *name, const char *interface_name, ThreadsAffinityType *parent) {
    ThreadsAffinityType *new_affinity = SCCalloc(1, sizeof(ThreadsAffinityType));
    if (new_affinity == NULL) {
        FatalError("Unable to allocate memory for new affinity type");
    }

    new_affinity->name = strdup(interface_name);
    new_affinity->parent = parent;
    new_affinity->mode_flag = EXCLUSIVE_AFFINITY;
    new_affinity->prio = PRIO_MEDIUM;
    for (int i = 0; i < MAX_NUMA_NODES; i++) {
        new_affinity->lcpu[i] = 0;
    }

    if (parent != NULL) {
        if (parent->nb_children == parent->nb_children_capacity) {
            parent->nb_children_capacity *= 2;
            parent->children = SCRealloc(parent->children, parent->nb_children_capacity * sizeof(ThreadsAffinityType *));
            if (parent->children == NULL) {
                FatalError("Unable to reallocate memory for children affinity types");
            }
        }
        parent->children[parent->nb_children++] = new_affinity;
    }

    return new_affinity;
}

ThreadsAffinityType *FindAffinityByInterface(ThreadsAffinityType *parent, const char *interface_name) {
    for (uint32_t i = 0; i < parent->nb_children; i++) {
        if (strcmp(parent->children[i]->name, interface_name) == 0) {
            return parent->children[i];
        }
    }
    return NULL;
}

/**
 * \brief find affinity by its name and interface name, if children are not allowed, then those are alloced and initialized.
 * \retval a pointer to the affinity or NULL if not found
 */
ThreadsAffinityType *GetAffinityTypeForNameAndIface(const char *name, const char *interface_name) {
    int i;
    ThreadsAffinityType *parent_affinity = NULL;

    for (i = 0; i < MAX_CPU_SET; i++) {
        if (strcmp(thread_affinity[i].name, name) == 0) {
            parent_affinity = &thread_affinity[i];
            break;
        }
    }

    if (parent_affinity == NULL) {
        SCLogError("Affinity with name \"%s\" not found", name);
        return NULL;
    }

    if (interface_name != NULL) {
        ThreadsAffinityType *child_affinity = FindAffinityByInterface(parent_affinity, interface_name);
        // found or not found, it is returned
        return child_affinity;
    }

    return parent_affinity;
}

/**
 * \brief find affinity by its name and interface name, if children are not allowed, then those are alloced and initialized.
 * \retval a pointer to the affinity or NULL if not found
 */
ThreadsAffinityType *GetOrAllocAffinityTypeForIfaceOfName(const char *name, const char *interface_name) {
    int i;
    ThreadsAffinityType *parent_affinity = NULL;

    // Step 1: Find the parent affinity by its name
    for (i = 0; i < MAX_CPU_SET; i++) {
        if (strcmp(thread_affinity[i].name, name) == 0) {
            parent_affinity = &thread_affinity[i];
            break;
        }
    }

    if (parent_affinity == NULL) {
        SCLogError("Affinity with name \"%s\" not found", name);
        return NULL;
    }

    // Step 2: If interface_name is provided, search for or create the interface-specific affinity
    if (interface_name != NULL) {
        ThreadsAffinityType *child_affinity = FindAffinityByInterface(parent_affinity, interface_name);
        if (child_affinity != NULL) {
            return child_affinity;
        }

        // If not found, allocate and initialize a new child affinity
        return AllocAndInitAffinityType(name, interface_name, parent_affinity);
    }

    // Step 3: If no interface name is provided, return the parent affinity
    return parent_affinity;
}

#if !defined __CYGWIN__ && !defined OS_WIN32 && !defined __OpenBSD__ && !defined sun
static void AffinitySetupInit(void)
{
    int i, j;
    int ncpu = UtilCpuGetNumProcessorsConfigured();

    SCLogDebug("Initialize affinity setup\n");
    /* be conservative relatively to OS: use all cpus by default */
    for (i = 0; i < MAX_CPU_SET; i++) {
        cpu_set_t *cs = &thread_affinity[i].cpu_set;
        CPU_ZERO(cs);
        for (j = 0; j < ncpu; j++) {
            CPU_SET(j, cs);
        }
        SCMutexInit(&thread_affinity[i].taf_mutex, NULL);
    }
}

void BuildCpusetWithCallback(const char *name, ConfNode *node,
                             void (*Callback)(int i, void * data),
                             void *data)
{
    ConfNode *lnode;
    TAILQ_FOREACH(lnode, &node->head, next) {
        int i;
        long int a,b;
        int stop = 0;
        int max = UtilCpuGetNumProcessorsOnline() - 1;
        if (!strcmp(lnode->val, "all")) {
            a = 0;
            b = max;
            stop = 1;
        } else if (strchr(lnode->val, '-') != NULL) {
            char *sep = strchr(lnode->val, '-');
            char *end;
            a = strtoul(lnode->val, &end, 10);
            if (end != sep) {
                SCLogError("%s: invalid cpu range (start invalid): \"%s\"", name, lnode->val);
                exit(EXIT_FAILURE);
            }
            b = strtol(sep + 1, &end, 10);
            if (end != sep + strlen(sep)) {
                SCLogError("%s: invalid cpu range (end invalid): \"%s\"", name, lnode->val);
                exit(EXIT_FAILURE);
            }
            if (a > b) {
                SCLogError("%s: invalid cpu range (bad order): \"%s\"", name, lnode->val);
                exit(EXIT_FAILURE);
            }
            if (b > max) {
                SCLogError("%s: upper bound (%ld) of cpu set is too high, only %d cpu(s)", name, b,
                        max + 1);
            }
        } else {
            char *end;
            a = strtoul(lnode->val, &end, 10);
            if (end != lnode->val + strlen(lnode->val)) {
                SCLogError("%s: invalid cpu range (not an integer): \"%s\"", name, lnode->val);
                exit(EXIT_FAILURE);
            }
            b = a;
        }
        for (i = a; i<= b; i++) {
            Callback(i, data);
        }
        if (stop)
            break;
    }
}

static void AffinityCallback(int i, void *data)
{
    CPU_SET(i, (cpu_set_t *)data);
}

static void BuildCpuset(const char *name, ConfNode *node, cpu_set_t *cpu)
{
    BuildCpusetWithCallback(name, node, AffinityCallback, (void *) cpu);
}
#endif /* OS_WIN32 and __OpenBSD__ */

/**
 * \brief Extract cpu affinity configuration from current config file
 */

void AffinitySetupLoadFromConfig(void)
{
#if !defined __CYGWIN__ && !defined OS_WIN32 && !defined __OpenBSD__ && !defined sun
    ConfNode *root = ConfGetNode("threading.cpu-affinity");
    ConfNode *affinity, *cpu_node, *mode_node, *prio_node, *node, *nprio;

    if (thread_affinity_init_done == 0) {
        AffinitySetupInit();
        thread_affinity_init_done = 1;
    }

    SCLogDebug("Load affinity from config\n");
    if (root == NULL) {
        SCLogInfo("can't get cpu-affinity node");
        return;
    }

    TAILQ_FOREACH(affinity, &root->head, next) {
        if (strcmp(affinity->val, "decode-cpu-set") == 0 ||
            strcmp(affinity->val, "stream-cpu-set") == 0 ||
            strcmp(affinity->val, "reject-cpu-set") == 0 ||
            strcmp(affinity->val, "output-cpu-set") == 0) {
            continue;
        }
        const char *setname = affinity->val;
        if (strcmp(affinity->val, "detect-cpu-set") == 0)
            setname = "worker-cpu-set";

        ThreadsAffinityType *taf = GetOrAllocAffinityTypeForIfaceOfName(setname, NULL);
        if (taf == NULL) {
            FatalError("unknown cpu-affinity type");
        } else {
            SCLogConfig("Found affinity definition for \"%s\"", setname);
        }

        CPU_ZERO(&taf->cpu_set);
        node = ConfNodeLookupChild(affinity->head.tqh_first, "cpu");
        if (node == NULL) {
            SCLogInfo("unable to find 'cpu'");
        } else {
            BuildCpuset(setname, node, &taf->cpu_set);
        }

        CPU_ZERO(&taf->lowprio_cpu);
        CPU_ZERO(&taf->medprio_cpu);
        CPU_ZERO(&taf->hiprio_cpu);
        nprio = ConfNodeLookupChild(affinity->head.tqh_first, "prio");
        if (nprio != NULL) {
            node = ConfNodeLookupChild(nprio, "low");
            if (node == NULL) {
                SCLogDebug("unable to find 'low' prio using default value");
            } else {
                BuildCpuset(setname, node, &taf->lowprio_cpu);
            }

            node = ConfNodeLookupChild(nprio, "medium");
            if (node == NULL) {
                SCLogDebug("unable to find 'medium' prio using default value");
            } else {
                BuildCpuset(setname, node, &taf->medprio_cpu);
            }

            node = ConfNodeLookupChild(nprio, "high");
            if (node == NULL) {
                SCLogDebug("unable to find 'high' prio using default value");
            } else {
                BuildCpuset(setname, node, &taf->hiprio_cpu);
            }
            node = ConfNodeLookupChild(nprio, "default");
            if (node != NULL) {
                if (!strcmp(node->val, "low")) {
                    taf->prio = PRIO_LOW;
                } else if (!strcmp(node->val, "medium")) {
                    taf->prio = PRIO_MEDIUM;
                } else if (!strcmp(node->val, "high")) {
                    taf->prio = PRIO_HIGH;
                } else {
                    FatalError("unknown cpu_affinity prio");
                }
                SCLogConfig("Using default prio '%s' for set '%s'",
                        node->val, setname);
            }
        }

        node = ConfNodeLookupChild(affinity->head.tqh_first, "mode");
        if (node != NULL) {
            if (!strcmp(node->val, "exclusive")) {
                taf->mode_flag = EXCLUSIVE_AFFINITY;
            } else if (!strcmp(node->val, "balanced")) {
                taf->mode_flag = BALANCED_AFFINITY;
            } else {
                FatalError("unknown cpu_affinity node");
            }
        }

        node = ConfNodeLookupChild(affinity->head.tqh_first, "threads");
        if (node != NULL) {
            if (StringParseUint32(&taf->nb_threads, 10, 0, (const char *)node->val) < 0) {
                FatalError("invalid value for threads "
                            "count: '%s'",
                        node->val);
            }
            if (! taf->nb_threads) {
                FatalError("bad value for threads count");
            }
        }

        if (strcmp(affinity->val, "worker-cpu-set") == 0 && ConfNodeLookupChild(affinity->head.tqh_first, "per-iface") != NULL) {
            ConfNode *child;
            node = ConfNodeLookupChild(affinity->head.tqh_first, "per-iface");
            TAILQ_FOREACH(child, &node->head, next) {
                const char *interface_name;
                uint32_t nb_threads = 0;
                if (!strncmp(child->val, "interface", strlen(child->val))) {
                    ConfNode *subchild;
                    TAILQ_FOREACH(subchild, &child->head, next) {
                        if ((!strcmp(subchild->name, "interface"))) {
                            interface_name = subchild->val;
                        } else if ((!strcmp(subchild->name, "cpu"))) {
                            cpu_node = subchild;
                        } else if ((!strcmp(subchild->name, "mode"))) {
                            mode_node = subchild;
                        } else if ((!strcmp(subchild->name, "prio"))) {
                            prio_node = subchild;
                        } else if ((!strcmp(subchild->name, "threads"))) {
                            if (StringParseUint32(&nb_threads, 10, 0, (const char *)subchild->val) < 0) {
                                FatalError("invalid value for threads count: '%s'", subchild->val);
                            }
                            if (!nb_threads) {
                                FatalError("bad value for threads count");
                            }
                        }
                    }
                }
                const char *setname = affinity->val;
                ThreadsAffinityType *taf = GetOrAllocAffinityTypeForIfaceOfName(setname, interface_name);
                if (taf == NULL) {
                    FatalError("unknown cpu-affinity type");
                } else {
                    SCLogConfig("Found affinity definition for \"%s\" (\"%s\")", setname, interface_name);
                }

                CPU_ZERO(&taf->cpu_set);
                if (cpu_node == NULL) {
                    SCLogInfo("unable to find 'cpu' for interface %s", interface_name);
                } else {
                    BuildCpuset(interface_name, cpu_node, &taf->cpu_set);
                }

                CPU_ZERO(&taf->lowprio_cpu);
                CPU_ZERO(&taf->medprio_cpu);
                CPU_ZERO(&taf->hiprio_cpu);
                if (prio_node != NULL) {
                    ConfNode *node = ConfNodeLookupChild(prio_node, "low");
                    if (node == NULL) {
                        SCLogDebug("unable to find 'low' prio for interface %s", interface_name);
                    } else {
                        BuildCpuset(interface_name, node, &taf->lowprio_cpu);
                    }

                    node = ConfNodeLookupChild(prio_node, "medium");
                    if (node == NULL) {
                        SCLogDebug("unable to find 'medium' prio for interface %s", interface_name);
                    } else {
                        BuildCpuset(interface_name, node, &taf->medprio_cpu);
                    }

                    node = ConfNodeLookupChild(prio_node, "high");
                    if (node == NULL) {
                        SCLogDebug("unable to find 'high' prio for interface %s", interface_name);
                    } else {
                        BuildCpuset(interface_name, node, &taf->hiprio_cpu);
                    }
                    node = ConfNodeLookupChild(prio_node, "default");
                    if (node != NULL) {
                        if (!strcmp(node->val, "low")) {
                            taf->prio = PRIO_LOW;
                        } else if (!strcmp(node->val, "medium")) {
                            taf->prio = PRIO_MEDIUM;
                        } else if (!strcmp(node->val, "high")) {
                            taf->prio = PRIO_HIGH;
                        } else {
                            FatalError("unknown cpu_affinity prio");
                        }
                        SCLogConfig("Using default prio '%s' for interface '%s'",
                                    node->val, interface_name);
                    }
                }

                if (mode_node != NULL) {
                    if (!strcmp(mode_node->val, "exclusive")) {
                        taf->mode_flag = EXCLUSIVE_AFFINITY;
                    } else if (!strcmp(mode_node->val, "balanced")) {
                        taf->mode_flag = BALANCED_AFFINITY;
                    } else {
                        FatalError("unknown cpu_affinity mode");
                    }
                }

                if (nb_threads) {
                    taf->nb_threads = nb_threads;
                }
            }
        }
    }
#endif /* OS_WIN32 and __OpenBSD__ */
}

static hwloc_topology_t topology = NULL;

static int HwLocDeviceNumaGet(hwloc_topology_t topology, hwloc_obj_t obj) {
#if HWLOC_VERSION_MAJOR >= 2 && HWLOC_VERSION_MINOR >= 5
    // TODO: test this block of code or remove it
    hwloc_obj_t nodes[MAX_NUMA_NODES]; // Assuming a maximum of 16 NUMA nodes
    unsigned num_nodes = MAX_NUMA_NODES;
    struct hwloc_location location;
    
    location.type = HWLOC_LOCATION_TYPE_OBJECT;
    location.location.object = obj;

    int result = hwloc_get_local_numanode_objs(topology, &location, &num_nodes, nodes, 0);
    if (result == 0 && num_nodes > 0) {
        printf("NUMA nodes for PCIe device:\n");
        for (unsigned i = 0; i < num_nodes; i++) {
            printf("NUMA node %d\n", nodes[i]->logical_index);
        }
    }
    return -1;
#endif /* HWLOC_VERSION_MAJOR >= 2 && HWLOC_VERSION_MINOR >= 5 */

    hwloc_obj_t non_io_ancestor = hwloc_get_non_io_ancestor_obj(topology, obj);
    if (non_io_ancestor == NULL) {
        fprintf(stderr, "Failed to find non-IO ancestor object.\n");
        return -1;
    }

    // Iterate over NUMA nodes and check their nodeset
    hwloc_obj_t numa_node = NULL;
    while ((numa_node = hwloc_get_next_obj_by_type(topology, HWLOC_OBJ_NUMANODE, numa_node)) != NULL) {
        if (hwloc_bitmap_isset(non_io_ancestor->nodeset, numa_node->os_index)) {
            return numa_node->logical_index;
        }
    }

    return -1;
}

static hwloc_obj_t HwLocDeviceGetByKernelName(hwloc_topology_t topology, const char *interface_name) {
    hwloc_obj_t obj = NULL;

    while ((obj = hwloc_get_next_osdev(topology, obj)) != NULL) {
        if (obj->attr->osdev.type == HWLOC_OBJ_OSDEV_NETWORK && strcmp(obj->name, interface_name) == 0) {
            hwloc_obj_t parent = obj->parent;
            while (parent) {
                if (parent->type == HWLOC_OBJ_PCI_DEVICE) {
                    return parent;
                }
                parent = parent->parent;
            }
        }
    }
    return NULL;
}

// Static function to deparse PCIe interface string name to individual components
static void deparse_pcie_address(const char *pcie_address, unsigned int *domain, unsigned int *bus, unsigned int *device, unsigned int *function) {
    *domain = 0; // Default domain to 0 if not provided

    // Handle both full and short PCIe address formats
    if (sscanf(pcie_address, "%x:%x:%x.%x", domain, bus, device, function) != 4) {
        if (sscanf(pcie_address, "%x:%x.%x", bus, device, function) != 3) {
            fprintf(stderr, "Error parsing PCIe address: %s\n", pcie_address);
            exit(EXIT_FAILURE);
        }
    }
}

// Function to convert PCIe address to hwloc object
static hwloc_obj_t HwLocDeviceGetByPcie(hwloc_topology_t topology, const char *pcie_address) {
    hwloc_obj_t obj = NULL;
    unsigned int domain, bus, device, function;
    deparse_pcie_address(pcie_address, &domain, &bus, &device, &function);
    while ((obj = hwloc_get_next_pcidev(topology, obj)) != NULL) {
        if (obj->attr->pcidev.domain == domain && obj->attr->pcidev.bus == bus && obj->attr->pcidev.dev == device && obj->attr->pcidev.func == function) {
            return obj;
        }
    }
    return NULL;
}

static void HwlocObjectDump(hwloc_obj_t obj) {
    if (!obj) {
        SCLogDebug("No object found for the given PCIe address.\n");
        return;
    }

    SCLogDebug("Object type: %s\n", hwloc_obj_type_string(obj->type));
    SCLogDebug("Logical index: %u\n", obj->logical_index);
    SCLogDebug("Depth: %u\n", obj->depth);
    SCLogDebug("Attributes:\n");
    if (obj->type == HWLOC_OBJ_PCI_DEVICE) {
        SCLogDebug("  Domain: %04x\n", obj->attr->pcidev.domain);
        SCLogDebug("  Bus: %02x\n", obj->attr->pcidev.bus);
        SCLogDebug("  Device: %02x\n", obj->attr->pcidev.dev);
        SCLogDebug("  Function: %01x\n", obj->attr->pcidev.func);
        SCLogDebug("  Class ID: %04x\n", obj->attr->pcidev.class_id);
        SCLogDebug("  Vendor ID: %04x\n", obj->attr->pcidev.vendor_id);
        SCLogDebug("  Device ID: %04x\n", obj->attr->pcidev.device_id);
        SCLogDebug("  Subvendor ID: %04x\n", obj->attr->pcidev.subvendor_id);
        SCLogDebug("  Subdevice ID: %04x\n", obj->attr->pcidev.subdevice_id);
        SCLogDebug("  Revision: %02x\n", obj->attr->pcidev.revision);
        SCLogDebug("  Link speed: %f GB/s\n", obj->attr->pcidev.linkspeed);
    } else {
        SCLogDebug("  No PCI device attributes available.\n");
    }
}

static bool CPUIsFromNuma(uint16_t ncpu, uint16_t numa)
{
    int core_id = ncpu;
    int depth = hwloc_get_type_depth(topology, HWLOC_OBJ_NUMANODE);
    hwloc_obj_t numa_node = NULL;

    while ((numa_node = hwloc_get_next_obj_by_depth(topology, depth, numa_node)) != NULL) {
        hwloc_cpuset_t cpuset = hwloc_bitmap_alloc();
        hwloc_bitmap_copy(cpuset, numa_node->cpuset);

        if (hwloc_bitmap_isset(cpuset, core_id)) {
            SCLogDebug("Core %d - NUMA %d", core_id, numa_node->logical_index);
            hwloc_bitmap_free(cpuset);
            break;
        }
        hwloc_bitmap_free(cpuset);
    }

    if (numa == numa_node->logical_index)
        return true;

    return false;
}


/**
 * \brief Return next cpu to use for a given thread family
 * \retval the cpu to used given by its id
 */
uint16_t AffinityGetNextCPU(ThreadVars *tv, ThreadsAffinityType *taf)
{
    int iface_numa = -1;
    if (tv->type == TVT_PPT && tv->iface_name && ((strcmp(tv->iface_name, taf->name) == 0) || strcmp("worker-cpu-set", taf->name) == 0)) {
        if (topology == NULL) {
            if (hwloc_topology_init(&topology) == -1) {
                FatalError("Failed to initialize topology");
            }
            int ret = hwloc_topology_set_flags(topology, HWLOC_TOPOLOGY_FLAG_WHOLE_SYSTEM);
            ret = hwloc_topology_set_io_types_filter(topology,  HWLOC_TYPE_FILTER_KEEP_ALL);
            if (ret == -1) {
                FatalError("Failed to set topology flags");
                hwloc_topology_destroy(topology);
            }
            if (hwloc_topology_load(topology) == -1) {
                FatalError("Failed to load topology");
                hwloc_topology_destroy(topology);
            }
        }

        // try kernel inteface first
        hwloc_obj_t if_obj = HwLocDeviceGetByKernelName(topology, tv->iface_name);
        if (if_obj == NULL) {
            // if unsuccessful try PCIe search
            if_obj = HwLocDeviceGetByPcie(topology, tv->iface_name);
        }

        if (if_obj != NULL) {
            static char pcie_address[32];
            snprintf(pcie_address, sizeof(pcie_address), "%04x:%02x:%02x.%x", if_obj->attr->pcidev.domain, if_obj->attr->pcidev.bus, if_obj->attr->pcidev.dev, if_obj->attr->pcidev.func);
            SCLogDebug("Interface (%s / %s) has NUMA ID %d", tv->iface_name, pcie_address, HwLocDeviceNumaGet(topology, if_obj));
            HwlocObjectDump(if_obj);
        }

        iface_numa = HwLocDeviceNumaGet(topology, if_obj);
    }

    uint16_t ncpu = 0;
#if !defined __CYGWIN__ && !defined OS_WIN32 && !defined __OpenBSD__ && !defined sun
    int iter = 0;
    SCMutexLock(&taf->taf_mutex);
    int alternative_numa = 0;
    if (iface_numa != -1) {
        ncpu = taf->lcpu[iface_numa];
        while ((!CPU_ISSET(ncpu, &taf->cpu_set) || !CPUIsFromNuma(ncpu, iface_numa))) {
            ncpu++;
            if (ncpu >= UtilCpuGetNumProcessorsOnline()) {
                break;
            }
        }
        if (ncpu < UtilCpuGetNumProcessorsOnline()) {
            taf->lcpu[iface_numa] = ncpu + 1;
        } else {
            taf->lcpu[iface_numa] = UtilCpuGetNumProcessorsOnline();
            // now we want to move to other NUMA node but don't want to step on toes of other ifaces
            // so we need to avoid them by using lcpus of individual NUMA nodes
            for (alternative_numa = 0; alternative_numa < MAX_NUMA_NODES; alternative_numa++) {
                if (alternative_numa == iface_numa) {
                    continue;
                }
                if (taf->lcpu[alternative_numa] >= UtilCpuGetNumProcessorsOnline()) {
                    continue;
                }
                ncpu = taf->lcpu[alternative_numa];
                while (!CPU_ISSET(ncpu, &taf->cpu_set) || !CPUIsFromNuma(ncpu, alternative_numa)) {
                    ncpu++;
                    if (ncpu >= UtilCpuGetNumProcessorsOnline()) {
                        taf->lcpu[alternative_numa] = UtilCpuGetNumProcessorsOnline();
                        break;
                    }
                }
                if (ncpu < UtilCpuGetNumProcessorsOnline()) {
                    taf->lcpu[alternative_numa] = ncpu + 1;
                    break;
                }
            }
        }
    }
    
    bool all_cpus_used = true;
    for (int i = 0; i < MAX_NUMA_NODES; i++) {
        if (taf->lcpu[i] < UtilCpuGetNumProcessorsOnline())
            all_cpus_used = false;
    }
    if (all_cpus_used) {
        for (int i = 0; i < MAX_NUMA_NODES; i++) {
            taf->lcpu[i] = 0;
        }
    }

    if (iface_numa == -1 || ncpu >= UtilCpuGetNumProcessorsOnline()) {
        ncpu = taf->lcpu[0];
        while (!CPU_ISSET(ncpu, &taf->cpu_set) && iter < 2) {
            ncpu++;
            if (ncpu >= UtilCpuGetNumProcessorsOnline()) {
                ncpu = 0;
                iter++;
            }
        }
        taf->lcpu[0] = ncpu + 1;

        if (iter == 2) {
            SCLogError("cpu_set does not contain "
                    "available cpus, cpu affinity conf is invalid");
        }
    }

    all_cpus_used = true;
    for (int i = 0; i < MAX_NUMA_NODES; i++) {
        if (taf->lcpu[i] < UtilCpuGetNumProcessorsOnline())
            all_cpus_used = false;
    }
    if (all_cpus_used) {
        for (int i = 0; i < MAX_NUMA_NODES; i++) {
            taf->lcpu[i] = 0;
        }
    }
    SCMutexUnlock(&taf->taf_mutex);
    SCLogDebug("Setting affinity on CPU %d", ncpu);
#endif /* OS_WIN32 and __OpenBSD__ */
    return ncpu;
}

/**
 * \brief Return the total number of CPUs in a given affinity
 * \retval the number of affined CPUs
 */
uint16_t UtilAffinityGetAffinedCPUNum(ThreadsAffinityType *taf)
{
    uint16_t ncpu = 0;
#if !defined __CYGWIN__ && !defined OS_WIN32 && !defined __OpenBSD__ && !defined sun
    SCMutexLock(&taf->taf_mutex);
    for (int i = UtilCpuGetNumProcessorsOnline(); i >= 0; i--)
        if (CPU_ISSET(i, &taf->cpu_set))
            ncpu++;
    SCMutexUnlock(&taf->taf_mutex);
#endif
    return ncpu;
}

#ifdef HAVE_DPDK
/**
 * Find if CPU sets overlap
 * \return 1 if CPUs overlap, 0 otherwise
 */
uint16_t UtilAffinityCpusOverlap(ThreadsAffinityType *taf1, ThreadsAffinityType *taf2)
{
    ThreadsAffinityType tmptaf;
    CPU_ZERO(&tmptaf);
    SCMutexInit(&tmptaf.taf_mutex, NULL);

    cpu_set_t tmpcset;

    SCMutexLock(&taf1->taf_mutex);
    SCMutexLock(&taf2->taf_mutex);
    CPU_AND(&tmpcset, &taf1->cpu_set, &taf2->cpu_set);
    SCMutexUnlock(&taf2->taf_mutex);
    SCMutexUnlock(&taf1->taf_mutex);

    for (int i = UtilCpuGetNumProcessorsOnline(); i >= 0; i--)
        if (CPU_ISSET(i, &tmpcset))
            return 1;
    return 0;
}

/**
 * Function makes sure that CPUs of different types don't overlap by excluding
 * one affinity type from the other
 * \param mod_taf - CPU set to be modified
 * \param static_taf - static CPU set to be used only for evaluation
 */
void UtilAffinityCpusExclude(ThreadsAffinityType *mod_taf, ThreadsAffinityType *static_taf)
{
    cpu_set_t tmpset;
    SCMutexLock(&mod_taf->taf_mutex);
    SCMutexLock(&static_taf->taf_mutex);
    CPU_XOR(&tmpset, &mod_taf->cpu_set, &static_taf->cpu_set);
    SCMutexUnlock(&static_taf->taf_mutex);
    mod_taf->cpu_set = tmpset;
    SCMutexUnlock(&mod_taf->taf_mutex);
}
#endif /* HAVE_DPDK */
