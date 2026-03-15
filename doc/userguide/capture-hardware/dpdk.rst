.. _dpdk:

DPDK
====

Introduction
-------------

The Data Plane Development Kit (DPDK) is a set of libraries and drivers that
enhance and speed up packet processing in the data plane. Its primary use is to
provide faster packet processing by bypassing the kernel network stack, which
can provide significant performance improvements. For detailed instructions on
how to setup DPDK, please refer to :doc:`../configuration/suricata-yaml` to
learn more about the basic setup for DPDK.
The following sections contain examples of how to set up DPDK and Suricata for
more obscure use-cases.

Hugepage analysis
-----------------

Suricata can analyse utilized hugepages on the system. This can be particularly 
beneficial when there's a potential overallocation of hugepages. 
The hugepage analysis is designed to examine the hugepages in use and 
provide recommendations on an adequate number of hugepages. This then ensures 
Suricata operates optimally while leaving sufficient memory for other 
applications on the system. The analysis works by comparing snapshots of the
hugepages before and after Suricata is initialized. After the initialization,
no more hugepages are allocated by Suricata.
The hugepage analysis can be seen in the Perf log level and is printed out 
during the Suricata start. It is only printed when Suricata detects some 
disrepancies in the system related to hugepage allocation.

It's recommended to perform this analysis from a "clean" state - 
that is a state when all your hugepages are free. It is especially recommended 
when no other hugepage-dependent applications are running on your system.
This can be checked in one of two ways:

.. code-block:: 

  # global check
  cat /proc/meminfo

  HugePages_Total:    1024
  HugePages_Free:     1024

  # per-numa check depends on NUMA node ID, hugepage size, 
  # and nr_hugepages/free_hugepages - e.g.:
  cat /sys/devices/system/node/node0/hugepages/hugepages-2048kB/free_hugepages

After the termination of Suricata and other hugepage-related applications, 
if the count of free hugepages is not equal with the total number of hugepages, 
it indicates some hugepages were not freed completely.
This can be fixed by removing DPDK-related files from the hugepage-mounted 
directory (filesystem). 
It's important to exercise caution while removing hugepages, especially when 
other hugepage-dependent applications are in operation, as this action will 
disrupt their memory functionality.
Removing the DPDK files from the hugepage directory can often be done as:

.. code-block:: bash

  sudo rm -rf /dev/hugepages/rtemap_*

  # To check where hugepages are mounted:
  dpdk-hugepages.py -s
  # or 
  mount | grep huge

Bond interface
--------------

Link Bonding Poll Mode Driver (Bond PMD), is a software
mechanism provided by the Data Plane Development Kit (DPDK) for aggregating
multiple physical network interfaces into a single logical interface.
Bonding can be e.g. used to:

* deliver bidirectional flows of tapped interfaces to the same worker,
* establish redundancy by monitoring multiple links,
* improve network performance by load-balancing traffic across multiple links.

Bond PMD is essentially a virtual driver that manipulates with multiple
physical network interfaces. It can operate in multiple modes as described
in the `DPDK docs
<https://doc.dpdk.org/guides/prog_guide/link_bonding_poll_mode_drv_lib.html>`_
The individual bonding modes can accustom user needs.
DPDK Bond PMD has a requirement that the aggregated interfaces must be
the same device types - e.g. both physical ports run on mlx5 PMD.
Bond PMD supports multiple queues and therefore can work in workers runmode.
It should have no effect on traffic distribution of the individual ports and
flows should be distributed by physical ports according to the RSS
configuration the same way as if they would be configured independently.

As an example of Bond PMD, we can setup Suricata to monitor 2 interfaces
that receive TAP traffic from optical interfaces. This means that Suricata
receive one direction of the communication on one interface and the other
direction is received on the other interface.

::

    ...
    dpdk:
      eal-params:
        proc-type: primary
        vdev: 'net_bonding0,mode=0,slave=0000:04:00.0,slave=0000:04:00.1'

      # DPDK capture support
      # RX queues (and TX queues in IPS mode) are assigned to cores in 1:1 ratio
      interfaces:
        - interface: net_bonding0 # PCIe address of the NIC port
          # Threading: possible values are either "auto" or number of threads
          # - auto takes all cores
          # in IPS mode it is required to specify the number of cores and the
          # numbers on both interfaces must match
          threads: 4
    ...

In the DPDK part of suricata.yaml we have added a new parameter to the
eal-params section for virtual devices - `vdev`.
DPDK Environment Abstraction Layer (EAL) can initialize some virtual devices
during the initialization of EAL.
In this case, EAL creates a new device of type `net_bonding`. Suffix of
`net_bonding` signifies the name of the interface (in this case the zero).
Extra arguments are passed after the device name, such as the bonding mode
(`mode=0`). This is the round-robin mode as is described in the DPDK
documentation of Bond PMD.
Members (slaves) of the `net_bonding0` interface are appended after
the bonding mode parameter.

When the device is specified within EAL parameters, it can be used within
Suricata `interfaces` list. Note that the list doesn't contain PCIe addresses
of the physical ports but instead the `net_bonding0` interface.
Threading section is also adjusted according to the items in the interfaces
list by enablign set-cpu-affinity and listing CPUs that should be used in
management and worker CPU set.

::

    ...
    threading:
      set-cpu-affinity: yes
      cpu-affinity:
        management-cpu-set:
          cpu: [ 0 ]  # include only these CPUs in affinity settings
        receive-cpu-set:
          cpu: [ 0 ]  # include only these CPUs in affinity settings
        worker-cpu-set:
          cpu: [ 2,4,6,8 ]
    ...

Interrupt (power-saving) mode
-----------------------------

The DPDK is traditionally recognized for its polling mode operation. 
In this mode, CPU cores are continuously querying for packets from 
the Network Interface Card (NIC). While this approach offers benefits like 
reduced latency and improved performance, it might not be the most efficient 
in scenarios with sporadic or low traffic. 
The constant polling can lead to unnecessary CPU consumption. 
To address this, DPDK offers an `interrupt` mode.

The obvious advantage that interrupt mode brings is power efficiency. 
So far in our tests, we haven't observed a decrease in performance. Suricata's
performance has actually seen a slight improvement.
The (IPS runmode) users should be aware that interrupts can 
introduce non-deterministic latency. However, the latency should never be 
higher than in other (e.g. AF_PACKET/AF_XDP/...) capture methods. 

Interrupt mode in DPDK can be configured on a per-interface basis. 
This allows for a hybrid setup where some workers operate in polling mode, 
while others utilize the interrupt mode. 
The configuration for the interrupt mode can be found and modified in the 
DPDK section of the suricata.yaml file.

Below is a sample configuration that demonstrates how to enable the interrupt mode for a specific interface:

::

  ...
  dpdk:
      eal-params:
        proc-type: primary

      interfaces:
        - interface: 0000:3b:00.0
          interrupt-mode: true
          threads: 4

.. _dpdk-automatic-interface-configuration:

Automatic interface configuration
---------------------------------

A number of interface properties can be manually configured. However, Suricata
can automatically configure the interface properties based on the NIC
capabilities. This can be done by setting ``auto`` to ``mempool-size``,
``mempool-cache-size``, ``rx-descriptors``, and ``tx-descriptors`` interface
node properties.
This will allow Suricata to automatically set the sizes of individual properties
according to the best-effort calculation based on the NIC capabilities.
For example, receive (RX) descriptors are calculated based on the maximal
"power of 2" that is lower or equal to the number of descriptors supported
by the NIC. Number of TX descriptors depends on the configured ``copy-mode``.
IDS (none) mode uses no TX descriptors and does not create any TX queues by
default. IPS and TAP mode uses the same number of TX descriptors as RX
descriptors.
The number of mempool and its cache is then derived from the count of
descriptors.

Rx (and Tx) descriptors are set to the highest possible value to allow more
buffer room when traffic spikes occur. However, it requires more memory.
Individual properties can still be set manually if needed.

.. note:: Mellanox ConnectX-4 NICs may not support auto-configuration of
  ``RX /TX descriptors``. Instead it can be set to a fixed value (e.g. 16384).

.. _dpdk-link-state-change-timeout:

Link State Change timeout
-------------------------

The `linkup-timeout` YAML configuration option allows the user to set a timeout
period to wait until the interface's link is detected. This ensures that
Suricata does not start processing packets until the link is up. This option is
particularly useful for Intel E810 (Ice) NICs, which begin receiving packets
only after a few seconds have passed since the interface started. In such cases,
if this check is disabled, Suricata reports as started but only begins
processing packets after a few seconds. This issue has not been observed with
other cards.

Setting the value to 0 causes Suricata to skip the link check.
If the interface's link remains down after the timeout period, Suricata warns
the user but continues with the engine initialization.

.. _dpdk-encapsulation-stripping:

Encapsulation stripping
-----------------------

Suricata supports stripping the hardware-offloaded encapsulation stripping on
the supported NICs. Currently, VLAN encapsulation stripping is supported.
VLAN encapsulation stripping can be enabled with `vlan-strip-offload`.

.. _dpdk-pcap-file-mode:

PCAP File Mode (Offline Testing)
---------------------------------

Suricata supports reading PCAP files through the DPDK ``net_pcap`` driver for
offline testing of the DPDK capture method. This allows users to test and
validate DPDK-based detection without requiring physical network interfaces.

When using the ``net_pcap`` driver, Suricata can automatically detect when
the PCAP file has been fully read (characterized by receiving no packets) and
gracefully stop processing that interface. This eliminates the need for timeout
workarounds that were previously required.

Configuration
^^^^^^^^^^^^^

To use PCAP file mode, configure DPDK with a ``net_pcap`` virtual device in the
EAL parameters and reference it in the interfaces list:

.. code-block:: yaml

  dpdk:
    eal-params:
      proc-type: primary
      vdev: 'net_pcap0,rx_pcap=/path/to/capture.pcap'
      no-huge:
      m: 256

    interfaces:
      - interface: net_pcap0
        threads: 1
        mempool-size: 511
        mempool-cache-size: auto
        rx-descriptors: 16
        tx-descriptors: 16
        copy-mode: none
        # Optional: explicitly enable/disable PCAP file mode auto-exit
        # pcap-file-mode: true  # default: auto-detected for net_pcap driver

By default, Suricata automatically detects the ``net_pcap`` driver and enables
PCAP file mode. The interface will stop after approximately 100 consecutive polls
that return zero packets, which indicates the end of the PCAP file.

The ``pcap-file-mode`` configuration option can be explicitly set to ``true`` or
``false`` to override the auto-detection behavior if needed.

Multiple PCAP Files
^^^^^^^^^^^^^^^^^^^

Suricata supports reading multiple PCAP files simultaneously by configuring
multiple ``net_pcap`` virtual devices. Each interface will independently detect
its own EOF condition and stop accordingly:

.. code-block:: yaml

  dpdk:
    eal-params:
      proc-type: primary
      vdev: ['net_pcap0,rx_pcap=/path/to/capture1.pcap',
             'net_pcap1,rx_pcap=/path/to/capture2.pcap']
      no-huge:
      m: 512

    interfaces:
      - interface: net_pcap0
        threads: 1
        mempool-size: 511
        mempool-cache-size: auto
        rx-descriptors: 16
        tx-descriptors: 16
        copy-mode: none

      - interface: net_pcap1
        threads: 1
        mempool-size: 511
        mempool-cache-size: auto
        rx-descriptors: 16
        tx-descriptors: 16
        copy-mode: none

.. note:: When using multiple PCAP files, each interface exits independently
  when its PCAP file is exhausted. Suricata continues running until all
  interfaces have completed or the process is explicitly stopped. Flow records
  and other state information are preserved until Suricata shuts down completely.

Limitations and Considerations
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* **Per-Interface Exit**: The auto-exit feature operates on a per-interface basis.
  When using multiple interfaces, Suricata will not automatically exit when the
  first PCAP file is exhausted. This behavior preserves flow tables and other
  state information that may be needed for processing subsequent packets from
  other interfaces.

* **Streaming PCAP Files**: The current implementation is designed for finite
  PCAP files. If you plan to use streaming PCAP files (files that are continuously
  appended to), you should explicitly disable PCAP file mode by setting
  ``pcap-file-mode: false`` to prevent premature interface shutdown.

* **Zero-Packet Threshold**: The interface stops after detecting approximately
  100 consecutive polls with zero packets. This threshold provides a balance
  between quick detection of EOF and avoiding false positives from temporary
  gaps in packet flow.

Example Use Cases
^^^^^^^^^^^^^^^^^

PCAP file mode is particularly useful for:

* **Regression Testing**: Automated testing of detection rules against known
  PCAP files without manual intervention.

* **Performance Benchmarking**: Measuring DPDK performance with controlled,
  reproducible packet traces.

* **Rule Development**: Quickly iterating on detection rules using sample
  traffic captures.

* **CI/CD Integration**: Automated testing in continuous integration pipelines
  without requiring physical network interfaces or timeouts.
