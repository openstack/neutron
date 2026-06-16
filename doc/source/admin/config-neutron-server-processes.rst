.. _config-neutron-server-processes:

================================
Neutron server-side processes
================================

On controller nodes, what is commonly referred to as ``neutron-server`` is
actually a set of cooperating processes. Each process has a dedicated role:
serving the REST API, handling RPC from agents, running periodic tasks, or
performing ML2/OVN maintenance work.

Since OpenStack Epoxy (2025.1), the Neutron API is served exclusively through
a WSGI server (typically uWSGI). The companion processes listed below are
started as separate services alongside the API.


Overview
--------

The following table summarizes the Neutron server-side processes:

.. list-table::
   :header-rows: 1
   :widths: 15 30 20 25

   * - Process
     - Executable / entry point
     - When it runs
     - Key configuration
   * - API
     - uWSGI workers loading ``neutron.wsgi.api:application``
     - Always
     - uWSGI ``processes``, :ref:`config-wsgi`
   * - RPC
     - ``neutron-rpc-server`` (spawns ``rpc worker`` and
       ``rpc reports worker`` child processes)
     - When agents require RPC
     - uWSGI ``processes``; Neutron ``rpc_workers`` and ``rpc_state_report_workers``
   * - Periodic
     - ``neutron-periodic-workers`` (runs plugin periodic tasks as threads)
     - With any ML2 mechanism driver and WSGI API
     - ``periodic_interval``, ``periodic_fuzzy_delay``
   * - Maintenance
     - ``neutron-ovn-maintenance-worker``
     - ML2/OVN deployments only
     - See :ref:`maintenance_worker`

All of these processes load the same ``neutron.conf`` and plugin configuration
files (for example ``ml2_conf.ini``). Only these server-side processes connect
to the Neutron database; agents must not connect directly.


API workers
-----------

The API workers serve the Neutron REST API. Each worker is a uWSGI process
that loads the WSGI application entry point
``neutron.wsgi.api:application``.

The number of API workers is configured in the uWSGI configuration file
(``processes`` option). Deployers should also review the worker tuning
guidance in :doc:`config-wsgi`.

.. note::

   ML2/OVN requires the uWSGI ``start-time = %t`` parameter so that API
   workers can register themselves in the OVN hash ring during
   initialization. See :doc:`config-wsgi` for details.


RPC workers
-------------

The ``neutron-rpc-server`` service handles RPC communication between the
Neutron server and agents (for example DHCP, L3, and OVS agents). When
started, it spawns two types of child worker processes:

* **rpc worker** — handles general RPC requests from agents and other
  OpenStack services. The number of processes is controlled by
  ``[DEFAULT] rpc_workers``.

* **rpc reports worker** — dedicated to processing agent state reports
  (heartbeats). The number of processes is controlled by
  ``[DEFAULT] rpc_state_report_workers``.

When the Neutron API is served by an external web server (such as Apache with
``mod_wsgi``), RPC listeners cannot run inside the API process. In that case,
``neutron-rpc-server`` must be started as a separate service. See
:doc:`config-wsgi` for an example command.

.. note::

   If the ML2/OVN mechanism driver is used without additional agents that
   require RPC, both ``rpc_workers`` and ``rpc_state_report_workers`` can be
   set to ``0``. See :doc:`ovn/rpc` for more information.


Periodic workers
----------------

The ``neutron-periodic-workers`` service runs periodic tasks registered by
the ML2 plugin and service plugins (for example DHCP agent scheduling,
quota synchronization, and agent health checks). These tasks are collected
via each plugin's ``get_workers()`` method and executed as threads inside
a single process (internally referred to as the **services worker**).

This process is spawned for any deployment using the Neutron API WSGI module
with an ML2 mechanism driver.


Maintenance worker
------------------

The ``neutron-ovn-maintenance-worker`` service is required only when using
the ML2/OVN mechanism driver. It synchronizes the Neutron and OVN databases
and runs periodic inconsistency checks.

For details on what the maintenance worker does and how plugins can register
additional periodic tasks, see :ref:`maintenance_worker`.


Process identification
----------------------

Neutron child processes set descriptive process titles (for example
``api worker``, ``rpc worker``, ``rpc reports worker``, ``periodic worker``,
``services worker``, and ``maintenance worker``) to make them easy to identify
with tools such as ``ps``.

This behavior is controlled by the ``[DEFAULT] setproctitle`` option in
``neutron.conf``. When set to ``brief``, process titles are shorter and easier
to read. The default is ``on``, which appends the original command string for
backwards compatibility with scripts that match on the old process names.


Configuration reference
-----------------------

The following ``neutron.conf`` options control worker counts and periodic
task behavior:

``api_workers``
  Number of API worker processes. If not set, defaults to the number of CPU
  cores, capped by available memory.

``rpc_workers``
  Number of RPC worker processes. If not set, defaults to half the number of
  API workers. Set to ``0`` to disable RPC workers entirely.

``rpc_state_report_workers``
  Number of RPC worker processes dedicated to agent state reports. Defaults
  to ``1``. Set to ``0`` to disable the dedicated state-report workers.

``periodic_interval``
  Seconds between running periodic tasks. Defaults to ``40``.

``periodic_fuzzy_delay``
  Random delay range (in seconds) when starting the periodic task scheduler,
  to reduce stampeding across workers. Defaults to ``5``. Set to ``0`` to
  disable.

For the full list of options and their defaults, see
:doc:`../configuration/neutron`.
