..
      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.


      Convention for heading levels in Neutron devref:
      =======  Heading 0 (reserved for the title in a document)
      -------  Heading 1
      ~~~~~~~  Heading 2
      +++++++  Heading 3
      '''''''  Heading 4
      (Avoid deeper levels because they do not render well.)

Live Migration with ML2/OVN
===========================

This document describes how live migration works with the ML2/OVN mechanism
driver. For the generic ML2 live migration flow (OVS normal plug, OVS-hybrid
plug, MacVTap, SR-IOV), see :doc:`../live_migration`.

ML2/OVN uses a fundamentally different approach from the generic ML2/L2-agent
flow. Instead of RPC messages between L2 agents and the Neutron server,
ML2/OVN leverages OVN Southbound DB events and multi-chassis port bindings
to detect migration, program flows on the destination, and signal readiness
to Nova.


Overview
--------

The key differences between the generic ML2 and OVN live migration are:

* **Signaling mechanism**: Southbound DB events
  (``Port_Binding.additional_chassis``) instead of RPC messages between L2
  agents and the server.
* **Port preparation**: Multi-chassis binding via the ``requested-chassis``
  LSP option (since OVN 22.09.0) instead of L2 agent tap detection and RPC
  device detail requests.
* **Activation**: RARP-based activation strategy (configurable) instead of
  port rebinding triggering RPC fanout.
* **OpenFlow readiness**: ``nb_cfg`` bump and
  ``WaitForChassisNbCfgEvent`` ensure OpenFlow rules are fully written
  before signaling port UP. The generic flow does not explicitly track this.
* **Metadata**: Early provisioning on the destination via
  ``additional_chassis`` instead of the standard agent flow.


TAP Pre-creation (``ovs_create_tap``)
-------------------------------------

Starting in 2026.1, the ``[ovn] ovs_create_tap`` configuration option
controls whether os-vif (on the destination compute node) pre-creates the
TAP device before libvirt starts the VM transfer. This is ``True`` by
default since 2026.2 and it will be made the default behavior in 2027.1.

When ``ovs_create_tap=True``:

#. Neutron includes ``ovs_create_tap: True`` in the port's ``vif_details``
   during the binding operation.
#. Nova (on the destination) calls ``os_vif.plug()`` with
   ``create_tap=True`` during pre-live-migration, which:

   * Creates the TAP device via ``ip tuntap add``.
   * Adds the TAP to OVS ``br-int`` via ``ovs-vsctl add-port``.

#. Libvirt XML is generated with ``managed='no'`` so libvirt uses the
   pre-created TAP device.
#. ovn-controller on the destination detects the TAP and starts programming
   OpenFlow rules.

When ``ovs_create_tap=False`` (legacy behavior):

#. The TAP device is created by libvirt during the actual VM transfer
   (Phase 8). OpenFlow rules cannot be programmed until that point.
#. A "fake" ``network-vif-plugged`` event is sent immediately when the
   ``Logical_Switch_Port`` is updated in the NB DB, before flows are
   programmed. This creates a race window where the VM can be unpaused
   without network connectivity.


Migration Phases
----------------

The following phases describe the full live migration flow with
``ovs_create_tap=True``.

Phase 1: Scheduling
~~~~~~~~~~~~~~~~~~~

The user issues a live migration request. Nova API forwards it to the
conductor, which asks the scheduler to select a destination host.

::

    User            nova-api          nova-conductor       Scheduler
      |                 |                   |                  |
      |--POST---------->|                   |                  |
      | /migrate        |                   |                  |
      |                 |--live_migrate()-->|                  |
      |                 |   (RPC/cast)      |                  |
      |                 |                   |--select_dest()-->|
      |                 |                   |<--dest_host------|


Phase 2: Port binding (Conductor)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Nova conductor creates the port binding on the destination host via the
Neutron API. This binding is ``INACTIVE`` at this stage.

::

    nova-conductor             neutron-server (ML2/OVN)
          |                            |
          |--POST /ports/{id}/bind.--->|
          |   {host_id: dest_host,     |
          |    vnic_type, profile}     |
          |                            | bind_port()
          |                            | UPDATE LSP in NB DB
          |                            |   requested-chassis=DEST
          |<-- binding {               |
          |      status: INACTIVE,     |
          |      vif_details: {        |
          |        ovs_create_tap: T}  |
          |    }                       |

The Neutron API call to bind the port to the destination is made by
**nova-conductor**, not by nova-compute (source or destination).


Phase 3: OVN processes the binding
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

OVN Northd processes the NB DB change and creates the ``Port_Binding`` for the
destination chassis in the SB DB. At this point the TAP device does not
exist yet, so ovn-controller on the destination has nothing to do.

::

    neutron-server     OVN NB DB       OVN Northd        OVN SB DB
          |                |                |                 |
          |                |--process------>|                 |
          |                |                |--Port_Binding-->|
          |                |                |  chassis=DEST   |
          |                |                |  (INACTIVE)     |

This phase runs asynchronously in parallel with Phase 4.


Phase 4: Live migration kickoff (source compute)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Nova conductor sends the ``live_migration()`` RPC call to the source
nova-compute. The source compute registers a
``wait_for_instance_event('network-vif-plugged-{port_id}')`` event
and then calls ``pre_live_migration()`` on the destination compute via RPC.

::

    nova-conductor          nova-compute-SRC
          |                       |
          |--live_migration()---->|   (RPC)
          |                       |
          |             _do_live_migration()
          |             registers: wait_for_instance_event(
          |                          'network-vif-plugged-{port_id}')
          |                       |
          |                       |--pre_live_migration()--> nova-compute-DEST


Phase 5: TAP creation (destination compute + os-vif)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The TAP device is created by **nova-compute-DEST** via ``vif_plug_ovs``
(os-vif). It is **not** created by ovn-controller, neutron-server, or any
Neutron agent.

::

    nova-compute-DEST          os-vif / vif_plug_ovs          OVS-DEST
          |                            |                          |
          | pre_live_migration()       |                          |
          |                            |                          |
          |--os_vif.plug(dest_vif)---->|                          |
          |   create_tap=True          |                          |
          |                            | ip tuntap add tapXXX     |
          |                            |------------------------->|
          |                            | ovs-vsctl add-port       |
          |                            | br-int tapXXX            |
          |                            |------------------------->|
          |                            |                          |
          | network_api.setup_networks_on_host()
          | (sets migrating_to in port profile)
          |
          |<---- returns migrate_data


Phase 6: OVN detects TAP, programs flows
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When ovn-controller on the destination detects the TAP device, it starts
programming OpenFlow rules and populates
``Port_Binding.additional_chassis``.

::

    OVS-DEST        ovn-controller-DEST         OVN SB DB
        |                   |                       |
        | tapXXX appears    |                       |
        |------------------>|                       |
        |                   | programs OpenFlow     |
        |                   | rules for port        |
        |                   |                       |
        |                   |--UPDATE Port_Binding->|
        |                   |  additional_chassis   |
        |                   |  = [DEST chassis]     |
        |                   |                       |
        |                   |--UPDATE-------------->|
        |                   |  Chassis_Private      |
        |                   |  nb_cfg = N           |


Phase 7: Neutron signals ``network-vif-plugged``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Neutron server monitors the SB DB via OVSDB IDL. The
``PortBindingChassisUpdateEvent`` detects that
``Port_Binding.additional_chassis`` has been populated.

With ``ovs_create_tap=True`` and datapath type ``system`` (not DPDK),
Neutron does **not** immediately signal the port as UP. Instead it waits
for the destination ovn-controller to confirm that OpenFlow rules are fully
installed (see `Waiting for OpenFlow Rules`_).

Once the readiness check passes, Neutron sends the
``network-vif-plugged`` event to Nova via the server external events API.

::

    OVN SB DB          neutron-server (OVN SB IDL)         nova-api
        |                       |                              |
        | Port_Binding UPDATE   |                              |
        | additional_chassis set|                              |
        |---------------------->|                              |
        |             PortBindingChassisUpdateEvent.run()      |
        |             WaitForChassisNbCfgEvent fires           |
        |                       |--POST /os-server-ext-events->|
        |                       |  [network-vif-plugged,       |
        |                       |   port_id={id}]              |

Nova-compute-SRC's ``wait_for_instance_event()`` unblocks.


Phase 8: VM transfer
~~~~~~~~~~~~~~~~~~~~

Libvirt performs the actual QEMU migration. Memory pages, CPU state, and
device state are transferred. The VM is paused on the source, resumed on
the destination, and connects to the pre-created TAP device that already
has OpenFlow rules in OVS.

::

    nova-compute-SRC       libvirt-SRC                libvirt-DEST
          |                    |                            |
          | driver.live_migration()                         |
          |                    |                            |
          |                    |<=== QEMU migration ========|
          |                    |   memory pages, CPU state, |
          |                    |   device state transfer    |
          |                    |                            |
          |                    | VM paused on SRC           |
          |                    | VM resumed on DEST ------->|
          |                    |   connects to tapXXX       |


Phase 9: Post-migration
~~~~~~~~~~~~~~~~~~~~~~~

After migration succeeds, nova-compute-SRC activates the destination
binding and deactivates the source binding via the Neutron API. The
port's ``binding:host_id`` moves to the destination host. VIFs on the
source are unplugged.

::

    nova-compute-SRC              neutron-server               OVN NB DB
          |                             |                          |
          | _post_live_migration()      |                          |
          |--PUT /ports/{id}/bindings-->|                          |
          |  /{dest_host}/activate      |                          |
          |                             | activate DEST binding    |
          |                             | deactivate SRC binding   |
          |                             |--UPDATE LSP------------->|
          |                             |  binding:host = DEST     |
          |                             |                          |
          | driver.post_live_migration()                           |
          | unplug VIFs on SRC                                     |


.. _waiting_for_of_rules:

Waiting for OpenFlow Rules
--------------------------

A critical race exists between ovn-controller claiming a port (setting
``Port_Binding.additional_chassis``) and fully installing the OpenFlow
rules for that port. In large environments, ovn-controller can take
several seconds between claiming the port and writing the OF rules. If
Nova unpauses the VM before the rules are written, the instance has no
network connectivity.

To close this race, the ``PortBindingChassisUpdateEvent`` uses a two-step
synchronization:

#. When ``Port_Binding.additional_chassis`` is set for the destination
   chassis, Neutron registers a ``WaitForChassisNbCfgEvent`` (a one-time,
   auto-expiring OVSDB watcher) on the SB IDL. This event watches for
   the destination ``Chassis_Private.nb_cfg`` to reach a target value.

#. ``NB_Global.nb_cfg`` is bumped to create a fresh generation number
   ``N``. The bump is done **after** the watcher is installed to prevent a
   race where ovn-controller processes ``N`` before the watcher is in
   place.

#. When ``Chassis_Private.nb_cfg >= N``, ``set_port_status_up()`` is
   called, sending the ``network-vif-plugged`` event to Nova. This
   confirms that ovn-controller has completed a full processing cycle
   and the port's OpenFlow rules are written.

#. A 120-second safety timeout auto-unwatches the event if the expected
   ``nb_cfg`` is never reached.

Why ``nb_cfg`` and not other signals
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

There are three signals at different levels that indicate flow readiness:

* ``Interface.external_ids:ovn-installed``: Set by ovn-controller on the
  local OVS ``Interface`` table entry after installing all OpenFlow rules.
  This is a per-port signal and authoritative, but it is in the local OVSDB
  only and **not** visible to neutron-server via the SB DB connection.

* ``Port_Binding.up``: Set by ovn-controller in the SB DB. However, during
  live migration the destination is an ``additional_chassis``, and
  ``Port_Binding.up`` is tied to the primary chassis. It may not reflect
  destination readiness until after the binding is activated in Phase 9.

* ``Chassis_Private.nb_cfg``: A chassis-wide counter in the SB DB that
  reflects the latest NB transaction that ovn-controller has fully
  processed. This is visible to neutron-server and is the strongest
  guarantee available via the SB DB.

Why ``nb_cfg`` must be bumped at observation time
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``Chassis_Private.nb_cfg`` is chassis-wide, not per-port. Consider
this sequence:

#. Phase 2: Neutron writes ``requested-chassis=DEST`` on the LSP.
   Northd sets ``NB_Global.nb_cfg = N``.
#. ovn-controller on DEST processes SB changes but the TAP does not exist
   yet. It **cannot** program this port's flows. It may still advance
   ``Chassis_Private.nb_cfg = N`` for everything else it processed.
#. Phase 5: The TAP is created. ovn-controller detects it, programs
   flows, and advances ``Chassis_Private.nb_cfg`` to the current latest
   value ``M``.

Waiting for ``Chassis_Private.nb_cfg >= N`` (from Phase 2) is therefore
**not sufficient**. That threshold may have been passed before the port's
flows were ever installed. The bump creates a new ``N`` that is guaranteed
to be after the TAP was detected.


Activation Strategy
-------------------

The ``[ovn] live_migration_activation_strategy`` configuration option
controls how a migrated port is activated on the destination host:

* ``rarp`` (default): The port on the destination remains inactive until
  the hypervisor sends a Reverse ARP request through it. This confirms the
  VM is actually using the port before OVN switches traffic to the
  destination.

* Empty string (``""``): The port is immediately activated on the
  destination host. Used when RARP is not available or not desired.

This option is translated to the ``activation-strategy`` key in the
LSP options by the OVN client (see
``_configure_requested_chassis_options`` in ``ovn_client.py``).

.. note::

   DPDK ports (``vif_type=vhostuser``) do not support the RARP activation
   strategy. The activation strategy option is skipped for these ports.


Migration State Detection in the Mechanism Driver
-------------------------------------------------

During ``update_port_postcommit``, the OVN mechanism driver checks if a
port is in migration state (status ``DOWN`` with ``migrating_to`` in the
binding profile). The behavior depends on the VIF type and configuration:

* ``vif_type=unbound``: The port will be rebound; processing continues
  normally.

* ``ovs_create_tap=True`` and ``vif_type=ovs``: Return immediately
  without sending a fake event. Wait for the
  ``PortBindingChassisUpdateEvent`` Southbound event, which fires when
  ``Port_Binding.additional_chassis`` is populated by ovn-controller.

* ``ovs_create_tap=False`` or ``vif_type=vhostuser``: A "fake"
  ``network-vif-plugged`` event is sent by forcing the port status to
  ``ACTIVE``. This is the legacy behavior and does not guarantee that
  OpenFlow rules are in place.

A revision conflict retry mechanism handles the race between the OVN
"port down" event from the source node and the Nova API request to
activate the binding on the destination node.


Metadata Agent Early Provisioning
---------------------------------

The OVN metadata agent watches ``Port_Binding.additional_chassis`` to
provision metadata resources on the destination **before** the VM actually
lands there:

* ``_additional_chassis_added()``: When the agent's chassis appears in
  ``additional_chassis``, metadata resources (namespace, haproxy) are
  provisioned early.

* ``_additional_chassis_removed()``: If the agent's chassis is removed
  from ``additional_chassis`` **without** being set as the primary
  ``chassis``, the migration was rolled back and resources are torn down.
  If the chassis moves to the primary ``chassis`` column, the migration
  succeeded and resources remain.


Trunk Ports
-----------

The OVN trunk driver has a known limitation during live migration:
subport bindings are not cascaded from the parent port. The subports'
``binding:host`` remains empty during migration, so the trunk driver
cannot track subport state changes.

As a workaround, the trunk status is set to ``ACTIVE`` when the parent
port transitions to ``ACTIVE``, regardless of subport state. This
affects both trunk creation and live migration.

See:

* `LP#1988549 <https://bugs.launchpad.net/neutron/+bug/1988549>`_
* `LP#2095152 <https://bugs.launchpad.net/neutron/+bug/2095152>`_


Component Responsibilities
---------------------------

The following table summarizes which component is responsible for each
action during live migration:

.. list-table::
   :header-rows: 1
   :widths: 55 45

   * - Action
     - Owner
   * - Bind port to DEST (``POST /ports/{id}/bindings``)
     - nova-conductor
   * - Update ``Logical_Switch_Port`` in NB DB
     - neutron-server (ML2/OVN driver)
   * - Create ``Port_Binding`` for DEST chassis in SB DB
     - OVN Northd
   * - TAP device creation (``ip tuntap add``)
     - nova-compute-DEST via ``vif_plug_ovs``
   * - Add TAP to OVS (``ovs-vsctl add-port br-int``)
     - nova-compute-DEST via ``vif_plug_ovs``
   * - OpenFlow rules programming
     - ovn-controller (DEST)
   * - Set ``Port_Binding.additional_chassis``
     - ovn-controller (DEST)
   * - Advance ``Chassis_Private.nb_cfg``
     - ovn-controller (DEST)
   * - Bump ``NB_Global.nb_cfg``
     - neutron-server (OVN SB IDL handler)
   * - Send ``network-vif-plugged`` to Nova
     - neutron-server (OVN SB IDL handler)
   * - Activate DEST port binding
     - nova-compute-SRC (post-migration)


Error Recovery
--------------

Failed live migrations can leave duplicated ``PortBinding`` records in the
Neutron database. The ``neutron-remove-duplicated-port-bindings`` CLI script
can clean up these stale bindings. See :doc:`../live_migration` for details.

.. warning::

   This script must **not** be executed during an active live migration or
   cross-cell cold migration. It will delete the inactive port binding and
   break the process.
