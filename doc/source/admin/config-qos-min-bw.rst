Quality of Service (QoS): Guaranteed Minimum Bandwidth
======================================================

Most Networking Quality of Service (QoS) features are implemented solely
by OpenStack Neutron and they are already documented in the :doc:`QoS
configuration chapter of the Networking Guide <config-qos>`.  Some more
complex QoS features necessarily involve the scheduling of a cloud server,
therefore their implementation is shared between OpenStack Nova, Neutron
and Placement. As of the OpenStack Stein release the Guaranteed Minimum
Bandwidth feature is like the latter.

This Networking Guide chapter does not aim to replace Nova or Placement
documentation in any way, but it still hopes to give an overall
OpenStack-level guide to understanding and configuring a deployment to
use the Guaranteed Minimum Bandwidth feature.

A guarantee of minimum available bandwidth can be enforced on two levels:

* Scheduling a server on a compute host where the bandwidth is available.
  To be more precise: scheduling one or more ports of a server on a compute
  host's physical network interfaces where the bandwidth is available.
* Queueing network packets on a physical network interface to provide the
  guaranteed bandwidth.

In short the enforcement has two levels:

* (server) placement and
* data plane.

Since the data plane enforcement is already documented in the
:doc:`QoS chapter <config-qos>`,
here we only document the placement-level enforcement.

Limitations
-----------

* A pre-created port with a ``minimum-bandwidth`` rule must be passed
  when booting a server (``openstack server create``). Passing a network
  with a minimum-bandwidth rule at boot is not supported because of
  technical reasons (in this case the port is created too late for
  Neutron to affect scheduling).

* Bandwidth guarantees for ports can only be requested on networks
  backed by a physical network (physnet).

* In Stein there is no support for networks with multiple physnets.
  However some simpler multi-segment networks are still supported:

  * Networks with multiple segments all having the same physnet name.
  * Networks with only one physnet segment (the other segments being
    tunneled segments).

* If you mix ports with and without bandwidth guarantees on the same physical
  interface then the ports without a guarantee may starve. Therefore mixing
  them is not recommended. Instead it is recommended to separate them by
  :nova-doc:`Nova host aggregates <admin/aggregates>`.

* Changing the guarantee of a QoS policy (adding/deleting a
  ``minimum_bandwidth`` rule, or changing the ``min_kbps`` field of a
  ``minimum_bandwidth`` rule) is only possible while the policy is not in
  effect. That is ports of the QoS policy are not yet used by Nova. Requests
  to change guarantees of in-use policies are rejected.

* Changing the QoS policy of the port with new ``minimum_bandwidth`` rules
  changes placement ``allocations`` from Wallaby release.
  If the VM was booted with port without QoS policy and ``minimum_bandwidth``
  rules the port update succeeds but placement allocations will not change.
  The same is true if the port has no ``binding:profile``, thus no placement
  allocation record exists for it. But if the VM was booted with a port with
  QoS policy and ``minimum_bandwidth`` rules the update is possible and the
  allocations are changed in placement as well.

.. note::

  As it is possible to update a port to remove the QoS policy, updating it
  back to have QoS policy with ``minimum_bandwidth`` rule will not result in
  ``placement allocation`` record, only the dataplane enforcement will happen.

.. note::

  updating the ``minimum_bandwidth`` rule of a QoS policy that is attached
  to a port which is bound to a VM is still not possible.

* The first data-plane-only Guaranteed Minimum Bandwidth implementation
  (for SR-IOV egress traffic) was released in the Newton
  release of Neutron.  Because of the known lack of
  placement-level enforcement it was marked as "`best effort
  <https://docs.openstack.org/releasenotes/neutron/newton.html#other-notes>`_"
  (5th bullet point).  Since placement-level enforcement was not implemented
  bandwidth may have become overallocated and the system level
  resource inventory may have become inconsistent. Therefore for users
  of the data-plane-only implementation a migration/healing process is
  mandatory (see section `On Healing of Allocations`_) to bring the system
  level resource inventory to a consistent state. Further operations
  that would reintroduce inconsistency (e.g. migrating a server with
  ``minimum_bandwidth`` QoS rule, but no resource allocation in Placement)
  are rejected now in a backward-incompatible way.

* The Guaranteed Minimum Bandwidth feature is not complete in the Stein
  release. Not all Nova server lifecycle operations can be executed on a
  server with bandwidth guarantees. Since Stein (Nova API microversion
  2.72+) you can boot and delete a server with a guarantee and detach
  a port with a guarantee. Since Train you can also migrate and resize
  a server with a guarantee. Support for further server move operations
  (for example evacuate, live-migrate and unshelve after shelve-offload)
  is to be implemented later. For the definitive documentation please
  refer to the `Port with Resource Request chapter
  <https://docs.openstack.org/api-guide/compute/port_with_resource_request.html>`_
  of the OpenStack Compute API Guide.

* If an SR-IOV physical function is configured for use by the
  neutron-openvswitch-agent, and the same physical function's virtual
  functions are configured for use by the neutron-sriov-agent then the
  available bandwidth must be statically split between the corresponding
  resource providers by administrative choice. For example a 10 Gbps
  SR-IOV capable physical NIC could be treated as two independent NICs -
  a 5 Gbps NIC (technically the physical function of the NIC) added to
  an Open vSwitch bridge, and another 5 Gbps NIC whose virtual functions
  can be handed out to servers by neutron-sriov-agent.

* Neutron allows physnet names to be case sensitive. So physnet0 and
  Physnet0 are treated as different physnets. Physnets are mapped to
  traits in Placement for scheduling purposes. However Placement traits are
  case insensitive and normalized to full capital. Therefore the scheduling
  treats physnet0 and Physnet0 as the same physnet. It is advised not to use
  physnet names that are only differ by case.

* There are hardware platforms (e.g.: Cavium ThunderX) where it's possible
  to have virtual functions which are network devices that are not associated
  to a physical function. As bandwidth resources are tracked per physical
  function, for such hardware the placement enforcement of the QoS minimum
  bandwidth rules cannot be supported. Creating a server with ports using such
  QoS policy targeting such hardware backend will result in a ``NoValidHost``
  error during scheduling.

* When QoS is used with a trunk, Placement enforcement is applied only to the
  trunk's parent port. Subports are not going to have Placement allocation.
  As a workaround, parent port's QoS policy should take into account subports
  needs and request enough minimum bandwidth resources to accommodate every
  port in the trunk.

Placement pre-requisites
------------------------

Placement must support `microversion 1.29
<https://docs.openstack.org/placement/latest/placement-api-microversion-history.html#support-allocation-candidates-with-nested-resource-providers>`_.
This was first released in Rocky.

Nova pre-requisites
-------------------

Nova must support `microversion 2.72
<https://docs.openstack.org/nova/latest/reference/api-microversion-history.html#maximum-in-stein>`_.
This was first released in Stein.

Not all Nova virt drivers are supported, please refer to the
`Virt Driver Support section of the Nova Admin Guide
<https://docs.openstack.org/nova/latest/admin/port_with_resource_request.html#virt-driver-support>`_.

Neutron pre-requisites
----------------------

Neutron must support the following API extensions:

* ``agent-resources-synced``
* ``port-resource-request``
* ``qos-bw-minimum-ingress``

These were all first released in Stein.

Supported drivers and agents
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In release Stein the following agent-based ML2 mechanism drivers are
supported:

* Open vSwitch (``openvswitch``) vnic_types: ``normal``, ``direct``
* SR-IOV (``sriovnicswitch``) vnic_types: ``direct``, ``macvtap``

From the Yoga release the ``direct-physical`` vnic_type is now marked supported
for the SR-IOV (``sriovnicswitch``) agent.

neutron-server config
~~~~~~~~~~~~~~~~~~~~~

The ``placement`` service plugin synchronizes the agents' resource
provider information from neutron-server to Placement.

Since neutron-server talks to Placement you need to configure how
neutron-server should find Placement and authenticate to it.

``/etc/neutron/neutron.conf`` (on controller nodes):

.. code-block:: ini

    [DEFAULT]
    service_plugins = placement,...
    auth_strategy = keystone

    [placement]
    auth_type = password
    auth_url = https://controller/identity
    password = secret
    project_domain_name = Default
    project_name = service
    user_domain_name = Default
    username = placement

If a vnic_type is supported by default by multiple ML2 mechanism
drivers (e.g. ``vnic_type=direct`` by both ``openvswitch`` and
``sriovnicswitch``) and multiple agents' resources are also meant to be
tracked by Placement, then the admin must decide which driver to take
ports of that vnic_type by prohibiting the vnic_type for the unwanted
drivers. Use :oslo.config:option:`ovs_driver.vnic_type_prohibit_list` in this
case. Valid values are all the ``supported_vnic_types`` of the
`respective mechanism drivers
<https://docs.openstack.org/neutron/latest/admin/config-ml2.html#supported-vnic-types>`_.

``/etc/neutron/plugins/ml2/ml2_conf.ini`` (on controller nodes):

.. code-block:: ini

    [ovs_driver]
    vnic_type_prohibit_list = direct

    [sriov_driver]
    #vnic_type_prohibit_list = direct

neutron-openvswitch-agent config
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Set the agent configuration as the authentic source of
the resources available. Set it on a per-bridge basis by
:oslo.config:option:`ovs.resource_provider_bandwidths`.
The format is: ``bridge:egress:ingress,...``
You may set only one direction and omit the other.

.. note::

    ``egress`` / ``ingress`` is meant from the perspective of a cloud server.
    That is ``egress`` = cloud server upload, ``ingress`` = download.

    Egress and ingress available bandwidth values are in ``kilobit/sec (kbps)``.

If desired, resource provider inventory fields can be tweaked on a
per-agent basis by setting
:oslo.config:option:`ovs.resource_provider_inventory_defaults`.
Valid values are all the
`optional parameters of the update resource provider inventory call
<https://docs.openstack.org/api-ref/placement/?expanded=update-resource-provider-inventory-detail#update-resource-provider-inventory>`_.

``/etc/neutron/plugins/ml2/ovs_agent.ini`` (on compute and network nodes):

.. code-block:: ini

    [ovs]
    bridge_mappings = physnet0:br-physnet0,...
    resource_provider_bandwidths = br-physnet0:10000000:10000000,...
    #resource_provider_inventory_defaults = step_size:1000,...

neutron-sriov-agent config
~~~~~~~~~~~~~~~~~~~~~~~~~~

The configuration of neutron-sriov-agent is analog to that of
neutron-openvswitch-agent. However look out for:

* The different .ini section names as you can see below.
* That neutron-sriov-agent allows a physnet to be backed by multiple physical
  devices.
* Of course refer to SR-IOV physical functions instead of bridges in
  :oslo.config:option:`sriov_nic.resource_provider_bandwidths`.

``/etc/neutron/plugins/ml2/sriov_agent.ini`` (on compute nodes):

.. code-block:: ini

    [sriov_nic]
    physical_device_mappings = physnet0:ens5,physnet0:ens6,...
    resource_provider_bandwidths = ens5:40000000:40000000,ens6:40000000:40000000,...
    #resource_provider_inventory_defaults = step_size:1000,...

OVN chassis config
~~~~~~~~~~~~~~~~~~

Bandwidth config values are stored in each SB chassis register, in
"external_ids:ovn-cms-options". The configuration options are the same as in
SR-IOV and OVS agents. This is how the values are registered:

.. code-block:: bash

    $ root@dev20:~# ovs-vsctl list Open_vSwitch
      ...
      external_ids        : {hostname=dev20.fistro.com, \
                             ovn-cms-options="resource_provider_bandwidths=br-ex:1001:2000;br-ex2:3000:4000, \
                                              resource_provider_inventory_defaults=allocation_ratio:1.0;min_unit:10, \
                                              resource_provider_hypervisors=br-ex:dev20.fistro.com;br-ex2:dev20.fistro.com", \
                             rundir="/var/run/openvswitch", \
                             system-id="029e7d3d-d2ab-4f2c-bc92-ec58c94a8fc1"}
      ...

Each configuration option defined in "external_ids:ovn-cms-options" is divided
by commas.

This information is retrieved from the OVN SB database during the Neutron
server initialization and when the "Chassis" registers are updated.

During the Neutron server initialization, a ``MaintenanceWorker`` thread will
call ``OvnSbSynchronizer.do_sync``, that will call
``OVNClientPlacementExtension.read_initial_chassis_config``. This method lists
all chassis and builds the resource provider information needed by Placement.
This information is stored in the "Chassis" registers, in
"external_ids:ovn-cms-options", with the same format as retrieved from the
local "Open_vSwitch" registers from each chassis.

The second method to update the Placement information is when a "Chassis"
registers is updated. The ``OVNClientPlacementExtension`` extension registers
an event handler that attends the OVN SB "Chassis" bandwidth configuration
changes. This event handler builds a ``PlacementState`` instance and sends it
to the Placement API. If a new chassis is added or an existing one changes its
resource provider configuration, this event updates it in the Placement
database.

Propagation of resource information
-----------------------------------

The flow of information is different for available and used resources.

The authentic source of available resources is neutron agent configuration -
where the resources actually exist, as described in the agent configuration
sections above. This information is propagated in the following chain:
``neutron-l2-agent -> neutron-server -> Placement``.

From neutron agent to server the information is included in the
``configurations`` field of the agent heartbeat message sent on the message
queue periodically.

.. code-block:: console

    # as admin
    $ openstack network agent list --agent-type open-vswitch --host devstack0
    +--------------------------------------+--------------------+-----------+-------------------+-------+-------+---------------------------+
    | ID                                   | Agent Type         | Host      | Availability Zone | Alive | State | Binary                    |
    +--------------------------------------+--------------------+-----------+-------------------+-------+-------+---------------------------+
    | 5e57b85f-b017-419a-8745-9c406e149f9e | Open vSwitch agent | devstack0 | None              | :-)   | UP    | neutron-openvswitch-agent |
    +--------------------------------------+--------------------+-----------+-------------------+-------+-------+---------------------------+

    # output shortened and pretty printed
    # note: 'configurations' on the wire, but 'configuration' in the cli
    $ openstack network agent show -f value -c configuration 5e57b85f-b017-419a-8745-9c406e149f9e
    {'bridge_mappings': {'physnet0': 'br-physnet0'},
     'resource_provider_bandwidths': {'br-physnet0': {'egress': 10000000,
                                                      'ingress': 10000000}},
     'resource_provider_inventory_defaults': {'allocation_ratio': 1.0,
                                              'min_unit': 1,
                                              'reserved': 0,
                                              'step_size': 1},
     ...
    }

Re-reading the resource related subset of configuration on ``SIGHUP`` is not
implemented. The agent must be restarted to pick up and send changed
configuration.

Neutron-server propagates the information further to Placement for
the resources of each agent via Placement's HTTP REST API. To avoid
overloading Placement this synchronization generally does not happen on
every received heartbeat message. Instead the re-synchronization of the
resources of one agent is triggered by:

* The creation of a network agent record (as queried by ``openstack network
  agent list``). Please note that deleting an agent record and letting the
  next heartbeat to re-create it can be used to trigger synchronization
  without restarting an agent.
* The restart of that agent (technically ``start_flag`` being present in the
  heartbeat message).

Both of these can be used by an admin to force a re-sync if needed.

The success of a synchronization attempt from neutron-server to Placement is
persisted into the relevant agent's ``resources_synced`` attribute. For
example:

.. code-block:: console

    # as admin
    $ openstack network agent show -f value -c resources_synced 5e57b85f-b017-419a-8745-9c406e149f9e
    True

``resources_synced`` may take the value True, False and None:

* None: No sync was attempted (normal for agents not reporting
  Placement-backed resources).
* True: The last sync attempt was completely successful.
* False: The last sync attempt was partially or utterly unsuccessful.

In case ``resources_synced`` is not True for an agent, neutron-server
does try to re-sync on receiving every heartbeat message from that
agent. Therefore it should be able to recover from transient errors
of Neutron-Placement communication (e.g. Placement being started later
than Neutron).

It is important to note that the restart of neutron-server does not trigger
any kind of re-sync to Placement (to avoid an update storm).

As mentioned before, the information flow for resources requested and
(if proper) allocated is different. It involves a conversation between Nova,
Neutron and Placement.

#. Neutron exposes a port's resource needs in terms of resource classes and
   traits as the admin-only ``resource_request`` attribute of that port.

#. Nova reads this and `incorporates it as a numbered request group
   <https://docs.openstack.org/nova/latest/admin/port_with_resource_request.html#resource-group-policy>`_
   into the cloud servers overall allocation candidate request to Placement.

#. Nova selects (schedules) and allocates one candidate returned by Placement.

#. Nova informs Neutron when binding the port of which physical network
   interface resource provider had been selected for the port's resource
   request in the ``binding:profile.allocation`` sub-attribute of that port.

For details please see `slides 13-15
<https://www.openstack.org/videos/summits/berlin-2018/guaranteed-minimum-bandwidth-feature-demo>`_
of a (pre-release) demo that was presented on the Berlin Summit in November
2018.

Sample usage
------------

Physnets and QoS policies (together with their rules) are usually pre-created
by a cloud admin:

.. code-block:: console

    # as admin

    $ openstack network create net0 \
        --provider-network-type vlan \
        --provider-physical-network physnet0 \
        --provider-segment 100

    $ openstack subnet create subnet0 \
        --network net0 \
        --subnet-range 10.0.4.0/24

    $ openstack network qos policy create policy0

    $ openstack network qos rule create policy0 \
        --type minimum-bandwidth \
        --min-kbps 1000000 \
        --egress

    $ openstack network qos rule create policy0 \
        --type minimum-bandwidth \
        --min-kbps 1000000 \
        --ingress

Then a normal user can use the pre-created policy to create ports and boot
servers with those ports:

.. code-block:: console

    # as an unprivileged user

    # an ordinary soft-switched port: ``--vnic-type normal`` is the default
    $ openstack port create port-normal-qos \
        --network net0 \
        --qos-policy policy0

    # alternatively an SR-IOV port, unused in this example
    $ openstack port create port-direct-qos \
        --network net0 \
        --vnic-type direct \
        --qos-policy policy0

    $ openstack server create server0 \
        --flavor cirros256 \
        --image cirros-0.5.1-x86_64-disk \
        --port port-normal-qos

On Healing of Allocations
-------------------------

Since Placement carries a global view of a cloud deployment's resources
(what is available, what is used) it may in some conditions get out of sync
with reality.

One important case is when the data-plane-only Minimum Guaranteed Bandwidth
feature was used before Stein (first released in Newton). Since before Stein
guarantees were not enforced during server placement the available resources
may have become overallocated without notice. In this case Placement's view
and the reality of resource usage should be made consistent during/after an
upgrade to Stein.

Another case stems from OpenStack not having distributed transactions to
allocate resources provided by multiple OpenStack components (here Nova and
Neutron). There are known race conditions in which Placement's view may get
out of sync with reality. The design knowingly minimizes the race condition
windows, but there are known problems:

* If a QoS policy is modified after Nova read a port's ``resource_request``
  but before the port is bound its state before the modification will be
  applied.
* If a bound port with a resource allocation is deleted. The port's allocation
  is leaked. `<https://bugs.launchpad.net/nova/+bug/1820588>`_

.. note::

  Deleting a bound port has no known use case. Please consider detaching
  the interface first by ``openstack server remove port`` instead.

Incorrect allocations may be fixed by:

* Moving the server, which will delete the wrong allocation and create the
  correct allocation as soon as move operations are implemented (not in Stein
  unfortunately). Moving servers fixes local overallocations.
* The need for an upgrade-helper allocation healing tool is being tracked in
  `bug 1819923 <https://bugs.launchpad.net/nova/+bug/1819923>`_.
* Manually, by using `openstack resource provider allocation set
  <https://docs.openstack.org/osc-placement/latest/cli/index.html#resource-provider-allocation-set>`_
  /`delete <https://docs.openstack.org/osc-placement/latest/cli/index.html#resource-provider-allocation-delete>`_.

Debugging
---------

* Are all components running at least the Stein release?

* Is the ``placement`` service plugin enabled in neutron-server?

* Is ``resource_provider_bandwidths`` configured for the relevant neutron
  agent?

* Is ``resource_provider_bandwidths`` aligned with ``bridge_mappings`` or
  ``physical_device_mappings``?

* Was the agent restarted since changing the configuration file?

* Is ``resource_provider_bandwidths`` reaching neutron-server?

.. code-block:: console

    # as admin
    $ openstack network agent show ... | grep configurations

Please find an example in section `Propagation of resource information`_.

* Did neutron-server successfully sync to Placement?

.. code-block:: console

    # as admin
    $ openstack network agent show ... | grep resources_synced

Please find an example in section `Propagation of resource information`_.

* Is the resource provider tree correct? Is the root a compute host? One level
  below the agents? Two levels below the physical network interfaces?

.. code-block:: console

    $ openstack --os-placement-api-version 1.17 resource provider list
    +--------------------------------------+------------------------------------------+------------+--------------------------------------+--------------------------------------+
    | uuid                                 | name                                     | generation | root_provider_uuid                   | parent_provider_uuid                 |
    +--------------------------------------+------------------------------------------+------------+--------------------------------------+--------------------------------------+
    | 3b36d91e-bf60-460f-b1f8-3322dee5cdfd | devstack0                                |          2 | 3b36d91e-bf60-460f-b1f8-3322dee5cdfd | None                                 |
    | 4a8a819d-61f9-5822-8c5c-3e9c7cb942d6 | devstack0:NIC Switch agent               |          0 | 3b36d91e-bf60-460f-b1f8-3322dee5cdfd | 3b36d91e-bf60-460f-b1f8-3322dee5cdfd |
    | 1c7e83f0-108d-5c35-ada7-7ebebbe43aad | devstack0:NIC Switch agent:ens5          |          2 | 3b36d91e-bf60-460f-b1f8-3322dee5cdfd | 4a8a819d-61f9-5822-8c5c-3e9c7cb942d6 |
    | 89ca1421-5117-5348-acab-6d0e2054239c | devstack0:Open vSwitch agent             |          0 | 3b36d91e-bf60-460f-b1f8-3322dee5cdfd | 3b36d91e-bf60-460f-b1f8-3322dee5cdfd |
    | f9c9ce07-679d-5d72-ac5f-31720811629a | devstack0:Open vSwitch agent:br-physnet0 |          2 | 3b36d91e-bf60-460f-b1f8-3322dee5cdfd | 89ca1421-5117-5348-acab-6d0e2054239c |
    +--------------------------------------+------------------------------------------+------------+--------------------------------------+--------------------------------------+

* Does Placement have the expected traits?

.. code-block:: console

    # as admin
    $ openstack --os-placement-api-version 1.17 trait list | awk '/CUSTOM_/ { print $2 }' | sort
    CUSTOM_PHYSNET_PHYSNET0
    CUSTOM_VNIC_TYPE_DIRECT
    CUSTOM_VNIC_TYPE_DIRECT_PHYSICAL
    CUSTOM_VNIC_TYPE_MACVTAP
    CUSTOM_VNIC_TYPE_NORMAL

* Do the physical network interface resource providers have the proper trait
  associations and inventories?

.. code-block:: console

    # as admin
    $ openstack --os-placement-api-version 1.17 resource provider trait list RP-UUID
    $ openstack --os-placement-api-version 1.17 resource provider inventory list RP-UUID

* Does the QoS policy have a ``minimum-bandwidth`` rule?

* Does the port have the proper policy?

* Does the port have a ``resource_request``?

.. code-block:: console

    # as admin
    $ openstack port show port-normal-qos | grep resource_request

* Was the server booted with a port (as opposed to a network)?

* Did nova allocate resources for the server in Placement?

.. code-block:: console

    # as admin
    $ openstack --os-placement-api-version 1.17 resource provider allocation show SERVER-UUID

* Does the allocation have a part on the expected physical network interface
  resource provider?

.. code-block:: console

    # as admin
    $ openstack --os-placement-api-version 1.17 resource provider show --allocations RP-UUID

* Did placement manage to produce an allocation candidate list to nova during
  scheduling?

* Did nova manage to schedule the server?

* Did nova tell neutron which physical network interface resource provider
  was allocated to satisfy the bandwidth request?

.. code-block:: console

    # as admin
    $ openstack port show port-normal-qos | grep binding.profile.*allocation

* Did neutron manage to bind the port?

Links
-----

* Pre-release `feature demo <https://www.openstack.org/videos/summits/berlin-2018/guaranteed-minimum-bandwidth-feature-demo>`_ presented on the Berlin Summit in November 2018

* Nova documentation on using a port with ``resource_request``

  * `API Guide <https://docs.openstack.org/api-guide/compute/port_with_resource_request.html>`_
  * `Admin Guide <https://docs.openstack.org/nova/latest/admin/port_with_resource_request.html>`_

* Neutron spec: QoS minimum bandwidth allocation in Placement API

  * `on specs.openstack.org <https://specs.openstack.org/openstack/neutron-specs/specs/rocky/minimum-bandwidth-allocation-placement-api.html>`__
  * `on review.opendev.org <https://review.opendev.org/508149>`__

* Nova spec: Network Bandwidth resource provider

  * `on specs.openstack.org
    <https://specs.openstack.org/openstack/nova-specs/specs/stein/approved/bandwidth-resource-provider.html>`__
  * `on review.opendev.org
    <https://review.opendev.org/502306>`__

* Relevant OpenStack Networking API references

  * https://docs.openstack.org/api-ref/network/v2/#agent-resources-synced-extension
  * https://docs.openstack.org/api-ref/network/v2/#port-resource-request
  * https://docs.openstack.org/api-ref/network/v2/#qos-minimum-bandwidth-rules

* Microversion histories

  * `Compute 2.72
    <https://docs.openstack.org/nova/latest/reference/api-microversion-history.html#maximum-in-stein>`_
  * `Placement 1.29
    <https://docs.openstack.org/placement/latest/placement-api-microversion-history.html#support-allocation-candidates-with-nested-resource-providers>`_

* Implementation

  * `on review.opendev.org
    <https://review.opendev.org/#/q/topic:minimum-bandwidth-allocation-placement-api+OR+topic:bp/bandwidth-resource-provider>`_

* Known Bugs

  * `Missing tool to heal allocations
    <https://bugs.launchpad.net/nova/+bug/1819923>`_
  * `Bandwidth resource is leaked
    <https://bugs.launchpad.net/nova/+bug/1820588>`_
