Quality of Service (QoS): Guaranteed Minimum Packet Rate
========================================================

Similarly to how bandwidth can be a limiting factor of a network interface,
packet processing capacity tend to be a limiting factor of the soft switching
solutions like OVS. At the same time certain applications are dependent on not
just guaranteed bandwidth, but also on guaranteed packet rate to function
properly. OpenStack already supports bandwidth guarantees via the
minimum bandwidth QoS policy rules, which is described in detail in
:doc:`Quality of Service (QoS): Guaranteed Minimum Bandwidth
<config-qos-min-bw>`. It's recommended to read Guaranteed Minimum Bandwidth
guide first, but it's not strictly required.

Just like :doc:`Quality of Service (QoS): Guaranteed Minimum Bandwidth
<config-qos-min-bw>` guide, this chapter does not aim to replace Nova or
Placement documentation in any way, but gives a brief overview of the feature
and explains how it can be configured.

In a similar way to guaranteed bandwidth, we can distinguish two levels of
enforcement for guaranteeing packet processing capacity constraint:

* placement: Avoiding over-subscription when placing (scheduling) VMs and their
  ports.

* data plane: Enforcing the guarantee on the soft switch

.. note::

    At the time of writing this guide, only placement enforcement is supported.
    For detailed list of supported enforcement types and backends, please refer
    to :doc:`QoS configuration chapter of the Networking Guide <config-qos>`.

The solution needs to differentiate between two different deployment scenarios:

1) The packet processing functionality is implemented on the compute host CPUs
   and therefore packets processed from both ingress and egress directions are
   handled by the same set of CPU cores. This is the case in the
   non-hardware-offloaded OVS deployments. In this scenario OVS represents a
   single packet processing resource pool, which is represented with a
   single resource class called ``NET_PACKET_RATE_KILOPACKET_PER_SEC``.

2) The packet processing functionality is implemented in a specialized hardware
   where the incoming and outgoing packets are handled by independent
   hardware resources. This is the case for hardware-offloaded OVS. In this
   scenario a single OVS has two independent resource pools one for the
   incoming packets and one for the outgoing packets. Therefore these needs to
   be represented with two different resource classes
   ``NET_PACKET_RATE_EGR_KILOPACKET_PER_SEC`` and
   ``NET_PACKET_RATE_IGR_KILOPACKET_PER_SEC``.

Limitations
-----------

Since Guaranteed Minimum Packet Rate and Guaranteed Minimum Bandwidth features
have a lot in common, they also share certain limitations.

* A pre-created port with a ``minimum-packet-rate`` rule must be passed
  when booting a server (``openstack server create``). Passing a network
  with a minimum-packet-rate rule at boot is not supported because of
  technical reasons (in this case the port is created too late for
  Neutron to affect scheduling).

* Changing the guarantee of a QoS policy (adding/deleting a
  ``minimum_packet_rate`` rule, or changing the ``min_kpps`` field of a
  ``minimum_packet_rate`` rule) is only possible while the policy is not in
  effect. That is ports of the QoS policy are not yet bound by Nova. Requests
  to change guarantees of in-use policies are rejected.

* Changing the QoS policy of the port with new ``minimum_packet_rate`` rules
  changes placement ``allocations`` from Yoga release.
  If the VM was booted with port without QoS policy and ``minimum_packet_rate``
  rules the port update succeeds but placement allocations will not change.
  The same is true if the port had no allocation record in Placement before
  QoS policy update. But if the VM was booted with a port with QoS policy and
  ``minimum_packet_rate`` rules the update is possible and the allocations are
  changed in placement as well.

.. note::

  As it is possible to update a port to remove the QoS policy, updating it
  back to have QoS policy with ``minimum_packet_rate`` rule will not result in
  ``placement allocation`` record. In this case only dataplane enforcement will
  happen.

.. note::

  Updating the ``minimum_packet_rate`` rule of a QoS policy that is attached
  to a port which is bound to a VM is still not possible.

* When QoS is used with a trunk, Placement enforcement is applied only to the
  trunk's parent port. Subports are not going to have Placement allocation.
  As a workaround, parent port QoS policy should take into account subports
  needs and request enough minimum packet rate resources to accommodate every
  port in the trunk.

Placement pre-requisites
------------------------

Placement must support `microversion 1.36
<https://docs.openstack.org/placement/latest/placement-api-microversion-history.html#support-same-subtree-queryparam-on-get-allocation-candidates>`_.
This was first released in Train.

Nova pre-requisites
-------------------

Nova must support top of `microversion 2.72
<https://docs.openstack.org/nova/latest/reference/api-microversion-history.html#maximum-in-stein>`_,
additionally the Nova Xena release is needed to support the new
``port-resource-request-groups`` Neutron API extension.

Not all Nova virt drivers are supported, please refer to the
`Virt Driver Support section of the Nova Admin Guide
<https://docs.openstack.org/nova/latest/admin/port_with_resource_request.html#virt-driver-support>`_.

Neutron pre-requisites
----------------------

Neutron must support the following API extensions:

* ``qos-pps-minimum``
* ``port-resource-request-groups``

These were all first released in Yoga.

Neutron DB sanitization
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``resource_request`` field of the Neutron port is used to express the
resource needs of the port. The information in this field is calculated from
the QoS policy rules attached to the port. Initially, only the minimum
bandwidth rule was used as a source of requested resources. The format of
``resource_request`` looked like this:

.. code-block:: console

  {
      "required": [<CUSTOM_PHYSNET_ traits>, <CUSTOM_VNIC_TYPE traits>],
      "resources":
      {
          <NET_BW_[E|I]GR_KILOBIT_PER_SEC resource class name>:
              <requested bandwidth amount from the QoS policy>
      }
  },

This structure allowed to describe only one group of resources and traits,
which was sufficient at the time. However, with the introduction of QoS minimum
packet rate rule, ports can now have multiple sources of requested resources
and traits. Because of that, the format of ``resource_request`` field was
incapable of expressing such request and it had to be changed.

To solve this issue, ``port-resource-request-groups`` extension was
added in Neutron Yoga release. It provides support for the new format of
``resource_request`` field, that allows to request multiple groups of
resources and traits from the same RP subtree. The new format looks like this:

.. code-block:: console

  {
      "request_groups":
      [
          {
              "id": <min-pps-group-uuid>
              "required": [<CUSTOM_VNIC_TYPE traits>],
              "resources":
              {
                  NET_PACKET_RATE_[E|I]GR_KILOPACKET_PER_SEC:
                      <amount requested via the QoS policy>
              }
          },
          {
              "id": <min-bw-group-uuid>
              "required": [<CUSTOM_PHYSNET_ traits>,
                           <CUSTOM_VNIC_TYPE traits>],
              "resources":
              {
                  <NET_BW_[E|I]GR_KILOBIT_PER_SEC resource class name>:
                      <requested bandwidth amount from the QoS policy>
              }
          }
      ],
      "same_subtree":
      [
          <min-pps-group-uuid>,
          <min-bw-group-uuid>
      ]
  }

The main drawback about the new structure of ``resource_request`` field is lack
of backwards compatibility. This can cause issues if ``ml2_port_bindings``
table in Neutron DB contains port bindings that were created before the
introduction of ``port-resource-request-groups`` extension. Because
``port-resource-request-groups`` extension is enabled by default in Yoga
release, it's necessary to perform DB sanitization before upgrading Neutron to
Yoga.

DB sanitization will ensure that every row of ``ml2_port_bindings`` table
uses the new format. Upgrade check can be run before DB sanitization, to see
if there are any rows in the DB that require sanitization.

.. code-block:: console

    $ neutron-status upgrade check
    # If 'Port Binding profile sanity check' fails, DB sanitization is needed
    $ neutron-sanitize-port-binding-profile-allocation --config-file /etc/neutron/neutron.conf

Supported drivers and agents
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In release Yoga the following agent-based ML2 mechanism drivers are
supported:

* Open vSwitch (``openvswitch``) vnic_types: ``normal``, ``direct``

neutron-server config
~~~~~~~~~~~~~~~~~~~~~

QoS minimum packet rate rule requires exactly the same configuration in the
``neutron-server`` as QoS minimum bandwidth rule. Please refer to
``neutron-server config`` section of
:doc:`Quality of Service (QoS): Guaranteed Minimum Bandwidth guide
<config-qos-min-bw>` for more details.

neutron-openvswitch-agent config
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Set the agent configuration as the authentic source of the resources available.
Depending on OVS deployment type, packet processing capacity can be configured
with:

* :oslo.config:option:`ovs.resource_provider_packet_processing_without_direction`
  Format for this option is ``<hypervisor>:<packet_rate>``. This option should
  be used for non-hardware-offloaded OVS deployments.

* :oslo.config:option:`ovs.resource_provider_packet_processing_with_direction`

  Format for this option is
  ``<hypervisor>:<egress_packet_rate>:<ingress_packet_rate>``. You may set only
  one direction and omit the other. This option should be used for
  hardware-offloaded OVS deployments.

Regardless if direction-less or direction-oriented packet processing mode is
used, configuration is always applied to the whole OVS instance.

.. note::

    ``egress`` / ``ingress`` is meant from the VM point of view.
    That is ``egress`` = cloud server upload, ``ingress`` = download.

    Egress and ingress available packet rate values are in ``kilo packet/sec
    (kpps)``.

    Direction-less and direction-oriented modes are mutually exclusive options.
    Only one can be used at a time.

    The hypervisor name is optional, and needs to be set only in the rare case
    cases. For more information, please refer to Neutron agent documentation.

If desired, resource provider inventory fields can be tweaked on a
per-agent basis by setting
:oslo.config:option:`ovs.resource_provider_packet_processing_inventory_defaults`.
Valid values are all the
`optional parameters of the update resource provider inventory call
<https://docs.openstack.org/api-ref/placement/?expanded=update-resource-provider-inventory-detail#update-resource-provider-inventory>`_.

``/etc/neutron/plugins/ml2/ovs_agent.ini`` (on compute and network nodes):

.. code-block:: ini

    [ovs]
    resource_provider_packet_processing_with_direction = :10000000:10000000,...
    #resource_provider_packet_processing_inventory_defaults = step_size:1000,...


Propagation of resource information
-----------------------------------

Propagation of resource information is explained in detail in
:doc:`Quality of Service (QoS): Guaranteed Minimum Bandwidth guide
<config-qos-min-bw>`.

Sample usage
------------

Network and QoS policies (together with their rules) are usually pre-created
by a cloud admin:

.. code-block:: console

    # as admin

    $ openstack network create net0

    $ openstack subnet create subnet0 \
        --network net0 \
        --subnet-range 10.0.4.0/24

    $ openstack network qos policy create policy0

    $ openstack network qos rule create policy0 \
        --type minimum-packet-rate \
        --min-kpps 1000000 \
        --egress

    $ openstack network qos rule create policy0 \
        --type minimum-packet-rate \
        --min-kpps 1000000 \
        --ingress

Then a normal user can use the pre-created policy to create ports and boot
servers with those ports:

.. code-block:: console

    # as an unprivileged user

    # an ordinary soft-switched port: ``--vnic-type normal`` is the default
    $ openstack port create port-normal-qos \
        --network net0 \
        --qos-policy policy0

    $ openstack server create server0 \
        --os-compute-api-version 2.72 \
        --flavor cirros256 \
        --image cirros-0.5.2-x86_64-disk \
        --port port-normal-qos

On Healing of Allocations
-------------------------

Since Placement carries a global view of a cloud deployment's resources
(what is available, what is used) it may in some conditions get out of sync
with reality.

One important case stems from OpenStack not having distributed transactions to
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
  correct allocation. Moving servers fixes local overallocations.
* With `placement heal_allocations
  <https://docs.openstack.org/nova/latest/cli/nova-manage.html#placement-heal-allocations>`_
  tool.
* Manually, by using `openstack resource provider allocation set
  <https://docs.openstack.org/osc-placement/latest/cli/index.html#resource-provider-allocation-set>`_
  /`delete <https://docs.openstack.org/osc-placement/latest/cli/index.html#resource-provider-allocation-delete>`_.

Debugging
---------

* Is Nova running at least Xena release and Neutron at least the Yoga release?

* Are ``qos-pps-minimum`` and ``port-resource-request-groups`` extensions
  available?

.. code-block:: console

    $ openstack extension show qos-pps-minimum
    $ openstack extension show port-resource-request-groups

* Is the ``placement`` service plugin enabled in neutron-server?

* Is ``resource_provider_packet_processing_with_direction`` or
  ``resource_provider_packet_processing_without_direction`` configured for the
  relevant neutron agent?

* Was the agent restarted since changing the configuration file?

* Is ``resource_provider_packet_processing_with_direction`` or
  ``resource_provider_packet_processing_without_direction`` reaching
  neutron-server?

.. code-block:: console

    # as admin
    $ openstack network agent show ... -c configuration -f json

Please find an example in section `Propagation of resource information`_.

* Did neutron-server successfully sync to Placement?

.. code-block:: console

    # as admin
    $ openstack network agent show ... | grep resources_synced

Please find an example in section `Propagation of resource information`_.

* Is the resource provider tree correct? Is the root a compute host? One level
  below the agents?

.. code-block:: console

    $ openstack --os-placement-api-version 1.17 resource provider list
    +--------------------------------------+------------------------------------------+------------+--------------------------------------+--------------------------------------+
    | uuid                                 | name                                     | generation | root_provider_uuid                   | parent_provider_uuid                 |
    +--------------------------------------+------------------------------------------+------------+--------------------------------------+--------------------------------------+
    | 3b36d91e-bf60-460f-b1f8-3322dee5cdfd | devstack0                                |          2 | 3b36d91e-bf60-460f-b1f8-3322dee5cdfd | None                                 |
    | 89ca1421-5117-5348-acab-6d0e2054239c | devstack0:Open vSwitch agent             |          0 | 3b36d91e-bf60-460f-b1f8-3322dee5cdfd | 3b36d91e-bf60-460f-b1f8-3322dee5cdfd |
    +--------------------------------------+------------------------------------------+------------+--------------------------------------+--------------------------------------+

* Does Placement have the expected traits?

.. code-block:: console

    # as admin
    $ openstack --os-placement-api-version 1.17 trait list | awk '/CUSTOM_/ { print $2 }' | sort
    CUSTOM_VNIC_TYPE_NORMAL
    CUSTOM_VNIC_TYPE_SMART_NIC
    CUSTOM_VNIC_TYPE_VDPA

* Do the OVS agent resource provider have the proper trait associations and
  inventories?

.. code-block:: console

    # as admin
    $ openstack --os-placement-api-version 1.17 resource provider trait list <RP-UUID>
    $ openstack --os-placement-api-version 1.17 resource provider inventory list <RP-UUID>

* Does the QoS policy have a ``minimum-packet-rate`` rule?

* Does the port have the proper policy?

* Does the port have a ``resource_request``?

.. code-block:: console

    # as admin
    $ openstack port show port-normal-qos | grep resource_request

* Was the server booted with a port (as opposed to a network)?

* Did nova allocate resources for the server in Placement?

.. code-block:: console

    # as admin
    $ openstack --os-placement-api-version 1.17 resource provider allocation show <SERVER-UUID>

* Does the allocation have a part on the expected OVS agent resource provider?

.. code-block:: console

    # as admin
    $ openstack --os-placement-api-version 1.17 resource provider show --allocations <RP-UUID>

* Did placement manage to produce an allocation candidate list to nova during
  scheduling?

* Did nova manage to schedule the server?

* Did nova tell neutron which OVS agent resource provider was allocated to
  satisfy the packet rate request?

.. code-block:: console

    # as admin
    $ openstack port show port-normal-qos | grep binding.profile.*allocation

* Did neutron manage to bind the port?

Links
-----

* Nova documentation on using a port with ``resource_request``

  * `API Guide <https://docs.openstack.org/api-guide/compute/port_with_resource_request.html>`_
  * `Admin Guide <https://docs.openstack.org/nova/latest/admin/port_with_resource_request.html>`_

* Neutron spec: QoS minimum guaranteed packet rate

  * `on specs.openstack.org <https://specs.openstack.org/openstack/neutron-specs/specs/xena/qos-minimum-guaranteed-packet-rate.html>`__
  * `on review.opendev.org <https://review.opendev.org/785236>`__

* Nova spec: QoS minimum guaranteed packet rate

  * `on specs.openstack.org
    <https://specs.openstack.org/openstack/nova-specs/specs/xena/approved/qos-minimum-guaranteed-packet-rate.html>`__
  * `on review.opendev.org
    <https://review.opendev.org/785014>`__

* Relevant OpenStack Networking API references

  * https://docs.openstack.org/api-ref/network/v2/#agent-resources-synced-extension
  * https://docs.openstack.org/api-ref/network/v2/#port-resource-request
  * https://docs.openstack.org/api-ref/network/v2/#port-resource-request-groups
  * https://docs.openstack.org/api-ref/network/v2/#qos-minimum-packet-rate-rules

* Microversion histories

  * `Compute 2.72
    <https://docs.openstack.org/nova/latest/reference/api-microversion-history.html#maximum-in-stein>`_
  * `Placement 1.36
    <https://docs.openstack.org/placement/latest/placement-api-microversion-history.html#support-same-subtree-queryparam-on-get-allocation-candidates>`_

* Implementation

  * `on review.opendev.org
    <https://review.opendev.org/#/q/topic:bp/qos-minimum-guaranteed-packet-rate">`_

* Known Bugs

  * `Bandwidth resource is leaked
    <https://bugs.launchpad.net/nova/+bug/1820588>`_ this issue also affects
    packet rate resources.
