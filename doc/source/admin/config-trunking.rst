.. _config-trunking:

========
Trunking
========

The network trunk service allows multiple networks to be connected to an
instance using a single virtual NIC (vNIC). Multiple networks can be presented
to an instance by connecting it to a single port.

Operation
~~~~~~~~~

Network trunking consists of a service plug-in and a set of drivers that
manage trunks on different layer-2 mechanism drivers. Users can create a
port, associate it with a trunk, and launch an instance on that port. Users
can dynamically attach and detach additional networks without disrupting
operation of the instance.

Every trunk has a parent port and can have any number of subports.
The parent port is the port that the trunk is associated with. Users
create instances and specify the parent port of the trunk when launching
instances attached to a trunk.

The network presented by the subport is the network of the associated
port. When creating a subport, a ``segmentation-id`` may be required by
the driver. ``segmentation-id`` defines the segmentation ID on which the
subport network is presented to the instance. ``segmentation-type`` may be
required by certain drivers like OVS. At this time the following
``segmentation-type`` values are supported:

* ``vlan`` uses VLAN for segmentation.
* ``inherit`` uses the ``segmentation-type`` from the network the subport
  is connected to if no ``segmentation-type`` is specified for the subport.
  Note that using the ``inherit`` type requires the ``provider`` extension
  to be enabled and only works when the connected network's
  ``segmentation-type`` is ``vlan``.

.. note::

   The ``segmentation-type`` and ``segmentation-id`` parameters are optional
   in the Networking API. However, all drivers as of the Newton release
   require both to be provided when adding a subport to a trunk. Future
   drivers may be implemented without this requirement.

The ``segmentation-type`` and ``segmentation-id`` specified by the user on the
subports is intentionally decoupled from the ``segmentation-type`` and ID of
the networks. For example, it is possible to configure the Networking service
with ``tenant_network_types = vxlan`` and still create subports with
``segmentation_type = vlan``. The Networking service performs remapping as
necessary.

Example configuration
~~~~~~~~~~~~~~~~~~~~~

The ML2 plug-in supports trunking with the following mechanism drivers:

* Open vSwitch (OVS)
* Linux bridge
* Open Virtual Network (OVN)

When using a ``segmentation-type`` of ``vlan``, the OVS and Linux bridge
drivers present the network of the parent port as the untagged VLAN and all
subports as tagged VLANs.

Controller node
---------------

* In the ``neutron.conf`` file, enable the trunk service plug-in:

  .. code-block:: ini

     [DEFAULT]
     service_plugins = trunk

Verify service operation
------------------------

#. Source the administrative project credentials and list the enabled
   extensions.
#. Use the command :command:`openstack extension list --network` to verify
   that the ``Trunk Extension`` and ``Trunk port details`` extensions are
   enabled.

Workflow
--------

At a high level, the basic steps to launching an instance on a trunk are
the following:

#. Create networks and subnets for the trunk and subports
#. Create the trunk
#. Add subports to the trunk
#. Launch an instance on the trunk

Create networks and subnets for the trunk and subports
------------------------------------------------------

Create the appropriate networks for the trunk and subports that will be added
to the trunk. Create subnets on these networks to ensure the desired layer-3
connectivity over the trunk.

Create the trunk
----------------

* Create a parent port for the trunk.

  .. code-block:: console

     $ openstack port create --network project-net-A trunk-parent
     +-------------------+-------------------------------------------------------------------------+
     | Field             | Value                                                                   |
     +-------------------+-------------------------------------------------------------------------+
     | admin_state_up    | UP                                                                      |
     | binding_vif_type  | unbound                                                                 |
     | binding_vnic_type | normal                                                                  |
     | fixed_ips         | ip_address='192.0.2.7',subnet_id='8b957198-d3cf-4953-8449-ad4e4dd712cc' |
     | id                | 73fb9d54-43a7-4bb1-a8dc-569e0e0a0a38                                    |
     | mac_address       | fa:16:3e:dd:c4:d1                                                       |
     | name              | trunk-parent                                                            |
     | network_id        | 1b47d3e7-cda5-48e4-b0c8-d20bd7e35f55                                    |
     | revision_number   | 1                                                                       |
     | tags              | []                                                                      |
     +-------------------+-------------------------------------------------------------------------+

* Create the trunk using ``--parent-port`` to reference the port from
  the previous step:

  .. code-block:: console

     $ openstack network trunk create --parent-port trunk-parent trunk1
     +-----------------+--------------------------------------+
     | Field           | Value                                |
     +-----------------+--------------------------------------+
     | admin_state_up  | UP                                   |
     | id              | fdf02fcb-1844-45f1-9d9b-e4c2f522c164 |
     | name            | trunk1                               |
     | port_id         | 73fb9d54-43a7-4bb1-a8dc-569e0e0a0a38 |
     | revision_number | 1                                    |
     | sub_ports       |                                      |
     +-----------------+--------------------------------------+

Add subports to the trunk
-------------------------

Subports can be added to a trunk in two ways: creating the trunk with subports
or adding subports to an existing trunk.

* Create trunk with subports:

  This method entails creating the trunk with subports specified at trunk
  creation.

  .. code-block:: console

     $ openstack port create --network project-net-A trunk-parent
     +-------------------+-------------------------------------------------------------------------+
     | Field             | Value                                                                   |
     +-------------------+-------------------------------------------------------------------------+
     | admin_state_up    | UP                                                                      |
     | binding_vif_type  | unbound                                                                 |
     | binding_vnic_type | normal                                                                  |
     | fixed_ips         | ip_address='192.0.2.7',subnet_id='8b957198-d3cf-4953-8449-ad4e4dd712cc' |
     | id                | 73fb9d54-43a7-4bb1-a8dc-569e0e0a0a38                                    |
     | mac_address       | fa:16:3e:dd:c4:d1                                                       |
     | name              | trunk-parent                                                            |
     | network_id        | 1b47d3e7-cda5-48e4-b0c8-d20bd7e35f55                                    |
     | revision_number   | 1                                                                       |
     | tags              | []                                                                      |
     +-------------------+-------------------------------------------------------------------------+

     $ openstack port create --network trunked-net subport1
     +-------------------+----------------------------------------------------------------------------+
     | Field             | Value                                                                      |
     +-------------------+----------------------------------------------------------------------------+
     | admin_state_up    | UP                                                                         |
     | binding_vif_type  | unbound                                                                    |
     | binding_vnic_type | normal                                                                     |
     | fixed_ips         | ip_address='198.51.100.8',subnet_id='2a860e2c-922b-437b-a149-b269a8c9b120' |
     | id                | 91f9dde8-80a4-4506-b5da-c287feb8f5d8                                       |
     | mac_address       | fa:16:3e:ba:f0:4d                                                          |
     | name              | subport1                                                                   |
     | network_id        | aef78ec5-16e3-4445-b82d-b2b98c6a86d9                                       |
     | revision_number   | 1                                                                          |
     | tags              | []                                                                         |
     +-------------------+----------------------------------------------------------------------------+

     $ openstack network trunk create \
       --parent-port trunk-parent \
       --subport port=subport1,segmentation-type=vlan,segmentation-id=100 \
       trunk1
     +----------------+-------------------------------------------------------------------------------------------------+
     | Field          | Value                                                                                           |
     +----------------+-------------------------------------------------------------------------------------------------+
     | admin_state_up | UP                                                                                              |
     | id             | 61d8e620-fe3a-4d8f-b9e6-e1b0dea6d9e3                                                            |
     | name           | trunk1                                                                                          |
     | port_id        | 73fb9d54-43a7-4bb1-a8dc-569e0e0a0a38                                                            |
     | revision_number| 1                                                                                               |
     | sub_ports      | port_id='73fb9d54-43a7-4bb1-a8dc-569e0e0a0a38', segmentation_id='100', segmentation_type='vlan' |
     | tags           | []                                                                                              |
     +----------------+-------------------------------------------------------------------------------------------------+

* Add subports to an existing trunk:

  This method entails creating a trunk, then adding subports to the trunk
  after it has already been created.

  .. code-block:: console

     $ openstack network trunk set --subport \
       port=subport1,segmentation-type=vlan,segmentation-id=100 \
       trunk1

  .. note::

     The command provides no output.

  .. code-block:: console

     $ openstack network trunk show trunk1
     +----------------+-------------------------------------------------------------------------------------------------+
     | Field          | Value                                                                                           |
     +----------------+-------------------------------------------------------------------------------------------------+
     | admin_state_up | UP                                                                                              |
     | id             | 61d8e620-fe3a-4d8f-b9e6-e1b0dea6d9e3                                                            |
     | name           | trunk1                                                                                          |
     | port_id        | 73fb9d54-43a7-4bb1-a8dc-569e0e0a0a38                                                            |
     | revision_number| 1                                                                                               |
     | sub_ports      | port_id='73fb9d54-43a7-4bb1-a8dc-569e0e0a0a38', segmentation_id='100', segmentation_type='vlan' |
     | tags           | []                                                                                              |
     +----------------+-------------------------------------------------------------------------------------------------+

Launch an instance on the trunk
-------------------------------

* Show trunk details to get the ``port_id`` of the trunk.

  .. code-block:: console

     $ openstack network trunk show trunk1
     +----------------+--------------------------------------+
     | Field          | Value                                |
     +----------------+--------------------------------------+
     | admin_state_up | UP                                   |
     | id             | 61d8e620-fe3a-4d8f-b9e6-e1b0dea6d9e3 |
     | name           | trunk                                |
     | port_id        | 73fb9d54-43a7-4bb1-a8dc-569e0e0a0a38 |
     | revision_number| 1                                    |
     | sub_ports      |                                      |
     | tags           | []                                   |
     +----------------+--------------------------------------+

* Launch the instance by specifying ``port-id`` using the value of ``port_id``
  from the trunk details. Launching an instance on a subport is not supported.

Using trunks and subports inside an instance
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When configuring instances to use a subport, ensure that the interface on the
instance is set to use the MAC address assigned to the port by the Networking
service. Instances are not made aware of changes made to the trunk after they
are active. For example, when a subport with a ``segmentation-type`` of
``vlan`` is added to a trunk, any operations specific to the instance operating
system that allow the instance to send and receive traffic on the new VLAN must
be handled outside of the Networking service.

When creating subports, the MAC address of the trunk parent port can be set
on the subport. This will allow VLAN subinterfaces inside an instance launched
on a trunk to be configured without explicitly setting a MAC address. Although
unique MAC addresses can be used for subports, this can present issues with
ARP spoof protections and the native OVS firewall driver. If the native OVS
firewall driver is to be used, we recommend that the MAC address of the parent
port be re-used on all subports.

Trunk states
~~~~~~~~~~~~

* ``ACTIVE``

  The trunk is ``ACTIVE`` when both the logical and physical resources have
  been created. This means that all operations within the Networking and
  Compute services have completed and the trunk is ready for use.

* ``DOWN``

  A trunk is ``DOWN`` when it is first created without an instance launched on
  it, or when the instance associated with the trunk has been deleted.

* ``DEGRADED``

  A trunk can be in a ``DEGRADED`` state when a temporary failure during
  the provisioning process is encountered. This includes situations where a
  subport add or remove operation fails. When in a degraded state, the trunk
  is still usable and some subports may be usable as well. Operations that
  cause the trunk to go into a ``DEGRADED`` state can be retried to fix
  temporary failures and move the trunk into an ``ACTIVE`` state.

* ``ERROR``

  A trunk is in ``ERROR`` state if the request leads to a conflict or an
  error that cannot be fixed by retrying the request. The ``ERROR`` status
  can be encountered if the network is not compatible with the trunk
  configuration or the binding process leads to a persistent failure. When
  a trunk is in ``ERROR`` state, it must be brought to a sane state
  (``ACTIVE``), or else requests to add subports will be rejected.

* ``BUILD``

  A trunk is in ``BUILD`` state while the resources associated with the
  trunk are in the process of being provisioned. Once the trunk and all of
  the subports have been provisioned successfully, the trunk transitions
  to ``ACTIVE``. If there was a partial failure, the trunk transitions
  to ``DEGRADED``.

  When ``admin_state`` is set to ``DOWN``, the user is blocked from performing
  operations on the trunk. ``admin_state`` is set by the user and should not be
  used to monitor the health of the trunk.

Limitations and issues
~~~~~~~~~~~~~~~~~~~~~~

* See `bugs <https://bugs.launchpad.net/neutron/+bugs?field.tag=trunk>`__ for
  more information.
