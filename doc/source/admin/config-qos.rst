.. _config-qos:

========================
Quality of Service (QoS)
========================

QoS is defined as the ability to guarantee certain network requirements
like bandwidth, latency, jitter, and reliability in order to satisfy a
Service Level Agreement (SLA) between an application provider and end
users.

Network devices such as switches and routers can mark traffic so that it is
handled with a higher priority to fulfill the QoS conditions agreed under
the SLA. In other cases, certain network traffic such as Voice over IP (VoIP)
and video streaming needs to be transmitted with minimal bandwidth
constraints. On a system without network QoS management, all traffic will be
transmitted in a "best-effort" manner making it impossible to guarantee service
delivery to customers.

QoS is an advanced service plug-in. QoS is decoupled from the rest of the
OpenStack Networking code on multiple levels and it is available through the
ml2 extension driver.

Details about the DB models, API extension, and use cases are out of the scope
of this guide but can be found in the
`Neutron QoS specification <https://specs.openstack.org/openstack/neutron-specs/specs/liberty/qos-api-extension.html>`_.


Supported QoS rule types
~~~~~~~~~~~~~~~~~~~~~~~~

QoS supported rule types are now available as ``VALID_RULE_TYPES`` in `QoS rule types
<https://opendev.org/openstack/neutron-lib/src/branch/master/neutron_lib/services/qos/constants.py>`_:

* bandwidth_limit: Bandwidth limitations on networks, ports or floating IPs.

* dscp_marking: Marking network traffic with a DSCP value.

* minimum_bandwidth: Minimum bandwidth constraints on certain types of traffic.

* minimum_packet_rate: Minimum packet rate constraints on certain types of traffic.


Any QoS driver can claim support for some QoS rule types
by providing a driver property called
``supported_rules``, the QoS driver manager will recalculate rule types
dynamically that the QoS driver supports. In the most simple case, the
property can be represented by a simple Python list defined on the class.

The following table shows the Networking back ends, QoS supported rules, and
traffic directions (from the VM point of view).

.. table:: **Networking back ends, supported rules, and traffic direction**

    ====================  =============================  =======================  ===================  ===================
     Rule \\ back end      Open vSwitch                  SR-IOV                   Linux bridge         OVN
    ====================  =============================  =======================  ===================  ===================
     Bandwidth limit       Egress \\ Ingress             Egress (1)               Egress \\ Ingress    Egress \\ Ingress
     Minimum bandwidth     Egress \\ Ingress (2)         Egress \\ Ingress (2)    -                    -
     Minimum packet rate   -                             -                        -                    -
     DSCP marking          Egress                        -                        Egress               Egress
    ====================  =============================  =======================  ===================  ===================

.. note::

   (1) Max burst parameter is skipped because it is not supported by the
       IP tool.
   (2) Placement based enforcement works for both egress and ingress directions,
       but dataplane enforcement depends on the backend.

.. table:: **Neutron backends, supported directions and enforcement types for Minimum Bandwidth rule**

    ============================  ====================  ====================  ==============  =====
     Enforcement type \ Backend    Open vSwitch          SR-IOV                Linux Bridge    OVN
    ============================  ====================  ====================  ==============  =====
     Dataplane                     Egress (3)            Egress (1)            -               -
     Placement                     Egress/Ingress (2)    Egress/Ingress (2)    -               -
    ============================  ====================  ====================  ==============  =====

.. note::

    (1) Since Newton
    (2) Since Stein
    (3) Open vSwitch minimum bandwidth support is only implemented for egress
        direction and only for networks without tunneled traffic (only VLAN and
        flat network types).

.. note:: The SR-IOV agent does not support dataplane enforcement for ports
  with ``direct-physical`` vnic_type. However since Yoga the Placement
  enforcement is supported for this vnic_type too.

.. table:: **Neutron backends, supported directions and enforcement types for Minimum Packet Rate rule**

    ============================  ==========================  ====================  ==============  =====
     Enforcement type \ Backend    Open vSwitch                SR-IOV                Linux Bridge    OVN
    ============================  ==========================  ====================  ==============  =====
     Dataplane                     -                           -                     -               -
     Placement                     Any(1)/Egress/Ingress (2)   -                     -               -
    ============================  ==========================  ====================  ==============  =====

.. note::

    (1) Minimum packet rate rule supports ``any`` direction that can be used
        with non-hardware-offloaded OVS deployments, where packets processed
        from both ingress and egress directions are handled by the same set of
        CPU cores.
    (2) Since Yoga.

For an ml2 plug-in, the list of supported QoS rule types and parameters is
defined as a common subset of rules supported by all active mechanism drivers.
A QoS rule is always attached to a QoS policy. When a rule is created or
updated:

* The QoS plug-in will check if this rule and parameters are supported by any
  active mechanism driver if the QoS policy is not attached to any port or
  network.

* The QoS plug-in will check if this rule and parameters are supported by the
  mechanism drivers managing those ports if the QoS policy is attached to any
  port or network.


Valid DSCP Marks
----------------

Valid DSCP mark values are even numbers between 0 and 56, except 2-6, 42, 44,
and 50-54.  The full list of valid DSCP marks is:

0, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30, 32, 34, 36, 38, 40, 46, 48, 56


L3 QoS support
~~~~~~~~~~~~~~

The Neutron L3 services have implemented their own QoS extensions. Currently
only bandwidth limit QoS is provided. This is the L3 QoS extension list:

* Floating IP bandwidth limit: the rate limit is applied per floating IP
  address independently.

* Gateway IP bandwidth limit: the rate limit is applied in the router namespace
  gateway port (or in the SNAT namespace in case of DVR edge router). The rate
  limit applies to the gateway IP; that means all traffic using this gateway IP
  will be limited. This rate limit does not apply to the floating IP traffic.


L3 services that provide QoS extensions:

* L3 router: implements the rate limit using `Linux TC
  <https://man7.org/linux/man-pages/man8/tc.8.html>`_.

* OVN L3: implements the rate limit using the `OVN QoS metering rules
  <https://man7.org/linux/man-pages/man8/ovn-nbctl.8.html#LOGICAL_SWITCH_QOS_RULE_COMMANDS>`_.


The following table shows the L3 service, the QoS supported extension, and
traffic directions (from the VM point of view) for **bandwidth limiting**.

.. table:: **L3 service, supported extension, and traffic direction**

    ====================  ===================  ===================
     Rule \\ L3 service    L3 router            OVN L3
    ====================  ===================  ===================
     Floating IP           Egress \\ Ingress    Egress \\ Ingress
     Gateway IP            Egress \\ Ingress    -
    ====================  ===================  ===================


Configuration
~~~~~~~~~~~~~

To enable the service on a cloud with the architecture described in
`Networking architecture <https://docs.openstack.org/security-guide/networking/architecture.html#openstack-networking-service-placement-on-physical-servers>`_,
follow the steps below:

On the controller nodes:

#. Add the QoS service to the ``service_plugins`` setting in
   ``/etc/neutron/neutron.conf``. For example:

   .. code-block:: none

      service_plugins = router,metering,qos

#. Optionally, set the needed ``notification_drivers`` in the ``[qos]``
   section in ``/etc/neutron/neutron.conf`` (``message_queue`` is the
   default).

#. Optionally, in order to enable the floating IP QoS extension ``qos-fip``,
   set the ``service_plugins`` option in ``/etc/neutron/neutron.conf`` to
   include both ``router`` and ``qos``. For example:

   .. code-block:: none

      service_plugins = router,qos

#. In ``/etc/neutron/plugins/ml2/ml2_conf.ini``, add ``qos`` to
   ``extension_drivers`` in the ``[ml2]`` section. For example:

   .. code-block:: ini

      [ml2]
      extension_drivers = port_security,qos

#. Edit the configuration file for the agent you are using and set the
   ``extensions`` to include ``qos`` in the ``[agent]`` section of the
   configuration file. The agent configuration file will reside in
   ``/etc/neutron/plugins/ml2/<agent_name>_agent.ini`` where ``agent_name``
   is the name of the agent being used (for example ``openvswitch``).
   For example:

   .. code-block:: ini

      [agent]
      extensions = qos

On the network and compute nodes:

#. Edit the configuration file for the agent you are using and set the
   ``extensions`` to include ``qos`` in the ``[agent]`` section of the
   configuration file. The agent configuration file will reside in
   ``/etc/neutron/plugins/ml2/<agent_name>_agent.ini`` where ``agent_name``
   is the name of the agent being used (for example ``openvswitch``).
   For example:

   .. code-block:: ini

      [agent]
      extensions = qos

#. Optionally, in order to enable QoS for floating IPs, set the ``extensions``
   option in the ``[agent]`` section of ``/etc/neutron/l3_agent.ini`` to
   include ``fip_qos``. If ``dvr`` is enabled, this has to be done for all the
   L3 agents. For example:

   .. code-block:: ini

      [agent]
      extensions = fip_qos

.. note::

   Floating IP associated to neutron port or to port forwarding
   can all have bandwidth limit since Stein release. These neutron server
   side and agent side extension configs will enable it once for all.

#. Optionally, in order to enable QoS for router gateway IPs, set the
   ``extensions`` option in the ``[agent]`` section of
   ``/etc/neutron/l3_agent.ini`` to include ``gateway_ip_qos``. Set this
   to all the ``dvr_snat`` or ``legacy`` L3 agents. For example:

   .. code-block:: ini

      [agent]
      extensions = gateway_ip_qos


   And ``gateway_ip_qos`` should work together with the ``fip_qos`` in L3
   agent for centralized routers, then all L3 IPs with binding QoS policy
   can be limited under the QoS bandwidth limit rules:

   .. code-block:: ini

      [agent]
      extensions = fip_qos, gateway_ip_qos


#. As rate limit doesn't work on Open vSwitch's ``internal`` ports,
   optionally, as a workaround, to make QoS bandwidth limit work on
   router's gateway ports, set ``ovs_use_veth`` to ``True`` in ``DEFAULT``
   section in ``/etc/neutron/l3_agent.ini``

  .. code-block:: ini

      [DEFAULT]
      ovs_use_veth = True

.. note::

   QoS currently works with ml2 only (SR-IOV, Open vSwitch, and linuxbridge
   are drivers enabled for QoS).

DSCP marking on outer header for overlay networks
-------------------------------------------------

When using overlay networks (e.g., VxLAN), the DSCP marking rule only
applies to the inner header, and during encapsulation, the DSCP mark is
not automatically copied to the outer header.

#. In order to set the DSCP value of the outer header, modify the ``dscp``
   configuration option in ``/etc/neutron/plugins/ml2/<agent_name>_agent.ini``
   where ``<agent_name>`` is the name of the agent being used
   (e.g., ``openvswitch``):

   .. code-block:: ini

      [agent]
      dscp = 8

#. In order to copy the DSCP field of the inner header to the outer header,
   change the ``dscp_inherit`` configuration option to true in
   ``/etc/neutron/plugins/ml2/<agent_name>_agent.ini`` where ``<agent_name>``
   is the name of the agent being used (e.g., ``openvswitch``):

   .. code-block:: ini

      [agent]
      dscp_inherit = true

   If the ``dscp_inherit`` option is set to true, the previous ``dscp`` option
   is overwritten.

Trusted projects policy.yaml configuration
------------------------------------------

If projects are trusted to administrate their own QoS policies in
your cloud, neutron's file ``policy.yaml`` can be modified to allow this.

Modify ``/etc/neutron/policy.yaml`` policy entries as follows:

.. code-block:: none

   "get_policy": "rule:regular_user",
   "create_policy": "rule:regular_user",
   "update_policy": "rule:regular_user",
   "delete_policy": "rule:regular_user",
   "get_rule_type": "rule:regular_user",

To enable bandwidth limit rule:

.. code-block:: none

   "get_policy_bandwidth_limit_rule": "rule:regular_user",
   "create_policy_bandwidth_limit_rule": "rule:regular_user",
   "delete_policy_bandwidth_limit_rule": "rule:regular_user",
   "update_policy_bandwidth_limit_rule": "rule:regular_user",

To enable DSCP marking rule:

.. code-block:: none

   "get_policy_dscp_marking_rule": "rule:regular_user",
   "create_policy_dscp_marking_rule": "rule:regular_user",
   "delete_policy_dscp_marking_rule": "rule:regular_user",
   "update_policy_dscp_marking_rule": "rule:regular_user",

To enable minimum bandwidth rule:

.. code-block:: none

    "get_policy_minimum_bandwidth_rule": "rule:regular_user",
    "create_policy_minimum_bandwidth_rule": "rule:regular_user",
    "delete_policy_minimum_bandwidth_rule": "rule:regular_user",
    "update_policy_minimum_bandwidth_rule": "rule:regular_user",

To enable minimum packet rate rule:

.. code-block:: none

    "get_policy_minimum_packet_rate_rule": "rule:regular_user",
    "create_policy_minimum_packet_rate_rule": "rule:regular_user",
    "delete_policy_minimum_packet_rate_rule": "rule:regular_user",
    "update_policy_minimum_packet_rate_rule": "rule:regular_user",

User workflow
~~~~~~~~~~~~~

QoS policies are only created by admins with the default ``policy.yaml``.
Therefore, you should have the cloud operator set them up on
behalf of the cloud projects.

If projects are trusted to create their own policies, check the trusted
projects ``policy.yaml`` configuration section.

First, create a QoS policy and its bandwidth limit rule:

.. code-block:: console

   $ openstack network qos policy create bw-limiter
   +-------------------+--------------------------------------+
   | Field             | Value                                |
   +-------------------+--------------------------------------+
   | description       |                                      |
   | id                | 5df855e9-a833-49a3-9c82-c0839a5f103f |
   | is_default        | False                                |
   | name              | bw-limiter                           |
   | project_id        | 4db7c1ed114a4a7fb0f077148155c500     |
   | rules             | []                                   |
   | shared            | False                                |
   +-------------------+--------------------------------------+


   $ openstack network qos rule create --type bandwidth-limit --max-kbps 3000 \
       --max-burst-kbits 2400 --egress bw-limiter
   +----------------+--------------------------------------+
   | Field          | Value                                |
   +----------------+--------------------------------------+
   | direction      | egress                               |
   | id             | 92ceb52f-170f-49d0-9528-976e2fee2d6f |
   | max_burst_kbps | 2400                                 |
   | max_kbps       | 3000                                 |
   | name           | None                                 |
   | project_id     |                                      |
   +----------------+--------------------------------------+


.. note::

   The QoS implementation requires a burst value to ensure proper behavior of
   bandwidth limit rules in the Open vSwitch and Linux bridge agents.
   Configuring the proper burst value is very important. If the burst value is
   set too low, bandwidth usage will be throttled even with a proper bandwidth
   limit setting. This issue is discussed in various documentation sources, for
   example in `Juniper's documentation
   <http://www.juniper.net/documentation/en_US/junos12.3/topics/concept/policer-mx-m120-m320-burstsize-determining.html>`_.
   For TCP traffic it is recommended to set burst value as 80% of desired bandwidth
   limit value. For example, if the bandwidth limit is set to 1000kbps then enough
   burst value will be 800kbit. If the configured burst value is too low,
   achieved bandwidth limit will be lower than expected. If the configured burst
   value is too high, too few packets could be limited and achieved bandwidth
   limit would be higher than expected.
   If you do not provide a value, it defaults to 80% of the bandwidth limit which
   works for typical TCP traffic.

Second, associate the created policy with an existing neutron port.
In order to do this, user extracts the port id to be associated to
the already created policy. In the next example, we will assign the
``bw-limiter`` policy to the VM with IP address ``192.0.2.1``.

.. code-block:: console

   $ openstack port list
   +--------------------------------------+-----------------------------------+
   | ID                                   | Fixed IP Addresses                |
   +--------------------------------------+-----------------------------------+
   | 0271d1d9-1b16-4410-bd74-82cdf6dcb5b3 | { ... , "ip_address": "192.0.2.1"}|
   | 88101e57-76fa-4d12-b0e0-4fc7634b874a | { ... , "ip_address": "192.0.2.3"}|
   | e04aab6a-5c6c-4bd9-a600-33333551a668 | { ... , "ip_address": "192.0.2.2"}|
   +--------------------------------------+-----------------------------------+

   $ openstack port set --qos-policy bw-limiter \
       88101e57-76fa-4d12-b0e0-4fc7634b874a

In order to detach a port from the QoS policy, simply update again the
port configuration.

.. code-block:: console

   $ openstack port unset --qos-policy 88101e57-76fa-4d12-b0e0-4fc7634b874a


Ports can be created with a policy attached to them too.

.. code-block:: console

   $ openstack port create --qos-policy bw-limiter --network private port1
   +-----------------------+--------------------------------------------------+
   | Field                 | Value                                            |
   +-----------------------+--------------------------------------------------+
   | admin_state_up        | UP                                               |
   | allowed_address_pairs |                                                  |
   | binding_host_id       |                                                  |
   | binding_profile       |                                                  |
   | binding_vif_details   |                                                  |
   | binding_vif_type      | unbound                                          |
   | binding_vnic_type     | normal                                           |
   | created_at            | 2017-05-15T08:43:00Z                             |
   | data_plane_status     | None                                             |
   | description           |                                                  |
   | device_id             |                                                  |
   | device_owner          |                                                  |
   | dns_assignment        | None                                             |
   | dns_name              | None                                             |
   | extra_dhcp_opts       |                                                  |
   | fixed_ips             | ip_address='10.0.10.4', subnet_id='292f8c1e-...' |
   | id                    | f51562ee-da8d-42de-9578-f6f5cb248226             |
   | ip_address            | None                                             |
   | mac_address           | fa:16:3e:d9:f2:ba                                |
   | name                  | port1                                            |
   | network_id            | 55dc2f70-0f92-4002-b343-ca34277b0234             |
   | option_name           | None                                             |
   | option_value          | None                                             |
   | port_security_enabled | False                                            |
   | project_id            | 4db7c1ed114a4a7fb0f077148155c500                 |
   | qos_policy_id         | 5df855e9-a833-49a3-9c82-c0839a5f103f             |
   | revision_number       | 6                                                |
   | security_group_ids    | 0531cc1a-19d1-4cc7-ada5-49f8b08245be             |
   | status                | DOWN                                             |
   | subnet_id             | None                                             |
   | tags                  | []                                               |
   | trunk_details         | None                                             |
   | updated_at            | 2017-05-15T08:43:00Z                             |
   +-----------------------+--------------------------------------------------+


You can attach networks to a QoS policy. The meaning of this is that
any compute port connected to the network will use the network policy by
default unless the port has a specific policy attached to it. Internal network
owned ports like DHCP and internal router ports are excluded from network
policy application.

In order to attach a QoS policy to a network, update an existing
network, or initially create the network attached to the policy.

.. code-block:: console

    $ openstack network set --qos-policy bw-limiter private

The created policy can be associated with an existing floating IP.
In order to do this, user extracts the floating IP id to be associated to
the already created policy. In the next example, we will assign the
``bw-limiter`` policy to the floating IP address ``172.16.100.18``.

.. code-block:: console

   $ openstack floating ip list
   +--------------------------------------+---------------------+------------------+------+-----+
   | ID                                   | Floating IP Address | Fixed IP Address | Port | ... |
   +--------------------------------------+---------------------+------------------+------+-----+
   | 1163d127-6df3-44bb-b69c-c0e916303eb3 | 172.16.100.9        | None             | None | ... |
   | d0ed7491-3eb7-4c4f-a0f0-df04f10a067c | 172.16.100.18       | None             | None | ... |
   | f5a9ed48-2e9f-411c-8787-2b6ecd640090 | 172.16.100.2        | None             | None | ... |
   +--------------------------------------+---------------------+------------------+------+-----+

.. code-block:: console

   $ openstack floating ip set --qos-policy bw-limiter d0ed7491-3eb7-4c4f-a0f0-df04f10a067c

In order to detach a floating IP from the QoS policy, simply update the
floating IP configuration.

.. code-block:: console

   $ openstack floating ip set --no-qos-policy d0ed7491-3eb7-4c4f-a0f0-df04f10a067c

Or use the ``unset`` action.

.. code-block:: console

   $ openstack floating ip unset --qos-policy d0ed7491-3eb7-4c4f-a0f0-df04f10a067c

Floating IPs can be created with a policy attached to them too.

.. code-block:: console

   $ openstack floating ip create --qos-policy bw-limiter public
   +---------------------+--------------------------------------+
   | Field               | Value                                |
   +---------------------+--------------------------------------+
   | created_at          | 2017-12-06T02:12:09Z                 |
   | description         |                                      |
   | fixed_ip_address    | None                                 |
   | floating_ip_address | 172.16.100.12                        |
   | floating_network_id | 4065eb05-cccb-4048-988c-e8c5480a746f |
   | id                  | 6a0efeef-462b-4312-b4ad-627cde8a20e6 |
   | name                | 172.16.100.12                        |
   | port_id             | None                                 |
   | project_id          | 916e39e8be52433ba040da3a3a6d0847     |
   | qos_policy_id       | 5df855e9-a833-49a3-9c82-c0839a5f103f |
   | revision_number     | 1                                    |
   | router_id           | None                                 |
   | status              | DOWN                                 |
   | updated_at          | 2017-12-06T02:12:09Z                 |
   +---------------------+--------------------------------------+

The QoS bandwidth limit rules attached to a floating IP will become
active when you associate the latter with a port. For example, to associate
the previously created floating IP ``172.16.100.12`` to the instance port with
uuid ``a7f25e73-4288-4a16-93b9-b71e6fd00862`` and fixed IP ``192.168.222.5``:

.. code-block:: console

   $ openstack floating ip set --port a7f25e73-4288-4a16-93b9-b71e6fd00862 \
       0eeb1f8a-de96-4cd9-a0f6-3f535c409558

.. note::

   The QoS policy attached to a floating IP is not applied to a port,
   it is applied to an associated floating IP only.
   Thus the ID of QoS policy attached to a floating IP will not be visible
   in a port's ``qos_policy_id`` field after asscoating a floating IP to
   the port. It is only visible in the floating IP attributes.

.. note::

   For now, the L3 agent floating IP QoS extension only supports
   ``bandwidth_limit`` rules. Other rule types (like DSCP marking) will be
   silently ignored for floating IPs. A QoS policy that does not contain any
   ``bandwidth_limit`` rules will have no effect when attached to a
   floating IP.

   If floating IP is bound to a port, and both have binding QoS bandwidth
   rules, the L3 agent floating IP QoS extension ignores the behavior of
   the port QoS, and installs the rules from the QoS policy associated to the
   floating IP on the appropriate device in the router namespace.

Each project can have at most one default QoS policy, although it is not
mandatory. If a default QoS policy is defined, all new networks created within
this project will have this policy assigned, as long as no other QoS policy is
explicitly attached during the creation process. If the default QoS policy is
unset, no change to existing networks will be made.

In order to set a QoS policy as default, the parameter ``--default`` must be
used. To unset this QoS policy as default, the parameter ``--no-default`` must
be used.

.. code-block:: console

    $ openstack network qos policy create --default bw-limiter
    +-------------------+--------------------------------------+
    | Field             | Value                                |
    +-------------------+--------------------------------------+
    | description       |                                      |
    | id                | 5df855e9-a833-49a3-9c82-c0839a5f103f |
    | is_default        | True                                 |
    | name              | bw-limiter                           |
    | project_id        | 4db7c1ed114a4a7fb0f077148155c500     |
    | rules             | []                                   |
    | shared            | False                                |
    +-------------------+--------------------------------------+

    $ openstack network qos policy set --no-default bw-limiter
    +-------------------+--------------------------------------+
    | Field             | Value                                |
    +-------------------+--------------------------------------+
    | description       |                                      |
    | id                | 5df855e9-a833-49a3-9c82-c0839a5f103f |
    | is_default        | False                                |
    | name              | bw-limiter                           |
    | project_id        | 4db7c1ed114a4a7fb0f077148155c500     |
    | rules             | []                                   |
    | shared            | False                                |
    +-------------------+--------------------------------------+


Administrator enforcement
-------------------------

Administrators are able to enforce policies on project ports or networks.
As long as the policy is not shared, the project is not be able to detach
any policy attached to a network or port.

If the policy is shared, the project is able to attach or detach such
policy from its own ports and networks.


Rule modification
-----------------
You can modify rules at runtime. Rule modifications will be propagated to any
attached port.

.. code-block:: console

    $ openstack network qos rule set --max-kbps 2000 --max-burst-kbits 1600 \
        --ingress bw-limiter 92ceb52f-170f-49d0-9528-976e2fee2d6f

    $ openstack network qos rule show \
        bw-limiter 92ceb52f-170f-49d0-9528-976e2fee2d6f
    +----------------+--------------------------------------+
    | Field          | Value                                |
    +----------------+--------------------------------------+
    | direction      | ingress                              |
    | id             | 92ceb52f-170f-49d0-9528-976e2fee2d6f |
    | max_burst_kbps | 1600                                 |
    | max_kbps       | 2000                                 |
    | name           | None                                 |
    | project_id     |                                      |
    +----------------+--------------------------------------+

Just like with bandwidth limiting, create a policy for DSCP marking rule:

.. code-block:: console

    $ openstack network qos policy create dscp-marking
    +-------------------+--------------------------------------+
    | Field             | Value                                |
    +-------------------+--------------------------------------+
    | description       |                                      |
    | id                | d1f90c76-fbe8-4d6f-bb87-a9aea997ed1e |
    | is_default        | False                                |
    | name              | dscp-marking                         |
    | project_id        | 4db7c1ed114a4a7fb0f077148155c500     |
    | rules             | []                                   |
    | shared            | False                                |
    +-------------------+--------------------------------------+

You can create, update, list, delete, and show DSCP markings
with the neutron client:

.. code-block:: console

    $ openstack network qos rule create --type dscp-marking --dscp-mark 26 \
        dscp-marking
    +----------------+--------------------------------------+
    | Field          | Value                                |
    +----------------+--------------------------------------+
    | dscp_mark      | 26                                   |
    | id             | 115e4f70-8034-4176-8fe9-2c47f8878a7d |
    | name           | None                                 |
    | project_id     |                                      |
    +----------------+--------------------------------------+

.. code-block:: console

    $ openstack network qos rule set --dscp-mark 22 \
        dscp-marking 115e4f70-8034-4176-8fe9-2c47f8878a7d

    $ openstack network qos rule list dscp-marking
    +--------------------------------------+----------------------------------+
    | ID                                   | DSCP Mark                        |
    +--------------------------------------+----------------------------------+
    | 115e4f70-8034-4176-8fe9-2c47f8878a7d | 22                               |
    +--------------------------------------+----------------------------------+

    $ openstack network qos rule show \
        dscp-marking 115e4f70-8034-4176-8fe9-2c47f8878a7d
    +----------------+--------------------------------------+
    | Field          | Value                                |
    +----------------+--------------------------------------+
    | dscp_mark      | 22                                   |
    | id             | 115e4f70-8034-4176-8fe9-2c47f8878a7d |
    | name           | None                                 |
    | project_id     |                                      |
    +----------------+--------------------------------------+

    $ openstack network qos rule delete \
        dscp-marking 115e4f70-8034-4176-8fe9-2c47f8878a7d

You can also include minimum bandwidth rules in your policy:

.. code-block:: console

    $ openstack network qos policy create bandwidth-control
    +-------------------+--------------------------------------+
    | Field             | Value                                |
    +-------------------+--------------------------------------+
    | description       |                                      |
    | id                | 8491547e-add1-4c6c-a50e-42121237256c |
    | is_default        | False                                |
    | name              | bandwidth-control                    |
    | project_id        | 7cc5a84e415d48e69d2b06aa67b317d8     |
    | revision_number   | 1                                    |
    | rules             | []                                   |
    | shared            | False                                |
    +-------------------+--------------------------------------+

    $ openstack network qos rule create \
      --type minimum-bandwidth --min-kbps 1000 --egress bandwidth-control
    +------------+--------------------------------------+
    | Field      | Value                                |
    +------------+--------------------------------------+
    | direction  | egress                               |
    | id         | da858b32-44bc-43c9-b92b-cf6e2fa836ab |
    | min_kbps   | 1000                                 |
    | name       | None                                 |
    | project_id |                                      |
    +------------+--------------------------------------+

A policy with a minimum bandwidth ensures best efforts are made to provide
no less than the specified bandwidth to each port on which the rule is
applied. However, as this feature is not yet integrated with the Compute
scheduler, minimum bandwidth cannot be guaranteed.

It is also possible to combine several rules in one policy, as long as the type
or direction of each rule is different. For example, You can specify two
``bandwidth-limit`` rules, one with ``egress`` and one with ``ingress``
direction.

.. code-block:: console

    $ openstack network qos rule create --type bandwidth-limit \
        --max-kbps 50000 --max-burst-kbits 50000 --egress bandwidth-control
    +----------------+--------------------------------------+
    | Field          | Value                                |
    +----------------+--------------------------------------+
    | direction      | egress                               |
    | id             | 0db48906-a762-4d32-8694-3f65214c34a6 |
    | max_burst_kbps | 50000                                |
    | max_kbps       | 50000                                |
    | name           | None                                 |
    | project_id     |                                      |
    +----------------+--------------------------------------+

    $ openstack network qos rule create --type bandwidth-limit \
        --max-kbps 10000 --max-burst-kbits 10000 --ingress bandwidth-control
    +----------------+--------------------------------------+
    | Field          | Value                                |
    +----------------+--------------------------------------+
    | direction      | ingress                              |
    | id             | faabef24-e23a-4fdf-8e92-f8cb66998834 |
    | max_burst_kbps | 10000                                |
    | max_kbps       | 10000                                |
    | name           | None                                 |
    | project_id     |                                      |
    +----------------+--------------------------------------+

    $ openstack network qos rule create --type minimum-bandwidth \
        --min-kbps 1000 --egress bandwidth-control
    +------------+--------------------------------------+
    | Field      | Value                                |
    +------------+--------------------------------------+
    | direction  | egress                               |
    | id         | da858b32-44bc-43c9-b92b-cf6e2fa836ab |
    | min_kbps   | 1000                                 |
    | name       | None                                 |
    | project_id |                                      |
    +------------+--------------------------------------+

    $ openstack network qos policy show bandwidth-control
    +-------------------+-------------------------------------------------------------------+
    | Field             | Value                                                             |
    +-------------------+-------------------------------------------------------------------+
    | description       |                                                                   |
    | id                | 8491547e-add1-4c6c-a50e-42121237256c                              |
    | is_default        | False                                                             |
    | name              | bandwidth-control                                                 |
    | project_id        | 7cc5a84e415d48e69d2b06aa67b317d8                                  |
    | revision_number   | 4                                                                 |
    | rules             | [{u'max_kbps': 50000, u'direction': u'egress',                    |
    |                   |   u'type': u'bandwidth_limit',                                    |
    |                   |   u'id': u'0db48906-a762-4d32-8694-3f65214c34a6',                 |
    |                   |   u'max_burst_kbps': 50000,                                       |
    |                   |   u'qos_policy_id': u'8491547e-add1-4c6c-a50e-42121237256c'},     |
    |                   | [{u'max_kbps': 10000, u'direction': u'ingress',                   |
    |                   |   u'type': u'bandwidth_limit',                                    |
    |                   |   u'id': u'faabef24-e23a-4fdf-8e92-f8cb66998834',                 |
    |                   |   u'max_burst_kbps': 10000,                                       |
    |                   |   u'qos_policy_id': u'8491547e-add1-4c6c-a50e-42121237256c'},     |
    |                   |  {u'direction':                                                   |
    |                   |   u'egress', u'min_kbps': 1000, u'type': u'minimum_bandwidth',    |
    |                   |   u'id': u'da858b32-44bc-43c9-b92b-cf6e2fa836ab',                 |
    |                   |   u'qos_policy_id': u'8491547e-add1-4c6c-a50e-42121237256c'}]     |
    | shared            | False                                                             |
    +-------------------+-------------------------------------------------------------------+
