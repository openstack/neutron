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

Any plug-in or ml2 mechanism driver can claim support for some QoS rule types
by providing a plug-in/driver class property called
``supported_qos_rule_types`` that returns a list of strings that correspond
to `QoS rule types
<https://git.openstack.org/cgit/openstack/neutron/tree/neutron/services/qos/qos_consts.py>`_.

The following table shows the Networking back ends, QoS supported rules, and
traffic directions (from the VM point of view).

.. table:: **Networking back ends, supported rules, and traffic direction**

    ====================  ================  ================  ================
     Rule \ back end       Open vSwitch      SR-IOV            Linux bridge
    ====================  ================  ================  ================
     Bandwidth limit       Egress\Ingress    Egress (1)        Egress\Ingress
     Minimum bandwidth     -                 Egress            -
     DSCP marking          Egress            -                 Egress
    ====================  ================  ================  ================

.. note::

   (1) Max burst parameter is skipped because it is not supported by the
       IP tool.

In the most simple case, the property can be represented by a simple Python
list defined on the class.

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


Configuration
~~~~~~~~~~~~~

To enable the service, follow the steps below:

On network nodes:

#. Add the QoS service to the ``service_plugins`` setting in
   ``/etc/neutron/neutron.conf``. For example:

   .. code-block:: none

      service_plugins = \
      neutron.services.l3_router.l3_router_plugin.L3RouterPlugin,
      neutron.services.metering.metering_plugin.MeteringPlugin,
      neutron.services.qos.qos_plugin.QoSPlugin

#. Optionally, set the needed ``notification_drivers`` in the ``[qos]``
   section in ``/etc/neutron/neutron.conf`` (``message_queue`` is the
   default).

#. In ``/etc/neutron/plugins/ml2/ml2_conf.ini``, add ``qos`` to
   ``extension_drivers`` in the ``[ml2]`` section. For example:

   .. code-block:: ini

      [ml2]
      extension_drivers = port_security, qos

#. If the Open vSwitch agent is being used, set ``extensions`` to
   ``qos`` in the ``[agent]`` section of
   ``/etc/neutron/plugins/ml2/openvswitch_agent.ini``. For example:

   .. code-block:: ini

      [agent]
      extensions = qos

On compute nodes:

#. In ``/etc/neutron/plugins/ml2/openvswitch_agent.ini``, add ``qos`` to the
   ``extensions`` setting in the ``[agent]`` section. For example:

   .. code-block:: ini

      [agent]
      extensions = qos

.. note::

   QoS currently works with ml2 only (SR-IOV, Open vSwitch, and linuxbridge
   are drivers that are enabled for QoS in Mitaka release).

Trusted projects policy.json configuration
------------------------------------------

If projects are trusted to administrate their own QoS policies in
your cloud, neutron's file ``policy.json`` can be modified to allow this.

Modify ``/etc/neutron/policy.json`` policy entries as follows:

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
   "create_dscp_marking_rule": "rule:regular_user",
   "delete_dscp_marking_rule": "rule:regular_user",
   "update_dscp_marking_rule": "rule:regular_user",

To enable minimum bandwidth rule:

.. code-block:: none

    "get_policy_minimum_bandwidth_rule": "rule:regular_user",
    "create_policy_minimum_bandwidth_rule": "rule:regular_user",
    "delete_policy_minimum_bandwidth_rule": "rule:regular_user",
    "update_policy_minimum_bandwidth_rule": "rule:regular_user",

User workflow
~~~~~~~~~~~~~

QoS policies are only created by admins with the default ``policy.json``.
Therefore, you should have the cloud operator set them up on
behalf of the cloud projects.

If projects are trusted to create their own policies, check the trusted
projects ``policy.json`` configuration section.

First, create a QoS policy and its bandwidth limit rule:

.. code-block:: console

   $ openstack network qos policy create bw-limiter

   Created a new policy:
   +-------------+--------------------------------------+
   | Field       | Value                                |
   +-------------+--------------------------------------+
   | description |                                      |
   | id          | 5df855e9-a833-49a3-9c82-c0839a5f103f |
   | is_default  | False                                |
   | name        | qos1                                 |
   | project_id  | 4db7c1ed114a4a7fb0f077148155c500     |
   | rules       | []                                   |
   | shared      | False                                |
   +-------------+--------------------------------------+

   $ openstack network qos rule create --type bandwidth-limit --max-kbps 3000 \
       --max-burst-kbits 300 --egress bw-limiter

   Created a new bandwidth_limit_rule:
   +----------------+--------------------------------------+
   | Field          | Value                                |
   +----------------+--------------------------------------+
   | direction      | egress                               |
   | id             | 92ceb52f-170f-49d0-9528-976e2fee2d6f |
   | max_burst_kbps | 300                                  |
   | max_kbps       | 3000                                 |
   +----------------+--------------------------------------+

.. note::

   The QoS implementation requires a burst value to ensure proper behavior of
   bandwidth limit rules in the Open vSwitch and Linux bridge agents. If you
   do not provide a value, it defaults to 80% of the bandwidth limit which
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
   Updated port: 88101e57-76fa-4d12-b0e0-4fc7634b874a

In order to detach a port from the QoS policy, simply update again the
port configuration.

.. code-block:: console

   $ openstack port unset --no-qos-policy 88101e57-76fa-4d12-b0e0-4fc7634b874a
   Updated port: 88101e57-76fa-4d12-b0e0-4fc7634b874a


Ports can be created with a policy attached to them too.

.. code-block:: console

   $ openstack port create --qos-policy bw-limiter --network private port1

   Created a new port:
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
    Updated network: private

.. note::

   Configuring the proper burst value is very important. If the burst value is
   set too low, bandwidth usage will be throttled even with a proper bandwidth
   limit setting. This issue is discussed in various documentation sources, for
   example in `Juniper's documentation
   <http://www.juniper.net/documentation/en_US/junos12.3/topics/concept/policer-mx-m120-m320-burstsize-determining.html>`_.
   Burst value for TCP traffic can be set as 80% of desired bandwidth limit
   value. For example, if the bandwidth limit is set to 1000kbps then enough
   burst value will be 800kbit. If the configured burst value is too low,
   achieved bandwidth limit will be lower than expected. If the configured burst
   value is too high, too few packets could be limited and achieved bandwidth
   limit would be higher than expected.

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

    Created a new policy:
    +-------------+--------------------------------------+
    | Field       | Value                                |
    +-------------+--------------------------------------+
    | description |                                      |
    | id          | 5df855e9-a833-49a3-9c82-c0839a5f103f |
    | is_default  | True                                 |
    | name        | qos1                                 |
    | project_id  | 4db7c1ed114a4a7fb0f077148155c500     |
    | rules       | []                                   |
    | shared      | False                                |
    +-------------+--------------------------------------+

    $ openstack network qos policy set --no-default bw-limiter

    Created a new policy:
    +-------------+--------------------------------------+
    | Field       | Value                                |
    +-------------+--------------------------------------+
    | description |                                      |
    | id          | 5df855e9-a833-49a3-9c82-c0839a5f103f |
    | is_default  | False                                |
    | name        | qos1                                 |
    | project_id  | 4db7c1ed114a4a7fb0f077148155c500     |
    | rules       | []                                   |
    | shared      | False                                |
    +-------------+--------------------------------------+


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

    $ openstack network qos rule set --max-kbps 2000 --max-burst-kbps 200 \
        --ingress bw-limiter 92ceb52f-170f-49d0-9528-976e2fee2d6f
    Updated bandwidth_limit_rule: 92ceb52f-170f-49d0-9528-976e2fee2d6f

    $ openstack network qos rule show \
        bw-limiter 92ceb52f-170f-49d0-9528-976e2fee2d6f

    +----------------+--------------------------------------+
    | Field          | Value                                |
    +----------------+--------------------------------------+
    | direction      | ingress                              |
    | id             | 92ceb52f-170f-49d0-9528-976e2fee2d6f |
    | max_burst_kbps | 200                                  |
    | max_kbps       | 2000                                 |
    +----------------+--------------------------------------+

Just like with bandwidth limiting, create a policy for DSCP marking rule:

.. code-block:: console

    $ openstack network qos policy create dscp-marking

    +-------------+--------------------------------------+
    | Field       | Value                                |
    +-------------+--------------------------------------+
    | description |                                      |
    | id          | d1f90c76-fbe8-4d6f-bb87-a9aea997ed1e |
    | is_default  | False                                |
    | name        | dscp-marking                         |
    | project_id  | 4db7c1ed114a4a7fb0f077148155c500     |
    | rules       | []                                   |
    | shared      | False                                |
    +-------------+--------------------------------------+

You can create, update, list, delete, and show DSCP markings
with the neutron client:

.. code-block:: console

    $ openstack network qos rule create --type dscp-marking --dscp-mark 26 \
        dscp-marking

    Created a new dscp marking rule
    +----------------+--------------------------------------+
    | Field          | Value                                |
    +----------------+--------------------------------------+
    | id             | 115e4f70-8034-4176-8fe9-2c47f8878a7d |
    | dscp_mark      | 26                                   |
    +----------------+--------------------------------------+

.. code-block:: console

    $ openstack network qos rule set --dscp-mark 22 \
        dscp-marking 115e4f70-8034-4176-8fe9-2c47f8878a7d
    Updated dscp_rule: 115e4f70-8034-4176-8fe9-2c47f8878a7d

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
    | id             | 115e4f70-8034-4176-8fe9-2c47f8878a7d |
    | dscp_mark      | 22                                   |
    +----------------+--------------------------------------+

    $ openstack network qos rule delete \
        dscp-marking 115e4f70-8034-4176-8fe9-2c47f8878a7d
      Deleted dscp_rule: 115e4f70-8034-4176-8fe9-2c47f8878a7d

You can also include minimum bandwidth rules in your policy:

.. code-block:: console

    $ openstack network qos policy create bandwidth-control
    +-------------+--------------------------------------+
    | Field       | Value                                |
    +-------------+--------------------------------------+
    | description |                                      |
    | id          | 8491547e-add1-4c6c-a50e-42121237256c |
    | is_default  | False                                |
    | name        | bandwidth-control                    |
    | project_id  | 7cc5a84e415d48e69d2b06aa67b317d8     |
    | rules       | []                                   |
    | shared      | False                                |
    +-------------+--------------------------------------+

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

It is also possible to combine several rules in one policy:

.. code-block:: console

    $ openstack network qos rule create --type bandwidth-limit \
        --max-kbps 50000 --max-burst-kbits 50000 bandwidth-control
    +----------------+--------------------------------------+
    | Field          | Value                                |
    +----------------+--------------------------------------+
    | id             | 0db48906-a762-4d32-8694-3f65214c34a6 |
    | max_burst_kbps | 50000                                |
    | max_kbps       | 50000                                |
    | name           | None                                 |
    | project_id     |                                      |
    +----------------+--------------------------------------+

    $ openstack network qos policy show bandwidth-control
    +-------------+-------------------------------------------------------------------+
    | Field       | Value                                                             |
    +-------------+-------------------------------------------------------------------+
    | description |                                                                   |
    | id          | 8491547e-add1-4c6c-a50e-42121237256c                              |
    | is_default  | False                                                             |
    | name        | bandwidth-control                                                 |
    | project_id  | 7cc5a84e415d48e69d2b06aa67b317d8                                  |
    | rules       | [{u'max_kbps': 50000, u'type': u'bandwidth_limit',                |
    |             |   u'id': u'0db48906-a762-4d32-8694-3f65214c34a6',                 |
    |             |   u'max_burst_kbps': 50000,                                       |
    |             |   u'qos_policy_id': u'8491547e-add1-4c6c-a50e-42121237256c'},     |
    |             |  {u'direction':                                                   |
    |             |   u'egress', u'min_kbps': 1000, u'type': u'minimum_bandwidth',    |
    |             |   u'id': u'da858b32-44bc-43c9-b92b-cf6e2fa836ab',                 |
    |             |   u'qos_policy_id': u'8491547e-add1-4c6c-a50e-42121237256c'}]     |
    | shared      | False                                                             |
    +-------------+-------------------------------------------------------------------+
