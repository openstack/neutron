======================================================
Virtual Private Network-as-a-Service (VPNaaS) scenario
======================================================

Enabling VPNaaS
~~~~~~~~~~~~~~~

This section describes the setting for the reference implementation.
Vendor plugins or drivers can have different setup procedure and perhaps
they provide their version of manuals.

#. Enable the VPNaaS plug-in in the ``/etc/neutron/neutron.conf`` file
   by appending ``vpnaas`` to ``service_plugins`` in ``[DEFAULT]``:

   .. code-block:: ini

      [DEFAULT]
      # ...
      service_plugins = vpnaas

   .. note::

      ``vpnaas`` is just example of reference implementation.
      It depends on a plugin that you are going to use. Consider to
      set suitable plugin for your own deployment.

#. Configure the VPNaaS service provider by creating the
   ``/etc/neutron/neutron_vpnaas.conf`` file as follows, ``strongswan`` used
   in Ubuntu distribution:

   .. code-block:: ini

      [service_providers]
      service_provider = VPN:strongswan:neutron_vpnaas.services.vpn.service_drivers.ipsec.IPsecVPNDriver:default

   .. note::

      There are several kinds of service drivers.
      Depending upon the Linux distribution, you may need to override this value.
      Select ``libreswan`` for RHEL/CentOS, the config will like this:
      ``service_provider = VPN:openswan:neutron_vpnaas.services.vpn.service_drivers.ipsec.IPsecVPNDriver:default``.
      Consider to use the appropriate one for your deployment.

#. Configure the VPNaaS plugin for the L3 agent by adding to
   ``/etc/neutron/l3_agent.ini`` the following section, ``StrongSwanDriver``
   used in Ubuntu distribution:

   .. code-block:: ini

      [AGENT]
      extensions = vpnaas

      [vpnagent]
      vpn_device_driver = neutron_vpnaas.services.vpn.device_drivers.strongswan_ipsec.StrongSwanDriver

   .. note::

      There are several kinds of device drivers.
      Depending upon the Linux distribution, you may need to override this value.
      Select ``LibreSwanDriver`` for RHEL/CentOS, the config will like this:
      ``vpn_device_driver = neutron_vpnaas.services.vpn.device_drivers.libreswan_ipsec.LibreSwanDriver``.
      Consider to use the appropriate drivers for your deployment.

#. Create the required tables in the database:

   .. code-block:: console

      # neutron-db-manage --subproject neutron-vpnaas upgrade head

   .. note::

      In order to run the above command, you need to have `neutron-vpnaas <https://pypi.org/project/neutron-vpnaas>`__
      package installed on controller node.

#. Restart the ``neutron-server`` in controller node to apply the settings.

#. Restart the ``neutron-l3-agent`` in network node to apply the settings.

Using VPNaaS with endpoint group (recommended)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

IPsec site-to-site connections will support multiple local subnets,
in addition to the current multiple peer CIDRs. The multiple local subnet
feature is triggered by not specifying a local subnet, when creating a VPN
service. Backwards compatibility is maintained with single local subnets, by
providing the subnet in the VPN service creation.

To support multiple local subnets, a new capability called "End Point Groups"
has been added. Each endpoint group will define one or more endpoints of
a specific type, and can be used to specify both local and peer endpoints for
IPsec connections. The endpoint groups separate the "what gets connected" from
the "how to connect" for a VPN service, and can be used for different flavors
of VPN, in the future.

Refer `Multiple Local Subnets <https://docs.openstack.org/neutron-vpnaas/latest/contributor/multiple-local-subnets.html>`__ for more detail.

Create the IKE policy, IPsec policy, VPN service,
local endpoint group and peer endpoint group.
Then, create an IPsec site connection that applies the
above policies and service.

#. Create an IKE policy:

   .. code-block:: console

      $ openstack vpn ike policy create ikepolicy
        +-------------------------------+----------------------------------------+
        | Field                         | Value                                  |
        +-------------------------------+----------------------------------------+
        | Authentication Algorithm      | sha1                                   |
        | Description                   |                                        |
        | Encryption Algorithm          | aes-128                                |
        | ID                            | 735f4691-3670-43b2-b389-f4d81a60ed56   |
        | IKE Version                   | v1                                     |
        | Lifetime                      | {u'units': u'seconds', u'value': 3600} |
        | Name                          | ikepolicy                              |
        | Perfect Forward Secrecy (PFS) | group5                                 |
        | Phase1 Negotiation Mode       | main                                   |
        | Project                       | 095247cb2e22455b9850c6efff407584       |
        | project_id                    | 095247cb2e22455b9850c6efff407584       |
        +-------------------------------+----------------------------------------+

#. Create an IPsec policy:

   .. code-block:: console

      $ openstack vpn ipsec policy create ipsecpolicy
        +-------------------------------+----------------------------------------+
        | Field                         | Value                                  |
        +-------------------------------+----------------------------------------+
        | Authentication Algorithm      | sha1                                   |
        | Description                   |                                        |
        | Encapsulation Mode            | tunnel                                 |
        | Encryption Algorithm          | aes-128                                |
        | ID                            | 4f3f46fc-f2dc-4811-a642-9601ebae310f   |
        | Lifetime                      | {u'units': u'seconds', u'value': 3600} |
        | Name                          | ipsecpolicy                            |
        | Perfect Forward Secrecy (PFS) | group5                                 |
        | Project                       | 095247cb2e22455b9850c6efff407584       |
        | Transform Protocol            | esp                                    |
        | project_id                    | 095247cb2e22455b9850c6efff407584       |
        +-------------------------------+----------------------------------------+

#. Create a VPN service:

   .. code-block:: console

      $ openstack vpn service create vpn \
        --router 9ff3f20c-314f-4dac-9392-defdbbb36a66
        +----------------+--------------------------------------+
        | Field          | Value                                |
        +----------------+--------------------------------------+
        | Description    |                                      |
        | Flavor         | None                                 |
        | ID             | 9f499f9f-f672-4ceb-be3c-d5ff3858c680 |
        | Name           | vpn                                  |
        | Project        | 095247cb2e22455b9850c6efff407584     |
        | Router         | 9ff3f20c-314f-4dac-9392-defdbbb36a66 |
        | State          | True                                 |
        | Status         | PENDING_CREATE                       |
        | Subnet         | None                                 |
        | external_v4_ip | 192.168.20.7                         |
        | external_v6_ip | 2001:db8::7                          |
        | project_id     | 095247cb2e22455b9850c6efff407584     |
        +----------------+--------------------------------------+

   .. note::

      Please do not specify ``--subnet`` option in this case.

      The Networking openstackclient requires a router (Name or ID) and name.

#. Create local endpoint group:

   .. code-block:: console

      $ openstack vpn endpoint group create ep_subnet \
        --type subnet \
        --value 1f888dd0-2066-42a1-83d7-56518895e47d
        +-------------+-------------------------------------------+
        | Field       | Value                                     |
        +-------------+-------------------------------------------+
        | Description |                                           |
        | Endpoints   | [u'1f888dd0-2066-42a1-83d7-56518895e47d'] |
        | ID          | 667296d0-67ca-4d0f-b676-7650cf96e7b1      |
        | Name        | ep_subnet                                 |
        | Project     | 095247cb2e22455b9850c6efff407584          |
        | Type        | subnet                                    |
        | project_id  | 095247cb2e22455b9850c6efff407584          |
        +-------------+-------------------------------------------+

   .. note::

      The type of a local endpoint group must be ``subnet``.

#. Create peer endpoint group:

   .. code-block:: console

      $ openstack vpn endpoint group create ep_cidr \
        --type cidr \
        --value 192.168.1.0/24
        +-------------+--------------------------------------+
        | Field       | Value                                |
        +-------------+--------------------------------------+
        | Description |                                      |
        | Endpoints   | [u'192.168.1.0/24']                  |
        | ID          | 5c3d7f2a-4a2a-446b-9fcf-9a2557cfc641 |
        | Name        | ep_cidr                              |
        | Project     | 095247cb2e22455b9850c6efff407584     |
        | Type        | cidr                                 |
        | project_id  | 095247cb2e22455b9850c6efff407584     |
        +-------------+--------------------------------------+

   .. note::

      The type of a peer endpoint group must be ``cidr``.

#. Create an ipsec site connection:

   .. code-block:: console

      $ openstack vpn ipsec site connection create conn \
        --vpnservice vpn \
        --ikepolicy ikepolicy \
        --ipsecpolicy ipsecpolicy \
        --peer-address 192.168.20.9 \
        --peer-id 192.168.20.9 \
        --psk secret \
        --local-endpoint-group ep_subnet \
        --peer-endpoint-group ep_cidr
        +--------------------------+--------------------------------------------------------+
        | Field                    | Value                                                  |
        +--------------------------+--------------------------------------------------------+
        | Authentication Algorithm | psk                                                    |
        | Description              |                                                        |
        | ID                       | 07e400b7-9de3-4ea3-a9d0-90a185e5b00d                   |
        | IKE Policy               | 735f4691-3670-43b2-b389-f4d81a60ed56                   |
        | IPSec Policy             | 4f3f46fc-f2dc-4811-a642-9601ebae310f                   |
        | Initiator                | bi-directional                                         |
        | Local Endpoint Group ID  | 667296d0-67ca-4d0f-b676-7650cf96e7b1                   |
        | Local ID                 |                                                        |
        | MTU                      | 1500                                                   |
        | Name                     | conn                                                   |
        | Peer Address             | 192.168.20.9                                           |
        | Peer CIDRs               |                                                        |
        | Peer Endpoint Group ID   | 5c3d7f2a-4a2a-446b-9fcf-9a2557cfc641                   |
        | Peer ID                  | 192.168.20.9                                           |
        | Pre-shared Key           | secret                                                 |
        | Project                  | 095247cb2e22455b9850c6efff407584                       |
        | Route Mode               | static                                                 |
        | State                    | True                                                   |
        | Status                   | PENDING_CREATE                                         |
        | VPN Service              | 9f499f9f-f672-4ceb-be3c-d5ff3858c680                   |
        | dpd                      | {u'action': u'hold', u'interval': 30, u'timeout': 120} |
        | project_id               | 095247cb2e22455b9850c6efff407584                       |
        +--------------------------+--------------------------------------------------------+

   .. note::

      Please do not specify ``--peer-cidr`` option in this case. Peer CIDR(s) are provided
      by a peer endpoint group.

Configure VPNaaS without endpoint group (the legacy way)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Create the IKE policy, IPsec policy, VPN service.
Then, create an ipsec site connection that applies the
above policies and service.

#. Create an IKE policy:

   .. code-block:: console

      $ openstack vpn ike policy create ikepolicy1
        +-------------------------------+----------------------------------------+
        | Field                         | Value                                  |
        +-------------------------------+----------------------------------------+
        | Authentication Algorithm      | sha1                                   |
        | Description                   |                                        |
        | Encryption Algorithm          | aes-128                                |
        | ID                            | 99e4345d-8674-4d73-acb4-0e2524425e34   |
        | IKE Version                   | v1                                     |
        | Lifetime                      | {u'units': u'seconds', u'value': 3600} |
        | Name                          | ikepolicy1                             |
        | Perfect Forward Secrecy (PFS) | group5                                 |
        | Phase1 Negotiation Mode       | main                                   |
        | Project                       | 095247cb2e22455b9850c6efff407584       |
        | project_id                    | 095247cb2e22455b9850c6efff407584       |
        +-------------------------------+----------------------------------------+

#. Create an IPsec policy:

   .. code-block:: console

      $ openstack vpn ipsec policy create ipsecpolicy1
        +-------------------------------+----------------------------------------+
        | Field                         | Value                                  |
        +-------------------------------+----------------------------------------+
        | Authentication Algorithm      | sha1                                   |
        | Description                   |                                        |
        | Encapsulation Mode            | tunnel                                 |
        | Encryption Algorithm          | aes-128                                |
        | ID                            | e6f547af-4a1d-4c28-b40b-b97cce746459   |
        | Lifetime                      | {u'units': u'seconds', u'value': 3600} |
        | Name                          | ipsecpolicy1                           |
        | Perfect Forward Secrecy (PFS) | group5                                 |
        | Project                       | 095247cb2e22455b9850c6efff407584       |
        | Transform Protocol            | esp                                    |
        | project_id                    | 095247cb2e22455b9850c6efff407584       |
        +-------------------------------+----------------------------------------+

#. Create a VPN service:

   .. code-block:: console

      $ openstack vpn service create vpn \
        --router 66ca673a-cbbd-48b7-9fb6-bfa7ee3ef724 \
        --subnet cdfb411e-e818-466a-837c-7f96fc41a6d9
        +----------------+--------------------------------------+
        | Field          | Value                                |
        +----------------+--------------------------------------+
        | Description    |                                      |
        | Flavor         | None                                 |
        | ID             | 79ef6250-ddc3-428f-88c2-0ec8084f4e9a |
        | Name           | vpn                                  |
        | Project        | 095247cb2e22455b9850c6efff407584     |
        | Router         | 66ca673a-cbbd-48b7-9fb6-bfa7ee3ef724 |
        | State          | True                                 |
        | Status         | PENDING_CREATE                       |
        | Subnet         | cdfb411e-e818-466a-837c-7f96fc41a6d9 |
        | external_v4_ip | 192.168.20.2                         |
        | external_v6_ip | 2001:db8::d                          |
        | project_id     | 095247cb2e22455b9850c6efff407584     |
        +----------------+--------------------------------------+

   .. note::

      The ``--subnet`` option is required in this scenario.

#. Create an ipsec site connection:

   .. code-block:: console

      $ openstack vpn ipsec site connection create conn \
        --vpnservice vpn \
        --ikepolicy ikepolicy1 \
        --ipsecpolicy ipsecpolicy1 \
        --peer-address 192.168.20.11 \
        --peer-id 192.168.20.11 \
        --peer-cidr 192.168.1.0/24 \
        --psk secret
        +--------------------------+--------------------------------------------------------+
        | Field                    | Value                                                  |
        +--------------------------+--------------------------------------------------------+
        | Authentication Algorithm | psk                                                    |
        | Description              |                                                        |
        | ID                       | 5b2935e6-b2f0-423a-8156-07ed48703d13                   |
        | IKE Policy               | 99e4345d-8674-4d73-acb4-0e2524425e34                   |
        | IPSec Policy             | e6f547af-4a1d-4c28-b40b-b97cce746459                   |
        | Initiator                | bi-directional                                         |
        | Local Endpoint Group ID  | None                                                   |
        | Local ID                 |                                                        |
        | MTU                      | 1500                                                   |
        | Name                     | conn                                                   |
        | Peer Address             | 192.168.20.11                                          |
        | Peer CIDRs               | 192.168.1.0/24                                         |
        | Peer Endpoint Group ID   | None                                                   |
        | Peer ID                  | 192.168.20.11                                          |
        | Pre-shared Key           | secret                                                 |
        | Project                  | 095247cb2e22455b9850c6efff407584                       |
        | Route Mode               | static                                                 |
        | State                    | True                                                   |
        | Status                   | PENDING_CREATE                                         |
        | VPN Service              | 79ef6250-ddc3-428f-88c2-0ec8084f4e9a                   |
        | dpd                      | {u'action': u'hold', u'interval': 30, u'timeout': 120} |
        | project_id               | 095247cb2e22455b9850c6efff407584                       |
        +--------------------------+--------------------------------------------------------+

   .. note::

      Please do not specify ``--local-endpoint-group`` and ``--peer-endpoint-group``
      options in this case.
