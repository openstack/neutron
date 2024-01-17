.. _config-router-flavor-ovn:

===================================================
Creating a L3 OVN router with a user-defined flavor
===================================================

In this section we describe the steps necessary to create a router with a user
defined flavor.

   .. note::
      The following example refers to a dummy user-defined service provider,
      which in a real situation must be replaced with user provided code.

#. Add the service provider to neutron.conf:

   .. code-block:: console

      [service_providers]
      service_provider = L3_ROUTER_NAT:user-defined:neutron.services.ovn_l3.service_providers.user_defined.UserDefined

#. Re-start the neutron server and verify the user-defined provider has been
   loaded:

   .. code-block:: console

      $ openstack network service provider list
      +---------------+--------------+---------+
      | Service Type  | Name         | Default |
      +---------------+--------------+---------+
      | L3_ROUTER_NAT | user-defined | False   |
      | L3_ROUTER_NAT | ovn          | True    |
      +---------------+--------------+---------+

#. Create a service profile for the router flavor:

   .. code-block:: console

      $ openstack network flavor profile create --description "User-defined router flavor profile" --enable --driver neutron.services.ovn_l3.service_providers.user_defined.UserDefined
      +-------------+--------------------------------------------------------------------+
      | Field       | Value                                                              |
      +-------------+--------------------------------------------------------------------+
      | description | User-defined router flavor profile                                 |
      | driver      | neutron.services.ovn_l3.service_providers.user_defined.UserDefined |
      | enabled     | True                                                               |
      | id          | a717c92c-63f7-47e8-9efb-6ad0d61c4875                               |
      | meta_info   |                                                                    |
      | project_id  | None                                                               |
      +-------------+--------------------------------------------------------------------+

#. Create the router flavor:

   .. code-block:: console

      $ openstack network flavor create --service-type L3_ROUTER_NAT --description "User-defined flavor for routers in the L3 OVN plugin" user-defined-router-flavor
      +---------------------+------------------------------------------------------+
      | Field               | Value                                                |
      +---------------------+------------------------------------------------------+
      | description         | User-defined flavor for routers in the L3 OVN plugin |
      | enabled             | True                                                 |
      | id                  | e47c1c5c-629b-4c48-b49a-78abe6ac7696                 |
      | name                | user-defined-router-flavor                           |
      | service_profile_ids | []                                                   |
      | service_type        | L3_ROUTER_NAT                                        |
      +---------------------+------------------------------------------------------+

#. Add service profile to router flavor:

   .. code-block:: console

      $ openstack network flavor add profile user-defined-router-flavor a717c92c-63f7-47e8-9efb-6ad0d61c4875

#. Create router specifying user-defined flavor:

   .. code-block:: console

      $ openstack router create router-of-user-defined-flavor --external-gateway public --flavor-id e47c1c5c-629b-4c48-b49a-78abe6ac7696 --max-width 100
      +-------------------------+------------------------------------------------------------------------+
      | Field                   | Value                                                                  |
      +-------------------------+------------------------------------------------------------------------+
      | admin_state_up          | UP                                                                     |
      | availability_zone_hints |                                                                        |
      | availability_zones      |                                                                        |
      | created_at              | 2023-05-25T22:34:16Z                                                   |
      | description             |                                                                        |
      | enable_ndp_proxy        | None                                                                   |
      | external_gateway_info   | {"network_id": "ba485dc9-2459-41c1-9d4f-71914a7fba2a",                 |
      |                         | "external_fixed_ips": [{"subnet_id":                                   |
      |                         | "2e3adb94-c544-4916-a9fb-27a9dea21820", "ip_address": "172.24.8.69"},  |
      |                         | {"subnet_id": "996ed143-917b-4783-8349-03c6a6d9603e", "ip_address":    |
      |                         | "2001:db8::261"}], "enable_snat": true}                                |
      | flavor_id               | e47c1c5c-629b-4c48-b49a-78abe6ac7696                                   |
      | id                      | 9f5fec56-1829-4bad-abe5-7b4221649c8e                                   |
      | name                    | router-of-user-defined-flavor                                          |
      | project_id              | b807321af03f44dc808ff06bbc845804                                       |
      | revision_number         | 3                                                                      |
      | routes                  |                                                                        |
      | status                  | ACTIVE                                                                 |
      | tags                    |                                                                        |
      | tenant_id               | b807321af03f44dc808ff06bbc845804                                       |
      | updated_at              | 2023-05-25T22:34:16Z                                                   |
      +-------------------------+------------------------------------------------------------------------+


#. Create an OVN flavor router to verify they co-exist with the user-defined
   flavor:

   .. code-block:: console

      $ openstack router create ovn-flavor-router --external-gateway public --max-width 100
      +-------------------------+------------------------------------------------------------------------+
      | Field                   | Value                                                                  |
      +-------------------------+------------------------------------------------------------------------+
      | admin_state_up          | UP                                                                     |
      | availability_zone_hints |                                                                        |
      | availability_zones      |                                                                        |
      | created_at              | 2023-05-25T23:34:20Z                                                   |
      | description             |                                                                        |
      | enable_ndp_proxy        | None                                                                   |
      | external_gateway_info   | {"network_id": "ba485dc9-2459-41c1-9d4f-71914a7fba2a",                 |
      |                         | "external_fixed_ips": [{"subnet_id":                                   |
      |                         | "2e3adb94-c544-4916-a9fb-27a9dea21820", "ip_address": "172.24.8.195"}, |
      |                         | {"subnet_id": "996ed143-917b-4783-8349-03c6a6d9603e", "ip_address":    |
      |                         | "2001:db8::263"}], "enable_snat": true}                                |
      | flavor_id               | None                                                                   |
      | id                      | 21889ed3-b8df-4b0e-9a64-92ba9fab655d                                   |
      | name                    | ovn-flavor-router                                                      |
      | project_id              | b807321af03f44dc808ff06bbc845804                                       |
      | revision_number         | 3                                                                      |
      | routes                  |                                                                        |
      | status                  | ACTIVE                                                                 |
      | tags                    |                                                                        |
      | tenant_id               | e6d6b109d16b4e5e857a10034f4ba558                                       |
      | updated_at              | 2023-07-20T23:34:21Z                                                   |
      +-------------------------+------------------------------------------------------------------------+


#. List routers to verify:

   .. code-block:: console

      $ openstack router list
      +--------------------------------------+-------------------------------+--------+-------+----------------------------------+
      | ID                                   | Name                          | Status | State | Project                          |
      +--------------------------------------+-------------------------------+--------+-------+----------------------------------+
      | 21889ed3-b8df-4b0e-9a64-92ba9fab655d | ovn-flavor-router             | ACTIVE | UP    | b807321af03f44dc808ff06bbc845804 |
      | 9f5fec56-1829-4bad-abe5-7b4221649c8e | router-of-user-defined-flavor | ACTIVE | UP    | b807321af03f44dc808ff06bbc845804 |
      | e9f25566-ff73-4a76-aeb4-969c819f9c47 | router1                       | ACTIVE | UP    | 1bf97e3957654c0182a48727d619e00f |
      +--------------------------------------+-------------------------------+--------+-------+----------------------------------+
