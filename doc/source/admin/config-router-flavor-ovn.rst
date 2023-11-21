.. _config-router-flavor-ovn:

=============================================
Router flavors with the L3 OVN service plugin
=============================================

In this chapter we give examples on how to create routers with user-defined
flavors.

   .. note::
      The following example refers to a dummy user-defined service provider,
      which in a real situation must be replaced with user provided code.

#. Add service providers to neutron.conf. The second provider is a high
   availability version of the first one:

   .. code-block:: console

      [service_providers]
      service_provider = L3_ROUTER_NAT:user-defined:neutron.services.ovn_l3.service_providers.user_defined.UserDefined

#. Re-start the neutron server and verify the user-defined provider has been
   loaded:

   .. code-block:: console

      $ openstack network service provider list
      +---------------+-----------------+---------+
      | Service Type  | Name            | Default |
      +---------------+-----------------+---------+
      | L3_ROUTER_NAT | user-defined    | False   |
      | L3_ROUTER_NAT | ovn             | True    |
      +---------------+-----------------+---------+

#. Create service profiles for the router flavors:

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

#. Create the router flavors:

   .. code-block:: console

      $ openstack network flavor create --service-type L3_ROUTER_NAT --description "User-defined flavor for routers in the L3 OVN plugin" user-defined-router-flavor
      +---------------------+------------------------------------------------------+
      | Field               | Value                                                |
      +---------------------+------------------------------------------------------+
      | description         | User-defined flavor for routers in the L3 OVN plugin |
      | enabled             | True                                                 |
      | id                  | 65df2587-c535-4c3a-af2f-86b2968a3191                 |
      | name                | user-defined-router-flavor                           |
      | service_profile_ids | []                                                   |
      | service_type        | L3_ROUTER_NAT                                        |
      +---------------------+------------------------------------------------------+

#. Add service profile to the router flavors:

   .. code-block:: console

      $ openstack network flavor add profile user-defined-router-flavor a717c92c-63f7-47e8-9efb-6ad0d61c4875

#. Create routers specifying user-defined flavors. Please note the `ha`
   characteristics of the routers created:

   .. code-block:: console

      $ openstack router create router-of-user-defined-flavor-noha --no-ha --external-gateway public --flavor-id 65df2587-c535-4c3a-af2f-86b2968a3191 --max-width 100
      +---------------------------+----------------------------------------------------------------------+
      | Field                     | Value                                                                |
      +---------------------------+----------------------------------------------------------------------+
      | admin_state_up            | UP                                                                   |
      | availability_zone_hints   |                                                                      |
      | availability_zones        |                                                                      |
      | created_at                | 2024-03-27T00:31:56Z                                                 |
      | description               |                                                                      |
      | enable_default_route_bfd  | False                                                                |
      | enable_default_route_ecmp | False                                                                |
      | enable_ndp_proxy          | None                                                                 |
      | external_gateway_info     | {"network_id": "f1898eb8-54af-4704-8ce2-cf58d37cd1e1",               |
      |                           | "external_fixed_ips": [{"subnet_id":                                 |
      |                           | "5f2b4aac-7ef4-4e8a-bd80-a5e1e640e16b", "ip_address":                |
      |                           | "172.24.8.113"}, {"subnet_id":                                       |
      |                           | "07227d2b-f102-4788-97f8-a8e8f1b0f6ae", "ip_address":                |
      |                           | "2001:db8::234"}], "enable_snat": true}                              |
      | external_gateways         | [{'network_id': 'f1898eb8-54af-4704-8ce2-cf58d37cd1e1',              |
      |                           | 'external_fixed_ips': [{'ip_address': '172.24.8.113', 'subnet_id':   |
      |                           | '5f2b4aac-7ef4-4e8a-bd80-a5e1e640e16b'}, {'ip_address':              |
      |                           | '2001:db8::234', 'subnet_id':                                        |
      |                           | '07227d2b-f102-4788-97f8-a8e8f1b0f6ae'}]}]                           |
      | flavor_id                 | 65df2587-c535-4c3a-af2f-86b2968a3191                                 |
      | ha                        | False                                                                |
      | id                        | 66399600-d4c6-4d25-a05f-10789bf86b2d                                 |
      | name                      | router-of-user-defined-flavor-noha                                   |
      | project_id                | d458a40ca6d54aa6b2b92721badc9f48                                     |
      | revision_number           | 3                                                                    |
      | routes                    |                                                                      |
      | status                    | ACTIVE                                                               |
      | tags                      |                                                                      |
      | tenant_id                 | d458a40ca6d54aa6b2b92721badc9f48                                     |
      | updated_at                | 2024-03-27T00:31:56Z                                                 |
      +---------------------------+----------------------------------------------------------------------+

      $ openstack router create router-of-user-defined-flavor-ha --ha --external-gateway public --flavor-id 65df2587-c535-4c3a-af2f-86b2968a3191 --max-width 100
      +---------------------------+----------------------------------------------------------------------+
      | Field                     | Value                                                                |
      +---------------------------+----------------------------------------------------------------------+
      | admin_state_up            | UP                                                                   |
      | availability_zone_hints   |                                                                      |
      | availability_zones        |                                                                      |
      | created_at                | 2024-03-27T00:38:47Z                                                 |
      | description               |                                                                      |
      | enable_default_route_bfd  | False                                                                |
      | enable_default_route_ecmp | False                                                                |
      | enable_ndp_proxy          | None                                                                 |
      | external_gateway_info     | {"network_id": "f1898eb8-54af-4704-8ce2-cf58d37cd1e1",               |
      |                           | "external_fixed_ips": [{"subnet_id":                                 |
      |                           | "5f2b4aac-7ef4-4e8a-bd80-a5e1e640e16b", "ip_address":                |
      |                           | "172.24.8.212"}, {"subnet_id":                                       |
      |                           | "07227d2b-f102-4788-97f8-a8e8f1b0f6ae", "ip_address":                |
      |                           | "2001:db8::20a"}], "enable_snat": true}                              |
      | external_gateways         | [{'network_id': 'f1898eb8-54af-4704-8ce2-cf58d37cd1e1',              |
      |                           | 'external_fixed_ips': [{'ip_address': '172.24.8.212', 'subnet_id':   |
      |                           | '5f2b4aac-7ef4-4e8a-bd80-a5e1e640e16b'}, {'ip_address':              |
      |                           | '2001:db8::20a', 'subnet_id':                                        |
      |                           | '07227d2b-f102-4788-97f8-a8e8f1b0f6ae'}]}]                           |
      | flavor_id                 | 65df2587-c535-4c3a-af2f-86b2968a3191                                 |
      | ha                        | True                                                                 |
      | id                        | 036e639b-f087-418d-9087-5a94c45453b9                                 |
      | name                      | router-of-user-defined-flavor-ha                                     |
      | project_id                | d458a40ca6d54aa6b2b92721badc9f48                                     |
      | revision_number           | 3                                                                    |
      | routes                    |                                                                      |
      | status                    | ACTIVE                                                               |
      | tags                      |                                                                      |
      | tenant_id                 | d458a40ca6d54aa6b2b92721badc9f48                                     |
      | updated_at                | 2024-03-27T00:38:48Z                                                 |
      +---------------------------+----------------------------------------------------------------------+

      $ openstack router create router-of-user-defined-flavor-noha-implicit --external-gateway public --flavor-id 65df2587-c535-4c3a-af2f-86b2968a3191 --max-width 100
      +---------------------------+----------------------------------------------------------------------+
      | Field                     | Value                                                                |
      +---------------------------+----------------------------------------------------------------------+
      | admin_state_up            | UP                                                                   |
      | availability_zone_hints   |                                                                      |
      | availability_zones        |                                                                      |
      | created_at                | 2024-03-27T00:40:52Z                                                 |
      | description               |                                                                      |
      | enable_default_route_bfd  | False                                                                |
      | enable_default_route_ecmp | False                                                                |
      | enable_ndp_proxy          | None                                                                 |
      | external_gateway_info     | {"network_id": "f1898eb8-54af-4704-8ce2-cf58d37cd1e1",               |
      |                           | "external_fixed_ips": [{"subnet_id":                                 |
      |                           | "5f2b4aac-7ef4-4e8a-bd80-a5e1e640e16b", "ip_address":                |
      |                           | "172.24.8.80"}, {"subnet_id":                                        |
      |                           | "07227d2b-f102-4788-97f8-a8e8f1b0f6ae", "ip_address":                |
      |                           | "2001:db8::19c"}], "enable_snat": true}                              |
      | external_gateways         | [{'network_id': 'f1898eb8-54af-4704-8ce2-cf58d37cd1e1',              |
      |                           | 'external_fixed_ips': [{'ip_address': '172.24.8.80', 'subnet_id':    |
      |                           | '5f2b4aac-7ef4-4e8a-bd80-a5e1e640e16b'}, {'ip_address':              |
      |                           | '2001:db8::19c', 'subnet_id':                                        |
      |                           | '07227d2b-f102-4788-97f8-a8e8f1b0f6ae'}]}]                           |
      | flavor_id                 | 65df2587-c535-4c3a-af2f-86b2968a3191                                 |
      | ha                        | False                                                                |
      | id                        | ad2ab001-fc3a-4a3b-a9f0-8ad4f41f54dc                                 |
      | name                      | router-of-user-defined-flavor-noha-implicit                          |
      | project_id                | d458a40ca6d54aa6b2b92721badc9f48                                     |
      | revision_number           | 3                                                                    |
      | routes                    |                                                                      |
      | status                    | ACTIVE                                                               |
      | tags                      |                                                                      |
      | tenant_id                 | d458a40ca6d54aa6b2b92721badc9f48                                     |
      | updated_at                | 2024-03-27T00:40:53Z                                                 |
      +---------------------------+----------------------------------------------------------------------+

#. Create an OVN flavor router to verify it co-exists with the user-defined
   flavors:

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
      | ha                      | True                                                                   |
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

   .. note::
      OVN routers are natively highly available at the OVN/OVS level, through
      the use of BFD monitoring. Neutron doesn't get involved in the high
      availability aspect beyond router scheduling. For this reason, the `ha`
      attribute is associated to routers of the default OVN flavor and is
      always set to `True`. This is done for consistency with user defined
      flavors routers for which the `ha` attribute will be `True` or `False`,
      depending on the characteristics of the router.

#. List routers to verify:

   .. code-block:: console

      $ openstack router list
      +--------------------------------------+---------------------------------------------+--------+-------+----------------------------------+-------+
      | ID                                   | Name                                        | Status | State | Project                          | HA    |
      +--------------------------------------+---------------------------------------------+--------+-------+----------------------------------+-------+
      | 21889ed3-b8df-4b0e-9a64-92ba9fab655d | ovn-flavor-router                           | ACTIVE | UP    | b807321af03f44dc808ff06bbc845804 | True  |
      | 66399600-d4c6-4d25-a05f-10789bf86b2d | router-of-user-defined-flavor-noha          | ACTIVE | UP    | d458a40ca6d54aa6b2b92721badc9f48 | False |
      | 036e639b-f087-418d-9087-5a94c45453b9 | router-of-user-defined-flavor-ha            | ACTIVE | UP    | d458a40ca6d54aa6b2b92721badc9f48 | True  |
      | ad2ab001-fc3a-4a3b-a9f0-8ad4f41f54dc | router-of-user-defined-flavor-noha-implicit | ACTIVE | UP    | d458a40ca6d54aa6b2b92721badc9f48 | False |
      +--------------------------------------+---------------------------------------------+--------+-------+----------------------------------+-------+
