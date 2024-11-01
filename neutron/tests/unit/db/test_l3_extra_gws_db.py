# Copyright (c) 2023 Canonical Ltd.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from unittest import mock

import copy

import netaddr

from neutron_lib.api.definitions import external_net as enet_apidef
from neutron_lib.api.definitions import l3 as l3_apidef
from neutron_lib.api.definitions import l3_ext_gw_mode
from neutron_lib.api.definitions import l3_ext_gw_multihoming
from neutron_lib import constants
from neutron_lib.db import api as db_api
from neutron_lib import exceptions
from neutron_lib.utils import net as net_utils
from oslo_utils import uuidutils

from neutron.db import l3_extra_gws_db
from neutron.db.models import l3 as l3_models
from neutron.ipam import exceptions as ipam_exceptions
from neutron.objects import ipam as ipam_obj
from neutron.objects import network as net_obj
from neutron.objects import ports as port_obj
from neutron.objects import router as l3_obj
from neutron.objects import subnet as subnet_obj
from neutron.tests.unit.extensions import test_l3
from neutron.tests.unit import testlib_api

_uuid = uuidutils.generate_uuid


class TestDbIntPlugin(test_l3.TestL3NatIntPlugin,
                      l3_extra_gws_db.ExtraGatewaysMixinDbMixin):

    supported_extension_aliases = [enet_apidef.ALIAS, l3_apidef.ALIAS,
                                   l3_ext_gw_mode.ALIAS,
                                   l3_ext_gw_multihoming.ALIAS]


class TestExtraGatewaysDb(testlib_api.SqlTestCase):

    def setUp(self):
        super().setUp()
        plugin = __name__ + '.' + TestDbIntPlugin.__name__
        self.setup_coreplugin(plugin)
        self.target_object = TestDbIntPlugin()
        # Patch the context
        ctx_patcher = mock.patch('neutron_lib.context', autospec=True)
        mock_context = ctx_patcher.start()
        self.context = mock_context.get_admin_context()
        self.context.elevated.return_value = self.context
        self.context.session = db_api.get_writer_session()

        # Create a simple setup with one external network and a subnet on it.
        self.ext_net_a_id = _uuid()
        self.ext_sub_a_id = _uuid()
        self.tenant_id = _uuid()

        self.network_a = net_obj.Network(
            self.context,
            id=self.ext_net_a_id,
            project_id=self.tenant_id,
            admin_state_up=True,
            status=constants.NET_STATUS_ACTIVE)
        self.network_a.create()
        self.net_ext_a = net_obj.ExternalNetwork(
            self.context, network_id=self.ext_net_a_id)
        self.net_ext_a.create()
        self.ext_sub_a = subnet_obj.Subnet(self.context,
                                           id=self.ext_sub_a_id,
                                           project_id=self.tenant_id,
                                           ip_version=constants.IP_VERSION_4,
                                           cidr=net_utils.AuthenticIPNetwork(
                                               '192.0.2.0/25'),
                                           gateway_ip=netaddr.IPAddress(
                                               '192.0.2.1'),
                                           network_id=self.ext_net_a_id)
        self.ext_sub_a.create()

        self.ext_net_b_id = _uuid()
        self.ext_sub_b_id = _uuid()
        self.network_b = net_obj.Network(
            self.context,
            id=self.ext_net_b_id,
            project_id=self.tenant_id,
            admin_state_up=True,
            status=constants.NET_STATUS_ACTIVE)
        self.network_b.create()
        self.net_ext_b = net_obj.ExternalNetwork(
            self.context, network_id=self.ext_net_b_id)
        self.net_ext_b.create()

        self.ext_sub_b = subnet_obj.Subnet(
            self.context,
            id=self.ext_sub_b_id,
            project_id=self.tenant_id,
            ip_version=constants.IP_VERSION_4,
            cidr=net_utils.AuthenticIPNetwork('192.0.2.128/25'),
            gateway_ip=netaddr.IPAddress('192.0.2.129'),
            network_id=self.ext_net_b_id)
        self.ext_sub_b.create()

        self.ext_net_c_id = _uuid()
        self.ext_sub_c_id = _uuid()
        self.network_c = net_obj.Network(
            self.context,
            id=self.ext_net_c_id,
            project_id=self.tenant_id,
            admin_state_up=True,
            status=constants.NET_STATUS_ACTIVE)
        self.network_c.create()
        self.net_ext_c = net_obj.ExternalNetwork(
            self.context, network_id=self.ext_net_c_id)
        self.net_ext_c.create()

        self.ext_sub_c = subnet_obj.Subnet(
            self.context,
            id=self.ext_sub_c_id,
            project_id=self.tenant_id,
            ip_version=constants.IP_VERSION_4,
            # Overlaps with subnet A above on purpose for overlap testing.
            cidr=net_utils.AuthenticIPNetwork('192.0.2.0/25'),
            gateway_ip=netaddr.IPAddress('192.0.2.1'),
            network_id=self.ext_net_c_id)
        self.ext_sub_c.create()

        # Create an IPAM subnet for fixed ip allocations.
        self.ipam_ext_subnet_a = ipam_obj.IpamSubnet(
            self.context,
            neutron_subnet_id=self.ext_sub_a_id)
        self.ipam_ext_subnet_a.create()

        self.ipam_ext_subnet_b = ipam_obj.IpamSubnet(
            self.context,
            neutron_subnet_id=self.ext_sub_b_id)
        self.ipam_ext_subnet_b.create()

        self.ipam_ext_subnet_c = ipam_obj.IpamSubnet(
            self.context,
            neutron_subnet_id=self.ext_sub_c_id)
        self.ipam_ext_subnet_c.create()

        # Create an allocation pool that will use the IPAM subnet.
        self.ipam_ext_pool_a = ipam_obj.IpamAllocationPool(
            self.context,
            id=_uuid(),
            ipam_subnet_id=self.ipam_ext_subnet_a.id,
            first_ip='192.0.2.3',
            last_ip='192.0.2.126',
        )
        self.ipam_ext_pool_a.create()

        self.ipam_ext_pool_b = ipam_obj.IpamAllocationPool(
            self.context,
            id=_uuid(),
            ipam_subnet_id=self.ipam_ext_subnet_b.id,
            first_ip='192.0.2.131',
            last_ip='192.0.2.254',
        )
        self.ipam_ext_pool_b.create()

        self.ipam_ext_pool_c = ipam_obj.IpamAllocationPool(
            self.context,
            id=_uuid(),
            ipam_subnet_id=self.ipam_ext_subnet_c.id,
            first_ip='192.0.2.3',
            last_ip='192.0.2.126',
        )
        self.ipam_ext_pool_c.create()

        # Create a router that will be modified during the tests.
        self.router = l3_models.Router(
            id=_uuid(),
            name=None,
            tenant_id=self.tenant_id,
            admin_state_up=True,
            status=constants.NET_STATUS_ACTIVE,
            enable_snat=True,
            gw_port_id=None)

        self.context.session.add(self.router)
        self.context.session.expire_all()
        self.context.session.commit()

    def test_add_external_gateways_trivial(self):
        ext_gws = []
        body = {
            "router": {
                "external_gateways": ext_gws
            }
        }
        # A trivial case with an empty list passed in.
        result = self.target_object._add_external_gateways(
            self.context, self.router.id, ext_gws, body)
        self.assertEqual([], result)

    def test_add_external_gateways_single(self):
        ext_gws = [{"network_id": self.ext_net_a_id}]
        body = {
            "router": {
                "external_gateways": ext_gws
            }
        }

        result = self.target_object.add_external_gateways(
            self.context, self.router.id, body)

        res_gw_a = result['router']['external_gateways'][0]

        self.assertEqual(res_gw_a['network_id'], self.ext_net_a_id)
        self.assertIsNotNone(res_gw_a['external_fixed_ips'])

        new_router = self.target_object.get_router(self.context,
                                                   self.router.id)
        new_gw_info = new_router['external_gateway_info']
        self.assertEqual(new_gw_info['network_id'], self.ext_net_a_id)
        self.assertIsNotNone(new_gw_info['external_fixed_ips'])

        gw_ports = port_obj.Port.get_ports_by_router_and_network(
            self.context, self.router.id, constants.DEVICE_OWNER_ROUTER_GW,
            self.ext_net_a_id)
        self.assertEqual(len(gw_ports), 1)

        gw_port = gw_ports[0]
        self.assertEqual(new_router['gw_port_id'], gw_port['id'])

    def test_add_external_gateways_multiple(self):
        ext_gws = [
            {"network_id": self.ext_net_a_id},
            {"network_id": self.ext_net_b_id},
        ]
        body = {
            "router": {
                "external_gateways": ext_gws
            }
        }

        result = self.target_object.add_external_gateways(
            self.context, self.router.id, body)

        res_gw_a = result['router']['external_gateways'][0]
        res_gw_b = result['router']['external_gateways'][1]

        self.assertEqual(res_gw_a['network_id'], self.ext_net_a_id)
        self.assertEqual(res_gw_b['network_id'], self.ext_net_b_id)
        self.assertIsNotNone(res_gw_a['external_fixed_ips'])
        self.assertIsNotNone(res_gw_b['external_fixed_ips'])

        new_router = self.target_object.get_router(self.context,
                                                   self.router.id)

        new_gw_info = new_router['external_gateway_info']
        self.assertEqual(new_gw_info['network_id'], self.ext_net_a_id)
        self.assertIsNotNone(new_gw_info['external_fixed_ips'])

        gw_ports = l3_obj.RouterPort.get_objects(
            self.context,
            **{'router_id': self.router.id,
               'port_type': constants.DEVICE_OWNER_ROUTER_GW})

        self.assertEqual(len(gw_ports), 2)

        # Now check that calling the ADD API multiple times succeeds.
        ext_gws = [
            {"network_id": self.ext_net_b_id},
        ]
        body = {
            "router": {
                "external_gateways": ext_gws
            }
        }
        result = self.target_object.add_external_gateways(
            self.context, self.router.id, body)

        res_gw_a = result['router']['external_gateways'][0]
        res_gw_b = result['router']['external_gateways'][1]
        res_gw_c = result['router']['external_gateways'][2]

        self.assertEqual(res_gw_a['network_id'], self.ext_net_a_id)
        self.assertEqual(res_gw_b['network_id'], self.ext_net_b_id)
        self.assertEqual(res_gw_c['network_id'], self.ext_net_b_id)
        self.assertIsNotNone(res_gw_a['external_fixed_ips'])
        self.assertIsNotNone(res_gw_b['external_fixed_ips'])
        self.assertIsNotNone(res_gw_c['external_fixed_ips'])

        new_router = self.target_object.get_router(self.context,
                                                   self.router.id)

        new_gw_info = new_router['external_gateway_info']
        self.assertEqual(new_gw_info['network_id'], self.ext_net_a_id)
        self.assertIsNotNone(new_gw_info['external_fixed_ips'])

        gw_ports = l3_obj.RouterPort.get_objects(
            self.context,
            **{'router_id': self.router.id,
               'port_type': constants.DEVICE_OWNER_ROUTER_GW})

        self.assertEqual(len(gw_ports), 3)

        # Check that adding a gateway with already allocated fixed IPs fails.
        ext_gws = [
            {"network_id": self.ext_net_b_id,
             "external_fixed_ips": res_gw_c['external_fixed_ips']},
        ]
        body = {
            "router": {
                "external_gateways": ext_gws
            }
        }
        self.assertRaises(
            ipam_exceptions.IpAddressAlreadyAllocated,
            self.target_object.add_external_gateways, self.context,
            self.router.id, body
        )

    def test_remove_external_gateways_trivial(self):
        ext_gws = []
        body = {
            "router": {
                "external_gateways": ext_gws
            }
        }
        # A trivial case with an empty list passed in.
        result = self.target_object.remove_external_gateways(
            self.context, self.router.id, body)
        self.assertIsNone(result['router']['external_gateway_info'])

    def test_remove_external_gateways_single(self):
        ext_gws = [{"network_id": self.ext_net_a_id}]
        body = {
            "router": {
                "external_gateways": ext_gws
            }
        }
        self.target_object.add_external_gateways(
            self.context, self.router.id, body)
        self.assertIsNotNone(self.router.gw_port_id)

        result = self.target_object.remove_external_gateways(
            self.context, self.router.id, body)
        self.assertIsNone(self.router.gw_port_id)
        self.assertIsNone(result['router']['external_gateway_info'])

    def test_remove_external_gateways_multiple(self):
        ext_gws = [
            {"network_id": self.ext_net_a_id},
            {"network_id": self.ext_net_b_id},
        ]
        body = {
            "router": {
                "external_gateways": ext_gws
            }
        }

        self.target_object.add_external_gateways(
            self.context, self.router.id, body)
        self.assertIsNotNone(self.router.gw_port_id)

        gw_ports = l3_obj.RouterPort.get_objects(
            self.context,
            **{'router_id': self.router.id,
               'port_type': constants.DEVICE_OWNER_ROUTER_GW})
        self.assertEqual(len(gw_ports), 2)

        result = self.target_object.remove_external_gateways(
            self.context, self.router.id, body)
        self.assertIsNone(self.router.gw_port_id)
        self.assertIsNone(result['router']['external_gateway_info'])

        gw_ports = l3_obj.RouterPort.get_objects(
            self.context,
            **{'router_id': self.router.id,
               'port_type': constants.DEVICE_OWNER_ROUTER_GW})
        self.assertEqual(len(gw_ports), 0)

    def test_remove_external_gateways_remove_compat(self):
        '''Test removal of a compatibility gateway port using the new API.

        When removing a compatibility gateway port using the new API we need
        to make sure that an existing extra gateway port takes it place instead
        as a compatibility gateway port.
        '''
        ext_gws = [
            {"network_id": self.ext_net_a_id},
            {"network_id": self.ext_net_b_id},
        ]
        add_body = {
            "router": {
                "external_gateways": ext_gws
            }
        }
        remove_body = {
            "router": {
                "external_gateways": ext_gws[:1]
            }
        }

        self.target_object.add_external_gateways(
            self.context, self.router.id, add_body)
        self.assertIsNotNone(self.router.gw_port_id)

        old_gw_port_id = self.router.gw_port_id

        gw_ports = l3_obj.RouterPort.get_objects(
            self.context,
            **{'router_id': self.router.id,
               'port_type': constants.DEVICE_OWNER_ROUTER_GW})
        self.assertEqual(len(gw_ports), 2)

        self.target_object.remove_external_gateways(
            self.context, self.router.id, remove_body)

        gw_ports = l3_obj.RouterPort.get_objects(
            self.context,
            **{'router_id': self.router.id,
               'port_type': constants.DEVICE_OWNER_ROUTER_GW})
        self.assertEqual(len(gw_ports), 1)

        new_router = self.target_object.get_router(self.context,
                                                   self.router.id)
        self.assertNotEqual(old_gw_port_id, new_router['gw_port_id'])
        self.assertEqual(new_router['external_gateway_info']['network_id'],
                         self.ext_net_b_id)

    def test_update_external_gateways_add_pristine_and_remove(self):
        '''Test the addition of external gateway ports using the update API.'''
        ext_gws = [
            {"network_id": self.ext_net_a_id},
            {"network_id": self.ext_net_b_id},
        ]
        add_body = {
            "router": {
                "external_gateways": ext_gws
            }
        }

        result = self.target_object.update_external_gateways(
            self.context, self.router.id, add_body)
        self.assertIsNotNone(self.router.gw_port_id)

        res_gw_a = result['router']['external_gateways'][0]
        res_gw_b = result['router']['external_gateways'][1]
        self.assertEqual(res_gw_a['network_id'], self.ext_net_a_id)
        self.assertEqual(res_gw_b['network_id'], self.ext_net_b_id)
        self.assertIsNotNone(res_gw_a['external_fixed_ips'])
        self.assertIsNotNone(res_gw_b['external_fixed_ips'])

        new_router = self.target_object.get_router(self.context,
                                                   self.router.id)

        new_gw_info = new_router['external_gateway_info']
        self.assertEqual(new_gw_info['network_id'], self.ext_net_a_id)
        self.assertIsNotNone(new_gw_info['external_fixed_ips'])

        gw_ports = l3_obj.RouterPort.get_objects(
            self.context,
            **{'router_id': self.router.id,
               'port_type': constants.DEVICE_OWNER_ROUTER_GW})

        self.assertEqual(len(gw_ports), 2)

        # Reorder gateways.
        ext_gws = [
            {"network_id": self.ext_net_b_id},
            {"network_id": self.ext_net_a_id},
        ]
        update_body = {
            "router": {
                "external_gateways": ext_gws
            }
        }
        result = self.target_object.update_external_gateways(
            self.context, self.router.id, update_body)
        self.assertIsNotNone(self.router.gw_port_id)

        new_router = self.target_object.get_router(self.context,
                                                   self.router.id)
        new_gw_info = new_router['external_gateway_info']
        self.assertEqual(new_gw_info['network_id'], self.ext_net_b_id)
        self.assertIsNotNone(new_gw_info['external_fixed_ips'])

        # The compat gateway should now have a different network_id.
        res_gw_b = result['router']['external_gateways'][0]
        res_gw_a = result['router']['external_gateways'][1]
        self.assertEqual(res_gw_b['network_id'], self.ext_net_b_id)
        self.assertEqual(res_gw_a['network_id'], self.ext_net_a_id)
        self.assertIsNotNone(res_gw_a['external_fixed_ips'])
        self.assertIsNotNone(res_gw_b['external_fixed_ips'])

        # Remove one gateway.
        update_body = {
            "router": {
                "external_gateways": ext_gws[1:]
            }
        }

        result = self.target_object.update_external_gateways(
            self.context, self.router.id, update_body)
        self.assertIsNotNone(self.router.gw_port_id)

        new_router = self.target_object.get_router(self.context,
                                                   self.router.id)
        new_gw_info = new_router['external_gateway_info']
        self.assertEqual(new_gw_info['network_id'], self.ext_net_a_id)
        self.assertIsNotNone(new_gw_info['external_fixed_ips'])

        res_gw_a = result['router']['external_gateways'][0]
        self.assertEqual(res_gw_a['network_id'], self.ext_net_a_id)
        self.assertIsNotNone(res_gw_a['external_fixed_ips'])

        # Clear all gateways.
        update_body = {
            "router": {
                "external_gateways": {}
            }
        }

        result = self.target_object.update_external_gateways(
            self.context, self.router.id, update_body)
        self.assertIsNone(self.router.gw_port_id)

    def test_compat_remove_via_update(self):
        '''Test the removal of a gateway port using the compat API.

        Removal of a compat gateway in the presence of an extra
        gateway port should make that extra gateway port a compat
        gateway port.
        '''
        ext_gws = [
            {"network_id": self.ext_net_a_id},
            {"network_id": self.ext_net_b_id},
        ]
        body = {
            "router": {
                "external_gateways": ext_gws
            }
        }

        result = self.target_object.add_external_gateways(
            self.context, self.router.id, body)

        update_body = {
            "router": {
                "external_gateway_info": {}
            }
        }
        # Now perform an update with an empty gw info to remove the current
        # compat gw port.
        result = self.target_object.update_router(self.context, self.router.id,
                                                  update_body)

        # The existing extra gateway port should now take its place.
        res_gw = result['external_gateways'][0]
        self.assertEqual(res_gw['network_id'], self.ext_net_b_id)
        self.assertIsNotNone(res_gw['external_fixed_ips'])
        self.assertEqual(len(result['external_gateways']), 1)

        new_router = self.target_object.get_router(self.context,
                                                   self.router.id)

        new_gw_info = new_router['external_gateway_info']
        self.assertEqual(new_gw_info['network_id'], self.ext_net_b_id)
        self.assertIsNotNone(new_gw_info['external_fixed_ips'])

        gw_ports = l3_obj.RouterPort.get_objects(
            self.context,
            **{'router_id': self.router.id,
               'port_type': constants.DEVICE_OWNER_ROUTER_GW})

        self.assertEqual(len(gw_ports), 1)

    def test_update_fixed_ip(self):
        '''Test updating a fixed IP of an existing port.'''
        ext_gws = [
            {"network_id": self.ext_net_a_id},
            {"network_id": self.ext_net_b_id},
        ]
        body = {
            "router": {
                "external_gateways": ext_gws
            }
        }

        result = self.target_object.add_external_gateways(
            self.context, self.router.id, body)

        gw_ports_initial = [o.port_id for o in l3_obj.RouterPort.get_objects(
            self.context,
            **{'router_id': self.router.id,
               'port_type': constants.DEVICE_OWNER_ROUTER_GW})]

        fips = copy.deepcopy(
            result['router']['external_gateways'][1]['external_fixed_ips'])
        # Append a fixed ip not used in the allocation pool. The existing
        # one should be used to find an existing port.
        fips.append({'ip_address': '192.0.2.130',
                     'subnet_id': fips[0]['subnet_id']})
        expected_fips = copy.deepcopy(fips)

        update_body = {
            "router": {
                "external_gateways": [
                    {"network_id": self.ext_net_a_id},
                    # Use the new set of fixed IPs in the request.
                    {"network_id": self.ext_net_b_id,
                     "external_fixed_ips": fips},
                ]}
        }
        result = self.target_object.update_external_gateways(
            self.context, self.router.id,
            update_body)

        self.assertCountEqual(
            result['router']['external_gateways'][1]['external_fixed_ips'],
            expected_fips,
        )

        gw_ports_final = [o.port_id for o in l3_obj.RouterPort.get_objects(
            self.context,
            **{'router_id': self.router.id,
               'port_type': constants.DEVICE_OWNER_ROUTER_GW})]

        # Make sure the ports are not recreated in the process, i.e. port IDs
        # stay the same.
        self.assertCountEqual(
            gw_ports_initial,
            gw_ports_final,
        )

    def test_add_external_gateways_overlapping_subnets(self):
        ext_gws = [
            {"network_id": self.ext_net_a_id},
        ]
        body = {
            "router": {
                "external_gateways": ext_gws
            }
        }

        self.target_object.add_external_gateways(self.context, self.router.id,
                                                 body)

        ext_gws = [
            {"network_id": self.ext_net_c_id},
        ]
        body = {
            "router": {
                "external_gateways": ext_gws
            }
        }

        self.assertRaisesRegex(
            exceptions.BadRequest,
            'Bad router request: Cidr 192.0.2.0/25 of subnet'
            f' {self.ext_sub_c_id} overlaps with cidr 192.0.2.0/25 of '
            f'subnet {self.ext_sub_a_id}.',
            self.target_object.add_external_gateways, self.context,
            self.router.id, body
        )
