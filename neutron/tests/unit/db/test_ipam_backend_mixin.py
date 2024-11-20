# Copyright (c) 2015 Infoblox Inc.
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

import netaddr
from neutron_lib.api.definitions import portbindings
from neutron_lib import constants
from neutron_lib import exceptions as exc
from neutron_lib.exceptions import address_scope as addr_scope_exc
from oslo_utils import uuidutils
import webob.exc

from neutron.common.ovn import constants as ovn_const
from neutron.db import ipam_backend_mixin
from neutron.objects import subnet as subnet_obj
from neutron.plugins.ml2 import plugin as ml2_plugin
from neutron.services.segments import db as segments_db
from neutron.tests import base
from neutron.tests.common import test_db_base_plugin_v2


class TestIpamBackendMixin(base.BaseTestCase):

    def setUp(self):
        super().setUp()
        self.mixin = ipam_backend_mixin.IpamBackendMixin()
        self.ctx = mock.Mock()
        self.default_new_ips = (('id-1', '192.168.1.1'),
                                ('id-2', '192.168.1.2'))
        self.default_original_ips = (('id-1', '192.168.1.1'),
                                     ('id-5', '172.20.16.5'))
        self.owner_non_router = constants.DEVICE_OWNER_DHCP
        self.owner_router = constants.DEVICE_OWNER_ROUTER_INTF

    def _prepare_ips(self, ips):
        results = []
        for ip in ips:
            ip_dict = {'ip_address': ip[1],
                       'subnet_id': ip[0]}
            if len(ip) > 2:
                ip_dict['delete_subnet'] = ip[2]
            results.append(ip_dict)
        return results

    def _mock_slaac_subnet_on(self):
        slaac_subnet_obj = subnet_obj.Subnet(
            self.ctx,
            ipv6_address_mode=constants.IPV6_SLAAC,
            ipv6_ra_mode=constants.IPV6_SLAAC)
        self.mixin._get_subnet_object = mock.Mock(
            return_value=slaac_subnet_obj)

    def _mock_slaac_subnet_off(self):
        non_slaac_subnet_obj = subnet_obj.Subnet(
            self.ctx,
            ipv6_address_mode=None,
            ipv6_ra_mode=None)
        self.mixin._get_subnet_object = mock.Mock(
            return_value=non_slaac_subnet_obj)

    def _mock_slaac_for_subnet_ids(self, subnet_ids):
        """Mock incoming subnets as autoaddressed."""
        def _get_subnet_object(context, subnet_id):
            if subnet_id in subnet_ids:
                return subnet_obj.Subnet(
                    self.ctx,
                    ipv6_address_mode=constants.IPV6_SLAAC,
                    ipv6_ra_mode=constants.IPV6_SLAAC)
            return subnet_obj.Subnet(
                self.ctx, ipv6_address_mode=None, ipv6_ra_mode=None)

        self.mixin._get_subnet_object = mock.Mock(
            side_effect=_get_subnet_object)

    def test__is_distributed_service(self):
        uuid = uuidutils.generate_uuid()
        port = {'device_owner':
                '%snova' % constants.DEVICE_OWNER_COMPUTE_PREFIX,
                'device_id': uuid}
        self.assertFalse(self.mixin._is_distributed_service(port))
        port = {'device_owner': constants.DEVICE_OWNER_DHCP,
                'device_id': uuid}
        self.assertFalse(self.mixin._is_distributed_service(port))
        port = {'device_owner': constants.DEVICE_OWNER_DHCP,
                'device_id': ovn_const.OVN_METADATA_PREFIX + uuid}
        self.assertFalse(self.mixin._is_distributed_service(port))
        port = {'device_owner': constants.DEVICE_OWNER_DISTRIBUTED,
                'device_id': ovn_const.OVN_METADATA_PREFIX + uuid}
        self.assertTrue(self.mixin._is_distributed_service(port))

    def _test_get_changed_ips_for_port(self, expected, original_ips,
                                       new_ips, owner):
        change = self.mixin._get_changed_ips_for_port(self.ctx,
                                                      original_ips,
                                                      new_ips,
                                                      owner)

        self.assertCountEqual(expected.add, change.add)
        self.assertCountEqual(expected.original, change.original)
        self.assertCountEqual(expected.remove, change.remove)

    def test__get_changed_ips_for_port(self):
        new_ips = self._prepare_ips(self.default_new_ips)
        original_ips = self._prepare_ips(self.default_original_ips)

        expected_change = self.mixin.Changes(add=[new_ips[1]],
                                             original=[original_ips[0]],
                                             remove=[original_ips[1]])
        self._test_get_changed_ips_for_port(expected_change, original_ips,
                                            new_ips, self.owner_router)

    def test__get_changed_ips_for_port_autoaddress(self):
        new_ips = self._prepare_ips(self.default_new_ips)

        original = (('id-1', '192.168.1.1'),
                    ('id-5', '2000:1234:5678::12FF:FE34:5678'))
        original_ips = self._prepare_ips(original)

        self._mock_slaac_subnet_on()

        expected_change = self.mixin.Changes(add=[new_ips[1]],
                                             original=original_ips,
                                             remove=[])
        self._test_get_changed_ips_for_port(expected_change, original_ips,
                                            new_ips, self.owner_non_router)

    def test__get_changed_ips_for_port_remove_autoaddress(self):
        new = (('id-5', '2000:1234:5678::12FF:FE34:5678', True),
               ('id-1', '192.168.1.1'))
        new_ips = self._prepare_ips(new)
        reference_ips = [ip for ip in new_ips
                         if ip['subnet_id'] == 'id-1']

        original = (('id-5', '2000:1234:5678::12FF:FE34:5678'),)
        original_ips = self._prepare_ips(original)

        # mock ipv6 subnet as auto addressed and leave ipv4 as regular
        self._mock_slaac_for_subnet_ids([new[0][0]])
        # Autoaddressed ip allocation has to be removed
        # if it has 'delete_subnet' flag set to True
        expected_change = self.mixin.Changes(add=reference_ips,
                                             original=[],
                                             remove=original_ips)
        self._test_get_changed_ips_for_port(expected_change, original_ips,
                                            new_ips, self.owner_non_router)

    def test__get_changed_ips_for_port_autoaddress_ipv6_pd_enabled(self):
        owner_not_router = constants.DEVICE_OWNER_DHCP
        new_ips = self._prepare_ips(self.default_new_ips)

        original = (('id-1', '192.168.1.1'),
                    ('id-5', '2000:1234:5678::12FF:FE34:5678'))
        original_ips = self._prepare_ips(original)

        # mock to test auto address part
        pd_subnet_obj = subnet_obj.Subnet(
            self.ctx,
            id=uuidutils.generate_uuid(),
            subnetpool_id=constants.IPV6_PD_POOL_ID,
            ipv6_address_mode=constants.IPV6_SLAAC,
            ipv6_ra_mode=constants.IPV6_SLAAC)
        self.mixin._get_subnet_object = mock.Mock(return_value=pd_subnet_obj)

        # make a copy of original_ips
        # since it is changed by _get_changed_ips_for_port
        expected_change = self.mixin.Changes(add=[new_ips[1]],
                                             original=[original_ips[0]],
                                             remove=[original_ips[1]])

        self._test_get_changed_ips_for_port(expected_change, original_ips,
                                            new_ips, owner_not_router)

    def _test_get_changed_ips_for_port_no_ip_address(self):
        # IP address should be added if only subnet_id is provided,
        # independently from auto_address status for subnet
        new_ips = [{'subnet_id': 'id-3'}]
        original_ips = []

        expected_change = self.mixin.Changes(add=[new_ips[0]],
                                             original=[],
                                             remove=[])
        self._test_get_changed_ips_for_port(expected_change, original_ips,
                                            new_ips, self.owner_non_router)

    def test__get_changed_ips_for_port_no_ip_address_no_slaac(self):
        self._mock_slaac_subnet_off()
        self._test_get_changed_ips_for_port_no_ip_address()

    def test__get_changed_ips_for_port_no_ip_address_slaac(self):
        self._mock_slaac_subnet_on()
        self._test_get_changed_ips_for_port_no_ip_address()

    def test__get_changed_ips_for_port_subnet_id_no_ip(self):
        # If a subnet is specified without an IP address only allocate a new
        # address if one doesn't exist
        self._mock_slaac_subnet_off()
        new_ips = [{'subnet_id': 'id-3'}]
        original_ips = [{'subnet_id': 'id-3', 'ip_address': '4.3.2.1'}]

        expected_change = self.mixin.Changes(
            add=[],
            original=[{'subnet_id': 'id-3', 'ip_address': '4.3.2.1'}],
            remove=[])
        self._test_get_changed_ips_for_port(expected_change, original_ips,
                                            new_ips, self.owner_non_router)

    def test__get_changed_ips_for_port_multiple_ips_one_subnet_add_third(self):
        # If a subnet is specified without an IP address only allocate a new
        # address if one doesn't exist
        self._mock_slaac_subnet_off()
        new_ips = [{'subnet_id': 'id-3', 'ip_address': '4.3.2.1'},
                   {'subnet_id': 'id-3'},
                   {'subnet_id': 'id-3', 'ip_address': '4.3.2.10'}]
        original_ips = [{'subnet_id': 'id-3', 'ip_address': '4.3.2.1'},
                        {'subnet_id': 'id-3', 'ip_address': '4.3.2.10'}]

        expected_change = self.mixin.Changes(
            add=[{'subnet_id': 'id-3'}],
            original=[{'subnet_id': 'id-3', 'ip_address': '4.3.2.1'},
                      {'subnet_id': 'id-3', 'ip_address': '4.3.2.10'}],
            remove=[])
        self._test_get_changed_ips_for_port(expected_change, original_ips,
                                            new_ips, self.owner_non_router)

    def test__get_changed_ips_for_port_multiple_ips_one_subnet_noip(self):
        # If a subnet is specified without an IP address only allocate a new
        # address if one doesn't exist
        self._mock_slaac_subnet_off()
        new_ips = [{'subnet_id': 'id-3'},
                   {'subnet_id': 'id-3'}]
        original_ips = [{'subnet_id': 'id-3', 'ip_address': '4.3.2.1'},
                        {'subnet_id': 'id-3', 'ip_address': '4.3.2.10'}]

        expected_change = self.mixin.Changes(
            add=[],
            original=[{'subnet_id': 'id-3', 'ip_address': '4.3.2.1'},
                      {'subnet_id': 'id-3', 'ip_address': '4.3.2.10'}],
            remove=[])
        self._test_get_changed_ips_for_port(expected_change, original_ips,
                                            new_ips, self.owner_non_router)

    def test__get_changed_ips_for_port_subnet_id_no_ip_ipv6(self):
        # If a subnet is specified without an IP address only allocate a new
        # address if one doesn't exist
        self._mock_slaac_subnet_off()
        new_ips = [{'subnet_id': 'id-3'}]
        original_ips = [{'subnet_id': 'id-3', 'ip_address': '2001:db8::8'}]

        expected_change = self.mixin.Changes(
            add=[],
            original=[{'subnet_id': 'id-3', 'ip_address': '2001:db8::8'}],
            remove=[])
        self._test_get_changed_ips_for_port(expected_change, original_ips,
                                            new_ips, self.owner_non_router)

    def test__get_changed_ips_for_port_subnet_id_no_ip_eui64(self):
        # If a subnet is specified without an IP address allocate a new address
        # if the address is eui-64. This supports changing prefix when prefix
        # delegation is in use.
        self._mock_slaac_subnet_off()
        new_ips = [{'subnet_id': 'id-3'}]
        original_ips = [{'subnet_id': 'id-3',
                         'ip_address': '2001::eeb1:d7ff:fe2c:9c5f'}]

        expected_change = self.mixin.Changes(
            add=[{'subnet_id': 'id-3'}],
            original=[],
            remove=[{'subnet_id': 'id-3',
                     'ip_address': '2001::eeb1:d7ff:fe2c:9c5f'}])
        self._test_get_changed_ips_for_port(expected_change, original_ips,
                                            new_ips, self.owner_non_router)

    def test__is_ip_required_by_subnet_for_router_port(self):
        # Owner -> router:
        # _get_subnet_object should not be called,
        # expected True
        self._mock_slaac_subnet_off()

        result = self.mixin._is_ip_required_by_subnet(self.ctx, 'id',
                                                      self.owner_router)
        self.assertTrue(result)
        self.assertFalse(self.mixin._get_subnet_object.called)

    def test__is_ip_required_by_subnet_for_non_router_port(self):
        # Owner -> not router:
        # _get_subnet_object should be called,
        # expected True, because subnet is not slaac
        self._mock_slaac_subnet_off()

        result = self.mixin._is_ip_required_by_subnet(self.ctx, 'id',
                                                      self.owner_non_router)
        self.assertTrue(result)
        self.assertTrue(self.mixin._get_subnet_object.called)

    def test__is_ip_required_by_subnet_for_non_router_port_and_slaac(self):
        # Owner -> not router:
        # _get_subnet_object should be called,
        # expected False, because subnet is slaac
        self._mock_slaac_subnet_on()

        result = self.mixin._is_ip_required_by_subnet(self.ctx, 'id',
                                                      self.owner_non_router)
        self.assertFalse(result)
        self.assertTrue(self.mixin._get_subnet_object.called)

    def test__validate_network_subnetpools_mismatch_address_scopes(self):
        address_scope_id = "dummy-scope"
        subnetpool = mock.MagicMock()
        address_scope = mock.MagicMock()
        subnetpool.address_scope.return_value = address_scope_id
        address_scope.id.return_value = address_scope_id
        self.assertRaises(addr_scope_exc.NetworkAddressScopeAffinityError,
                          self.mixin._validate_network_subnetpools,
                          mock.MagicMock(),
                          constants.IP_VERSION_4,
                          subnetpool,
                          address_scope)

    def test__validate_network_subnetpools_subnetpool_mismatch(self):
        subnet = mock.MagicMock(ip_version=constants.IP_VERSION_4)
        subnet.subnetpool_id = 'fake-subnetpool'
        network = mock.MagicMock(subnets=[subnet])
        subnetpool = mock.MagicMock(id=uuidutils.generate_uuid())
        subnetpool.ip_version = constants.IP_VERSION_4

        self.assertRaises(exc.NetworkSubnetPoolAffinityError,
                          self.mixin._validate_network_subnetpools,
                          network,
                          constants.IP_VERSION_4,
                          subnetpool,
                          None)


class TestPlugin(ml2_plugin.Ml2Plugin, segments_db.SegmentDbMixin):
    __native_pagination_support = True
    __native_sorting_support = True

    supported_extension_aliases = [portbindings.ALIAS]


class TestPortUpdateIpam(test_db_base_plugin_v2.NeutronDbPluginV2TestCase):
    def setUp(self, plugin=None):
        if not plugin:
            plugin = 'neutron.tests.unit.db.test_ipam_backend_mixin.TestPlugin'
        super().setUp(plugin=plugin)
        ml2_plugin.MAX_BIND_TRIES = 0
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        ml2_plugin.MAX_BIND_TRIES = 10

    def test_port_update_allocate_from_net_subnet(self):
        """Tests that a port can get address by updating fixed_ips"""
        with self.network() as network:
            pass

        # Create a bound port with no IP address (since there is not subnet)
        response = self._create_port(self.fmt,
                                     net_id=network['network']['id'],
                                     tenant_id=network['network']['tenant_id'],
                                     arg_list=(portbindings.HOST_ID,),
                                     **{portbindings.HOST_ID: 'fakehost'},
                                     is_admin=True)
        port = self.deserialize(self.fmt, response)

        # Create the subnet and try to update the port to get an IP
        with self.subnet(network=network) as subnet:
            data = {'port': {
                'fixed_ips': [{'subnet_id': subnet['subnet']['id']}]}}
            port_id = port['port']['id']
            port_req = self.new_update_request('ports', data, port_id,
                                               as_admin=True)
            response = port_req.get_response(self.api)
            res = self.deserialize(self.fmt, response)

        self.assertEqual(webob.exc.HTTPOk.code, response.status_int)
        self.assertEqual(1, len(res['port']['fixed_ips']))
        ip = res['port']['fixed_ips'][0]['ip_address']
        ip_net = netaddr.IPNetwork(subnet['subnet']['cidr'])
        self.assertIn(ip, ip_net)


class TestPortUpdateIpamML2(TestPortUpdateIpam):
    def setUp(self):
        super().setUp(plugin='ml2')
