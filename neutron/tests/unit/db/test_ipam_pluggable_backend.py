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

import copy
from unittest import mock

import netaddr
from neutron_lib import constants
from neutron_lib import context as ncontext
from neutron_lib import exceptions as n_exc
from oslo_config import cfg
from oslo_db import exception as db_exc
from oslo_utils import netutils
from oslo_utils import uuidutils
import webob.exc

from neutron.conf import common as base_config
from neutron.db import ipam_backend_mixin
from neutron.db import ipam_pluggable_backend
from neutron.ipam import exceptions as ipam_exc
from neutron.ipam import requests as ipam_req
from neutron.objects import network as network_obj
from neutron.objects import ports as port_obj
from neutron.objects import subnet as obj_subnet
from neutron.tests.unit.db import test_db_base_plugin_v2 as test_db_base


class UseIpamMixin(object):

    def setUp(self):
        cfg.CONF.register_opts(base_config.core_opts)
        cfg.CONF.set_override("ipam_driver", 'internal')
        super(UseIpamMixin, self).setUp()


class TestIpamHTTPResponse(UseIpamMixin, test_db_base.TestV2HTTPResponse):
    pass


class TestIpamPorts(UseIpamMixin, test_db_base.TestPortsV2):
    pass


class TestIpamNetworks(UseIpamMixin, test_db_base.TestNetworksV2):
    pass


class TestIpamSubnets(UseIpamMixin, test_db_base.TestSubnetsV2):
    pass


class TestIpamSubnetPool(UseIpamMixin, test_db_base.TestSubnetPoolsV2):
    pass


class TestDbBasePluginIpam(test_db_base.NeutronDbPluginV2TestCase):
    def setUp(self, plugin=None):
        if not plugin:
            plugin = 'neutron.tests.unit.db.test_ipam_backend_mixin.TestPlugin'
        super(TestDbBasePluginIpam, self).setUp(plugin=plugin)
        cfg.CONF.set_override("ipam_driver", 'internal')
        self.subnet_id = uuidutils.generate_uuid()
        self.admin_context = ncontext.get_admin_context()

    def _prepare_mocks(self, address_factory=None, subnet_factory=None):
        if address_factory is None:
            address_factory = ipam_req.AddressRequestFactory
        if subnet_factory is None:
            subnet_factory = ipam_req.SubnetRequestFactory

        mocks = {
            'driver': mock.Mock(),
            'subnet': mock.Mock(),
            'subnets': mock.Mock(),
            'port': {
                'device_owner': constants.DEVICE_OWNER_COMPUTE_PREFIX + 'None'
            },
            'subnet_request': ipam_req.SpecificSubnetRequest(
                self._tenant_id,
                self.subnet_id,
                '10.0.0.0/24',
                '10.0.0.1',
                [netaddr.IPRange('10.0.0.2', '10.0.0.254')]),
        }
        mocks['driver'].get_subnet.return_value = mocks['subnet']
        mocks['driver'].allocate_subnet.return_value = mocks['subnet']
        mocks['driver'].get_allocator.return_value = mocks['subnets']
        mocks['subnets'].allocate.return_value = (
            '127.0.0.1', uuidutils.generate_uuid())
        mocks['driver'].get_subnet_request_factory.return_value = (
            subnet_factory)
        mocks['driver'].get_address_request_factory.return_value = (
            address_factory)
        mocks['subnet'].get_details.return_value = mocks['subnet_request']
        return mocks

    def _prepare_ipam(self):
        mocks = self._prepare_mocks()
        mocks['ipam'] = ipam_pluggable_backend.IpamPluggableBackend()
        return mocks

    def _prepare_mocks_with_pool_mock(self, pool_mock, address_factory=None,
                                      subnet_factory=None):
        mocks = self._prepare_mocks(address_factory=address_factory,
                                    subnet_factory=subnet_factory)
        pool_mock.get_instance.return_value = mocks['driver']
        return mocks

    def _get_allocate_mock(self, subnet_id, auto_ip='10.0.0.2',
                           fail_ip='127.0.0.1',
                           exception=n_exc.InvalidInput(
                               error_message='SomeError')):
        def allocate_mock(request):
            if isinstance(request, ipam_req.SpecificAddressRequest):
                if request.address == netaddr.IPAddress(fail_ip):
                    raise exception
                else:
                    return str(request.address), subnet_id
            else:
                return auto_ip, subnet_id

        return allocate_mock

    def _get_deallocate_mock(self, fail_ip='127.0.0.1',
                             exception=n_exc.InvalidInput(
                                 error_message='SomeError')):
        def deallocate_mock(ip):
            if str(ip) == fail_ip:
                raise exception

        return deallocate_mock

    def _validate_allocate_calls(self, expected_calls, mocks):
        self.assertTrue(mocks['subnets'].allocate.called)

        actual_calls = mocks['subnets'].allocate.call_args_list
        self.assertEqual(len(expected_calls), len(actual_calls))

        i = 0
        for call in expected_calls:
            if call['ip_address']:
                self.assertIsInstance(actual_calls[i][0][0],
                                      ipam_req.SpecificAddressRequest)
                self.assertEqual(netaddr.IPAddress(call['ip_address']),
                                 actual_calls[i][0][0].address)
            else:
                self.assertIsInstance(actual_calls[i][0][0],
                                      ipam_req.AnyAddressRequest)
            i += 1

    def _convert_to_ips(self, data):
        ips = [{'ip_address': ip,
                'subnet_id': data[ip][1],
                'subnet_cidr': data[ip][0]} for ip in data]
        return sorted(ips, key=lambda t: t['subnet_cidr'])

    def _gen_subnet_id(self):
        return uuidutils.generate_uuid()

    def test_deallocate_single_ip(self):
        mocks = self._prepare_ipam()
        ip = '192.168.12.45'
        data = {ip: ['192.168.12.0/24', self._gen_subnet_id()]}
        ips = self._convert_to_ips(data)

        mocks['ipam']._ipam_deallocate_ips(mock.ANY, mocks['driver'],
                                           mock.ANY, ips)

        mocks['driver'].get_subnet.assert_called_once_with(data[ip][1])
        mocks['subnet'].deallocate.assert_called_once_with(ip)

    def test_deallocate_multiple_ips(self):
        mocks = self._prepare_ipam()
        data = {'192.168.43.15': ['192.168.43.0/24', self._gen_subnet_id()],
                '172.23.158.84': ['172.23.128.0/17', self._gen_subnet_id()],
                '8.8.8.8': ['8.0.0.0/8', self._gen_subnet_id()]}
        ips = self._convert_to_ips(data)

        mocks['ipam']._ipam_deallocate_ips(mock.ANY, mocks['driver'],
                                           mock.ANY, ips)

        get_calls = [mock.call(data[ip][1]) for ip in data]
        mocks['driver'].get_subnet.assert_has_calls(get_calls, any_order=True)

        ip_calls = [mock.call(ip) for ip in data]
        mocks['subnet'].deallocate.assert_has_calls(ip_calls, any_order=True)

    def _single_ip_allocate_helper(self, mocks, ip, network, subnet):
        ips = [{'subnet_cidr': network,
                'subnet_id': subnet}]
        if ip:
            ips[0]['ip_address'] = ip

        allocated_ips = mocks['ipam']._ipam_allocate_ips(
            mock.ANY, mocks['driver'], mocks['port'], ips)

        mocks['driver'].get_allocator.assert_called_once_with([subnet])

        self.assertTrue(mocks['subnets'].allocate.called)
        request = mocks['subnets'].allocate.call_args[0][0]

        return {'ips': allocated_ips,
                'request': request}

    def test_allocate_single_fixed_ip(self):
        mocks = self._prepare_ipam()
        ip = '192.168.15.123'
        subnet_id = self._gen_subnet_id()
        mocks['subnets'].allocate.return_value = ip, subnet_id

        results = self._single_ip_allocate_helper(mocks,
                                                  ip,
                                                  '192.168.15.0/24',
                                                  subnet_id)

        self.assertIsInstance(results['request'],
                              ipam_req.SpecificAddressRequest)
        self.assertEqual(netaddr.IPAddress(ip), results['request'].address)

        self.assertEqual(ip, results['ips'][0]['ip_address'],
                         'Should allocate the same ip as passed')

    def test_allocate_single_any_ip(self):
        mocks = self._prepare_ipam()
        network = '192.168.15.0/24'
        ip = '192.168.15.83'
        subnet_id = self._gen_subnet_id()
        mocks['subnets'].allocate.return_value = ip, subnet_id

        results = self._single_ip_allocate_helper(mocks, '', network,
                                                  subnet_id)

        self.assertIsInstance(results['request'], ipam_req.AnyAddressRequest)
        self.assertEqual(ip, results['ips'][0]['ip_address'])

    def test_allocate_eui64_ip(self):
        mocks = self._prepare_ipam()
        ip = {'subnet_id': self._gen_subnet_id(),
              'subnet_cidr': '2001:470:abcd::/64',
              'mac': '6c:62:6d:de:cf:49',
              'eui64_address': True}
        eui64_ip = netutils.get_ipv6_addr_by_EUI64(ip['subnet_cidr'],
                                                   ip['mac'])
        mocks['ipam']._ipam_allocate_ips(mock.ANY, mocks['driver'],
                                         mock.ANY, [ip])

        request = mocks['subnets'].allocate.call_args[0][0]
        self.assertIsInstance(request, ipam_req.AutomaticAddressRequest)
        self.assertEqual(eui64_ip, request.address)

    def test_allocate_multiple_eui64_ips(self):
        mocks = self._prepare_ipam()
        ips = [{'subnet_id': self._gen_subnet_id(),
                'subnet_cidr': '2001:470:abcd::/64',
                'mac': '6c:62:6d:de:cf:49',
                'eui64_address': True},
               {'subnet_id': self._gen_subnet_id(),
                'subnet_cidr': '2001:360:abcd::/64',
                'mac': '6c:62:6d:de:cf:49',
                'eui64_address': True}]
        mocks['ipam']._ipam_allocate_ips(mock.ANY, mocks['driver'],
                                         mock.ANY, ips)

        eui64_ips = []
        request_ips = []
        i = 0
        requests = mocks['subnets'].allocate.call_args_list
        for ip in ips:
            eui64_ip = netutils.get_ipv6_addr_by_EUI64(ip['subnet_cidr'],
                                                       ip['mac'])
            self.assertIsInstance(requests[i][0][0],
                                  ipam_req.AutomaticAddressRequest)
            self.assertEqual(eui64_ip, requests[i][0][0].address)
            request_ips.append(requests[i][0][0].address)
            eui64_ips.append(eui64_ip)
            i += 1
        self.assertEqual(request_ips, eui64_ips)

    def test_allocate_multiple_ips(self):
        mocks = self._prepare_ipam()
        subnet_id = self._gen_subnet_id()
        data = {'': ['172.23.128.0/17', subnet_id],
                '192.168.43.15': ['192.168.43.0/24', self._gen_subnet_id()],
                '8.8.8.8': ['8.0.0.0/8', self._gen_subnet_id()]}
        ips = self._convert_to_ips(data)
        mocks['subnets'].allocate.side_effect = self._get_allocate_mock(
            subnet_id, auto_ip='172.23.128.94')

        mocks['ipam']._ipam_allocate_ips(
            mock.ANY, mocks['driver'], mocks['port'], ips)
        get_calls = [mock.call([data[ip][1]]) for ip in data]
        mocks['driver'].get_allocator.assert_has_calls(
            get_calls, any_order=True)

        self._validate_allocate_calls(ips, mocks)

    def _test_allocate_multiple_ips_with_exception(self,
                                                   exc_on_deallocate=False):
        mocks = self._prepare_ipam()
        fail_ip = '192.168.43.15'
        auto_ip = '172.23.128.94'
        subnet_id = self._gen_subnet_id()
        data = {'': ['172.23.128.0/17', subnet_id],
                fail_ip: ['192.168.43.0/24', self._gen_subnet_id()],
                '8.8.8.8': ['8.0.0.0/8', self._gen_subnet_id()]}
        ips = self._convert_to_ips(data)

        mocks['subnets'].allocate.side_effect = self._get_allocate_mock(
            subnet_id, auto_ip=auto_ip, fail_ip=fail_ip,
            exception=db_exc.DBDeadlock())

        # Exception should be raised on attempt to allocate second ip.
        # Revert action should be performed for the already allocated ips,
        # In this test case only one ip should be deallocated
        # and original error should be reraised
        self.assertRaises(db_exc.DBDeadlock,
                          mocks['ipam']._ipam_allocate_ips,
                          mock.ANY,
                          mocks['driver'],
                          mocks['port'],
                          ips)

        # get_subnet should be called only for the first two networks
        get_calls = [mock.call([data[ip][1]]) for ip in ['', fail_ip]]
        mocks['driver'].get_allocator.assert_has_calls(
            get_calls, any_order=True)

        # Allocate should be called for the first two ips only
        self._validate_allocate_calls(ips[:-1], mocks)
        # Deallocate should be called for the first ip only
        mocks['subnet'].deallocate.assert_called_once_with(auto_ip)

    def test_allocate_multiple_ips_with_exception(self):
        self._test_allocate_multiple_ips_with_exception()

    def test_allocate_multiple_ips_with_exception_on_rollback(self):
        # Validate that original exception is not replaced with one raised on
        # rollback (during deallocate)
        self._test_allocate_multiple_ips_with_exception(exc_on_deallocate=True)

    def test_deallocate_multiple_ips_with_exception(self):
        mocks = self._prepare_ipam()
        fail_ip = '192.168.43.15'
        data = {fail_ip: ['192.168.43.0/24', self._gen_subnet_id()],
                '0.10.8.8': ['0.10.0.0/8', self._gen_subnet_id()]}
        ips = self._convert_to_ips(data)

        mocks['subnet'].deallocate.side_effect = self._get_deallocate_mock(
            fail_ip=fail_ip, exception=db_exc.DBDeadlock())
        mocks['subnet'].allocate.side_effect = ValueError('Some-error')
        # Validate that exception from deallocate (DBDeadlock) is not replaced
        # by exception from allocate (ValueError) in rollback block,
        # so original exception is not changed
        self.assertRaises(db_exc.DBDeadlock,
                          mocks['ipam']._ipam_deallocate_ips,
                          mock.ANY,
                          mocks['driver'],
                          mock.ANY,
                          ips)
        mocks['subnets'].allocate.assert_called_once_with(mock.ANY)

    def test_test_fixed_ips_for_port_pd_gateway(self):
        context = mock.Mock()
        pluggable_backend = ipam_pluggable_backend.IpamPluggableBackend()
        with self.subnet(cidr=constants.PROVISIONAL_IPV6_PD_PREFIX,
                         ip_version=constants.IP_VERSION_6) as subnet:
            subnet = subnet['subnet']
            fixed_ips = [{'subnet_id': subnet['id'],
                         'ip_address': '::1'}]
            filtered_ips = (pluggable_backend.
                            _test_fixed_ips_for_port(context,
                                subnet['network_id'],
                                fixed_ips,
                                constants.DEVICE_OWNER_ROUTER_INTF,
                                "aa:bb:cc:dd:ee:ff",
                                [subnet]))
            # Assert that ports created on prefix delegation subnets
            # will be returned without an ip address. This prevents router
            # interfaces being given the ::1 gateway address.
            self.assertEqual(1, len(filtered_ips))
            self.assertEqual(subnet['id'], filtered_ips[0]['subnet_id'])
            self.assertNotIn('ip_address', filtered_ips[0])

    def test_test_fixed_ips_for_port_allocation_on_auto_address_subnet(self):
        context = mock.Mock()
        pluggable_backend = ipam_pluggable_backend.IpamPluggableBackend()
        with self.subnet(cidr="2001:db8::/64",
                         ip_version=constants.IP_VERSION_6,
                         ipv6_ra_mode=constants.IPV6_SLAAC,
                         ipv6_address_mode=constants.IPV6_SLAAC) as subnet:
            subnet = subnet['subnet']
            bad_fixed_ip = [{'subnet_id': subnet['id'],
                            'ip_address': '2001:db8::22'}]
            eui64_fixed_ip = [{'subnet_id': subnet['id'],
                              'ip_address': '2001:db8::a8bb:ccff:fedd:eeff'}]
            self.assertRaises(
                ipam_exc.AllocationOnAutoAddressSubnet,
                pluggable_backend._test_fixed_ips_for_port,
                context, subnet['network_id'], bad_fixed_ip,
                "device_owner", "aa:bb:cc:dd:ee:ff",
                [subnet])

            filtered_ips = pluggable_backend._test_fixed_ips_for_port(
                context, subnet['network_id'], eui64_fixed_ip, "device_owner",
                "aa:bb:cc:dd:ee:ff", [subnet])
            self.assertEqual(1, len(filtered_ips))
            self.assertEqual(subnet['id'], filtered_ips[0]['subnet_id'])

    @mock.patch('neutron.ipam.driver.Pool')
    def test_create_subnet_over_ipam(self, pool_mock):
        mocks = self._prepare_mocks_with_pool_mock(pool_mock)
        cidr = '192.168.0.0/24'
        allocation_pools = [{'start': '192.168.0.2', 'end': '192.168.0.254'}]
        with self.subnet(allocation_pools=allocation_pools,
                         cidr=cidr):
            pool_mock.get_instance.assert_called_once_with(None, mock.ANY)
            self.assertTrue(mocks['driver'].allocate_subnet.called)
            request = mocks['driver'].allocate_subnet.call_args[0][0]
            self.assertIsInstance(request, ipam_req.SpecificSubnetRequest)
            self.assertEqual(netaddr.IPNetwork(cidr), request.subnet_cidr)

    @mock.patch('neutron.ipam.driver.Pool')
    def test_create_ipv6_pd_subnet_over_ipam(self, pool_mock):
        mocks = self._prepare_mocks_with_pool_mock(pool_mock)
        cfg.CONF.set_override('ipv6_pd_enabled', True)
        cidr = constants.PROVISIONAL_IPV6_PD_PREFIX
        cidr_network = netaddr.IPNetwork(cidr)
        allocation_pools = [netaddr.IPRange(cidr_network.ip + 1,
                                            cidr_network.last)]
        with self.subnet(cidr=None, ip_version=constants.IP_VERSION_6,
                         subnetpool_id=constants.IPV6_PD_POOL_ID,
                         ipv6_ra_mode=constants.IPV6_SLAAC,
                         ipv6_address_mode=constants.IPV6_SLAAC):
            self.assertEqual(3, pool_mock.get_instance.call_count)
            self.assertTrue(mocks['driver'].allocate_subnet.called)
            request = mocks['driver'].allocate_subnet.call_args[0][0]
            self.assertIsInstance(request, ipam_req.SpecificSubnetRequest)
            self.assertEqual(netaddr.IPNetwork(cidr), request.subnet_cidr)
            self.assertEqual(allocation_pools, request.allocation_pools)

    @mock.patch('neutron.ipam.driver.Pool')
    def test_create_subnet_over_ipam_with_rollback(self, pool_mock):
        mocks = self._prepare_mocks_with_pool_mock(pool_mock)
        mocks['driver'].allocate_subnet.side_effect = ValueError
        cidr = '10.0.2.0/24'
        with self.network() as network:
            self._create_subnet(self.fmt, network['network']['id'],
                                cidr, expected_res_status=500)

            pool_mock.get_instance.assert_called_once_with(None, mock.ANY)
            self.assertTrue(mocks['driver'].allocate_subnet.called)
            request = mocks['driver'].allocate_subnet.call_args[0][0]
            self.assertIsInstance(request, ipam_req.SpecificSubnetRequest)
            self.assertEqual(netaddr.IPNetwork(cidr), request.subnet_cidr)
            # Verify no subnet was created for network
            req = self.new_show_request('networks', network['network']['id'])
            res = req.get_response(self.api)
            net = self.deserialize(self.fmt, res)
            self.assertEqual(0, len(net['network']['subnets']))

    def _test_rollback_on_subnet_creation(self, pool_mock, driver_mocks):
        cidr = '10.0.2.0/24'
        with mock.patch.object(
                ipam_backend_mixin.IpamBackendMixin, '_save_subnet',
                side_effect=ValueError), self.network() as network:
            self._create_subnet(self.fmt, network['network']['id'],
                                cidr, expected_res_status=500)
            pool_mock.get_instance.assert_any_call(None, mock.ANY)
            self.assertEqual(2, pool_mock.get_instance.call_count)
            self.assertTrue(driver_mocks['driver'].allocate_subnet.called)
            request = driver_mocks['driver'].allocate_subnet.call_args[0][0]
            self.assertIsInstance(request, ipam_req.SpecificSubnetRequest)
            self.assertEqual(netaddr.IPNetwork(cidr), request.subnet_cidr)
            # Verify remove ipam subnet was called
            driver_mocks['driver'].remove_subnet.assert_called_once_with(
                self.subnet_id)

    @mock.patch('neutron.ipam.driver.Pool')
    def test_ipam_subnet_deallocated_if_create_fails(self, pool_mock):
        driver_mocks = self._prepare_mocks_with_pool_mock(pool_mock)
        self._test_rollback_on_subnet_creation(pool_mock, driver_mocks)

    @mock.patch('neutron.ipam.driver.Pool')
    def test_ipam_subnet_create_and_rollback_fails(self, pool_mock):
        driver_mocks = self._prepare_mocks_with_pool_mock(pool_mock)
        # remove_subnet is called on rollback stage and n_exc.NotFound
        # typically produces 404 error. Validate that exception from
        # rollback stage is silenced and main exception (ValueError in this
        # case) is reraised. So resulting http status should be 500.
        driver_mocks['driver'].remove_subnet.side_effect = n_exc.NotFound
        self._test_rollback_on_subnet_creation(pool_mock, driver_mocks)

    @mock.patch('neutron.ipam.driver.Pool')
    def test_update_subnet_over_ipam(self, pool_mock):
        mocks = self._prepare_mocks_with_pool_mock(pool_mock)
        cidr = '10.0.0.0/24'
        allocation_pools = [{'start': '10.0.0.2', 'end': '10.0.0.254'}]
        with self.subnet(allocation_pools=allocation_pools,
                         cidr=cidr) as subnet:
            data = {'subnet': {'allocation_pools': [
                    {'start': '10.0.0.10', 'end': '10.0.0.20'},
                    {'start': '10.0.0.30', 'end': '10.0.0.40'}]}}
            req = self.new_update_request('subnets', data,
                                          subnet['subnet']['id'])
            res = req.get_response(self.api)
            self.assertEqual(200, res.status_code)

            pool_mock.get_instance.assert_any_call(None, mock.ANY)
            self.assertEqual(2, pool_mock.get_instance.call_count)
            self.assertTrue(mocks['driver'].update_subnet.called)
            request = mocks['driver'].update_subnet.call_args[0][0]
            self.assertIsInstance(request, ipam_req.SpecificSubnetRequest)
            self.assertEqual(netaddr.IPNetwork(cidr), request.subnet_cidr)

            ip_ranges = [netaddr.IPRange(p['start'],
                p['end']) for p in data['subnet']['allocation_pools']]
            self.assertEqual(ip_ranges, request.allocation_pools)

    @mock.patch('neutron.ipam.driver.Pool')
    def test_delete_subnet_over_ipam(self, pool_mock):
        mocks = self._prepare_mocks_with_pool_mock(pool_mock)
        gateway_ip = '10.0.0.1'
        cidr = '10.0.0.0/24'
        res = self._create_network(fmt=self.fmt, name='net',
                                   admin_state_up=True)
        network = self.deserialize(self.fmt, res)
        subnet = self._make_subnet(self.fmt, network, gateway_ip,
                                   cidr, ip_version=constants.IP_VERSION_4)
        req = self.new_delete_request('subnets', subnet['subnet']['id'])
        res = req.get_response(self.api)
        self.assertEqual(webob.exc.HTTPNoContent.code, res.status_int)

        pool_mock.get_instance.assert_any_call(None, mock.ANY)
        self.assertEqual(2, pool_mock.get_instance.call_count)
        mocks['driver'].remove_subnet.assert_called_once_with(
            subnet['subnet']['id'])

    @mock.patch('neutron.ipam.driver.Pool')
    def test_delete_subnet_over_ipam_with_rollback(self, pool_mock):
        mocks = self._prepare_mocks_with_pool_mock(pool_mock)
        mocks['driver'].remove_subnet.side_effect = ValueError
        gateway_ip = '10.0.0.1'
        cidr = '10.0.0.0/24'
        res = self._create_network(fmt=self.fmt, name='net',
                                   admin_state_up=True)
        network = self.deserialize(self.fmt, res)
        subnet = self._make_subnet(self.fmt, network, gateway_ip,
                                   cidr, ip_version=constants.IP_VERSION_4)
        req = self.new_delete_request('subnets', subnet['subnet']['id'])
        res = req.get_response(self.api)
        self.assertEqual(webob.exc.HTTPServerError.code, res.status_int)

        pool_mock.get_instance.assert_any_call(None, mock.ANY)
        self.assertEqual(2, pool_mock.get_instance.call_count)
        mocks['driver'].remove_subnet.assert_called_once_with(
            subnet['subnet']['id'])
        # Verify subnet was recreated after failed ipam call
        subnet_req = self.new_show_request('subnets',
                                           subnet['subnet']['id'])
        raw_res = subnet_req.get_response(self.api)
        sub_res = self.deserialize(self.fmt, raw_res)
        self.assertIn(sub_res['subnet']['cidr'], cidr)
        self.assertIn(sub_res['subnet']['gateway_ip'],
                      gateway_ip)

    @mock.patch('neutron.ipam.driver.Pool')
    def test_create_port_ipam(self, pool_mock):
        mocks = self._prepare_mocks_with_pool_mock(pool_mock)
        auto_ip = '10.0.0.2'
        expected_calls = [{'ip_address': ''}]
        with self.subnet() as subnet:
            mocks['subnets'].allocate.side_effect = self._get_allocate_mock(
                subnet['subnet']['id'], auto_ip=auto_ip)
            with self.port(subnet=subnet) as port:
                ips = port['port']['fixed_ips']
                self.assertEqual(1, len(ips))
                self.assertEqual(ips[0]['ip_address'], auto_ip)
                self.assertEqual(ips[0]['subnet_id'], subnet['subnet']['id'])
                self._validate_allocate_calls(expected_calls, mocks)

    @mock.patch('neutron.ipam.driver.Pool')
    def test_create_port_ipam_with_rollback(self, pool_mock):
        mocks = self._prepare_mocks_with_pool_mock(pool_mock)
        mocks['subnet'].allocate.side_effect = ValueError
        with self.network() as network:
            with self.subnet(network=network):
                net_id = network['network']['id']
                data = {
                    'port': {'network_id': net_id,
                             'tenant_id': network['network']['tenant_id']}}
                port_req = self.new_create_request('ports', data)
                res = port_req.get_response(self.api)
                self.assertEqual(webob.exc.HTTPServerError.code,
                                 res.status_int)

                # verify no port left after failure
                req = self.new_list_request('ports', self.fmt,
                                            "network_id=%s" % net_id)
                res = self.deserialize(self.fmt, req.get_response(self.api))
                self.assertEqual(0, len(res['ports']))

    @mock.patch('neutron.ipam.driver.Pool')
    def test_update_port_ipam(self, pool_mock):
        mocks = self._prepare_mocks_with_pool_mock(pool_mock)
        auto_ip = '10.0.0.2'
        new_ip = '10.0.0.15'
        expected_calls = [{'ip_address': ip} for ip in ['', new_ip]]
        with self.subnet() as subnet:
            mocks['subnets'].allocate.side_effect = self._get_allocate_mock(
                subnet['subnet']['id'], auto_ip=auto_ip)
            with self.port(subnet=subnet) as port:
                ips = port['port']['fixed_ips']
                self.assertEqual(1, len(ips))
                self.assertEqual(auto_ip, ips[0]['ip_address'])
                # Update port with another new ip
                data = {"port": {"fixed_ips": [{
                        'subnet_id': subnet['subnet']['id'],
                        'ip_address': new_ip}]}}
                req = self.new_update_request('ports', data,
                                              port['port']['id'])
                res = self.deserialize(self.fmt, req.get_response(self.api))
                ips = res['port']['fixed_ips']
                self.assertEqual(1, len(ips))
                self.assertEqual(new_ip, ips[0]['ip_address'])

                # Allocate should be called for the first two networks
                self._validate_allocate_calls(expected_calls, mocks)
                # Deallocate should be called for the first ip only
                mocks['subnet'].deallocate.assert_called_once_with(auto_ip)

    @mock.patch('neutron.ipam.driver.Pool')
    def test_delete_port_ipam(self, pool_mock):
        mocks = self._prepare_mocks_with_pool_mock(pool_mock)
        auto_ip = '10.0.0.2'
        with self.subnet() as subnet:
            mocks['subnets'].allocate.side_effect = self._get_allocate_mock(
                subnet['subnet']['id'], auto_ip=auto_ip)
            with self.port(subnet=subnet) as port:
                ips = port['port']['fixed_ips']
                self.assertEqual(1, len(ips))
                self.assertEqual(auto_ip, ips[0]['ip_address'])
                req = self.new_delete_request('ports', port['port']['id'])
                res = req.get_response(self.api)

                self.assertEqual(webob.exc.HTTPNoContent.code, res.status_int)
                mocks['subnet'].deallocate.assert_called_once_with(auto_ip)

    def test_recreate_port_ipam(self):
        with self.subnet() as subnet:
            subnet_cidr = subnet['subnet']['cidr']
            with self.port(subnet=subnet) as port:
                ips = port['port']['fixed_ips']
                self.assertEqual(1, len(ips))
                orig_ip = ips[0]['ip_address']
                self.assertIn(netaddr.IPAddress(ips[0]['ip_address']),
                              netaddr.IPSet(netaddr.IPNetwork(subnet_cidr)))
                req = self.new_delete_request('ports', port['port']['id'])
                res = req.get_response(self.api)
                self.assertEqual(webob.exc.HTTPNoContent.code, res.status_int)
                with self.port(subnet=subnet, fixed_ips=ips) as port:
                    ips = port['port']['fixed_ips']
                    self.assertEqual(1, len(ips))
                    self.assertEqual(orig_ip, ips[0]['ip_address'])

    def test_recreate_port_ipam_specific_ip(self):
        with self.subnet() as subnet:
            ip = '10.0.0.2'
            fixed_ip_data = [{'subnet_id': subnet['subnet']['id'],
                              'ip_address': ip}]
            with self.port(subnet=subnet, fixed_ips=fixed_ip_data) as port:
                ips = port['port']['fixed_ips']
                self.assertEqual(1, len(ips))
                self.assertEqual(ip, ips[0]['ip_address'])
                req = self.new_delete_request('ports', port['port']['id'])
                res = req.get_response(self.api)
                self.assertEqual(webob.exc.HTTPNoContent.code, res.status_int)
                with self.port(subnet=subnet, fixed_ips=ips) as port:
                    ips = port['port']['fixed_ips']
                    self.assertEqual(1, len(ips))
                    self.assertEqual(ip, ips[0]['ip_address'])

    @mock.patch('neutron.ipam.driver.Pool')
    def test_update_ips_for_port_passes_port_dict_to_factory(self, pool_mock):
        address_factory = mock.Mock()
        mocks = self._prepare_mocks_with_pool_mock(
            pool_mock, address_factory=address_factory)
        context = mock.Mock()
        new_ips = mock.Mock()
        original_ips = mock.Mock()
        mac = mock.Mock()

        ip_dict = {'ip_address': '192.1.1.10',
                   'subnet_id': uuidutils.generate_uuid()}
        changes = ipam_pluggable_backend.IpamPluggableBackend.Changes(
            add=[ip_dict], original=[], remove=[])
        changes_mock = mock.Mock(return_value=changes)
        fixed_ips_mock = mock.Mock(return_value=changes.add)
        mocks['ipam'] = ipam_pluggable_backend.IpamPluggableBackend()
        mocks['ipam']._get_changed_ips_for_port = changes_mock
        mocks['ipam']._ipam_get_subnets = mock.Mock(return_value=[])
        mocks['ipam']._test_fixed_ips_for_port = fixed_ips_mock
        mocks['ipam']._update_ips_for_pd_subnet = mock.Mock(return_value=[])

        port_dict = {'device_owner': uuidutils.generate_uuid(),
                     'mac_address': 'aa:bb:cc:dd:ee:ff',
                     'network_id': uuidutils.generate_uuid()}

        mocks['ipam']._update_ips_for_port(context, port_dict, None,
                                           original_ips, new_ips, mac)
        mocks['driver'].get_address_request_factory.assert_called_once_with()
        mocks['ipam']._ipam_get_subnets.assert_called_once_with(
            context, network_id=port_dict['network_id'], fixed_configured=True,
            fixed_ips=[ip_dict], host=None,
            service_type=port_dict['device_owner'],
            distributed_service=False)
        # Validate port_dict is passed into address_factory
        address_factory.get_request.assert_called_once_with(context,
                                                            port_dict,
                                                            ip_dict)

    @mock.patch('neutron.ipam.driver.Pool')
    def test_update_ips_for_port_ovn_distributed_svc(self, pool_mock):
        address_factory = mock.Mock()
        mocks = self._prepare_mocks_with_pool_mock(
            pool_mock, address_factory=address_factory)
        context = mock.Mock()
        new_ips = mock.Mock()
        original_ips = mock.Mock()
        mac = mock.Mock()

        ip_dict = {'ip_address': '192.1.1.10',
                   'subnet_id': uuidutils.generate_uuid()}
        changes = ipam_pluggable_backend.IpamPluggableBackend.Changes(
            add=[ip_dict], original=[], remove=[])
        changes_mock = mock.Mock(return_value=changes)
        fixed_ips_mock = mock.Mock(return_value=changes.add)
        mocks['ipam'] = ipam_pluggable_backend.IpamPluggableBackend()
        mocks['ipam']._get_changed_ips_for_port = changes_mock
        mocks['ipam']._ipam_get_subnets = mock.Mock(return_value=[])
        mocks['ipam']._test_fixed_ips_for_port = fixed_ips_mock
        mocks['ipam']._update_ips_for_pd_subnet = mock.Mock(return_value=[])

        port_dict = {
            'device_owner': constants.DEVICE_OWNER_DISTRIBUTED,
            'device_id': 'ovnmeta-%s' % uuidutils.generate_uuid(),
            'mac_address': 'aa:bb:cc:dd:ee:ff',
            'network_id': uuidutils.generate_uuid()}

        mocks['ipam']._update_ips_for_port(context, port_dict, None,
                                           original_ips, new_ips, mac)
        mocks['ipam']._ipam_get_subnets.assert_called_once_with(
            context, network_id=port_dict['network_id'], fixed_configured=True,
            fixed_ips=[ip_dict], host=None,
            service_type=port_dict['device_owner'],
            distributed_service=True)

    @mock.patch('neutron.ipam.driver.Pool')
    def test_update_ips_for_port_passes_port_id_to_factory(self, pool_mock):
        port_id = uuidutils.generate_uuid()
        network_id = uuidutils.generate_uuid()
        address_factory = mock.Mock()
        mocks = self._prepare_mocks_with_pool_mock(
            pool_mock, address_factory=address_factory)
        context = mock.Mock()

        ip_dict = {'ip_address': '192.1.1.10',
                   'subnet_id': uuidutils.generate_uuid()}
        port_dict = {'port': {'device_owner': uuidutils.generate_uuid(),
                              'network_id': network_id,
                              'mac_address': 'aa:bb:cc:dd:ee:ff',
                              'fixed_ips': [ip_dict]}}
        subnets = [{'id': ip_dict['subnet_id'],
                    'network_id': network_id,
                    'cidr': '192.1.1.0/24',
                    'ip_version': constants.IP_VERSION_4,
                    'ipv6_address_mode': None,
                    'ipv6_ra_mode': None}]
        get_subnets_mock = mock.Mock(return_value=subnets)
        get_subnet_mock = mock.Mock(return_value=subnets[0])
        mocks['ipam'] = ipam_pluggable_backend.IpamPluggableBackend()
        mocks['ipam']._ipam_get_subnets = get_subnets_mock
        mocks['ipam']._get_subnet = get_subnet_mock

        with mock.patch.object(port_obj.IPAllocation, 'create'):
            mocks['ipam'].allocate_ips_for_port_and_store(context,
                                                          port_dict,
                                                          port_id)

        mocks['driver'].get_address_request_factory.assert_called_once_with()

        port_dict_with_id = port_dict['port'].copy()
        port_dict_with_id['id'] = port_id
        # Validate port id is added to port dict before address_factory call
        ip_dict.pop('device_owner')
        address_factory.get_request.assert_called_once_with(context,
                                                            port_dict_with_id,
                                                            ip_dict)
        # Verify incoming port dict is not changed ('id' is not added to it)
        self.assertIsNone(port_dict['port'].get('id'))

    def _test_update_db_subnet(self, pool_mock, subnet, expected_subnet,
                               old_pools):
        subnet_factory = mock.Mock()
        context = self.admin_context

        if 'cidr' in subnet:
            subnet['cidr'] = netaddr.IPNetwork(subnet['cidr'])
        if 'cidr' in expected_subnet:
            expected_subnet['cidr'] = netaddr.IPNetwork(
                expected_subnet['cidr'])

        mocks = self._prepare_mocks_with_pool_mock(
            pool_mock, subnet_factory=subnet_factory)

        mocks['ipam'] = ipam_pluggable_backend.IpamPluggableBackend()
        mocks['ipam'].update_db_subnet(
            context, subnet['id'], subnet, old_pools)

        mocks['driver'].get_subnet_request_factory.assert_called_once_with()
        subnet_factory.get_request.assert_called_once_with(context,
                                                           expected_subnet,
                                                           None)

    @mock.patch('neutron.ipam.driver.Pool')
    def test_update_db_subnet_unchanged_pools(self, pool_mock):
        old_pools = [{'start': '192.1.1.2', 'end': '192.1.1.254'}]
        context = self.admin_context
        network_id = uuidutils.generate_uuid()
        network_obj.Network(context, id=network_id).create()
        subnet = {'id': uuidutils.generate_uuid(),
                  'ip_version': constants.IP_VERSION_4,
                  'cidr': netaddr.IPNetwork('192.1.1.0/24'),
                  'ipv6_address_mode': None,
                  'ipv6_ra_mode': None,
                  'network_id': network_id}
        subnet_with_pools = subnet.copy()
        subnet_obj = obj_subnet.Subnet(context, **subnet_with_pools)
        subnet_obj.create()
        subnet_with_pools['allocation_pools'] = old_pools
        # if subnet has no allocation pools set, then old pools has to
        # be added to subnet dict passed to request factory
        self._test_update_db_subnet(pool_mock, subnet, subnet_with_pools,
                                    old_pools)

    @mock.patch('neutron.ipam.driver.Pool')
    def test_update_db_subnet_new_pools(self, pool_mock):
        old_pools = [{'start': '192.1.1.2', 'end': '192.1.1.254'}]
        context = self.admin_context
        network_id = uuidutils.generate_uuid()
        network_obj.Network(context, id=network_id).create()
        subnet = {'id': uuidutils.generate_uuid(),
                  'ip_version': constants.IP_VERSION_4,
                  'cidr': netaddr.IPNetwork('192.1.1.0/24'),
                  'ipv6_address_mode': None,
                  'ipv6_ra_mode': None,
                  'network_id': network_id}
        # make a copy of subnet for validation, since update_subnet changes
        # incoming subnet dict
        expected_subnet = subnet.copy()
        subnet_obj = obj_subnet.Subnet(context, **subnet)
        subnet_obj.create()
        subnet['allocation_pools'] = [
            netaddr.IPRange('192.1.1.10', '192.1.1.254')]
        expected_subnet = subnet.copy()
        obj_subnet.IPAllocationPool(context,
                                    subnet_id=subnet['id'],
                                    start='192.1.1.10',
                                    end='192.1.1.254').create()
        # validate that subnet passed to request factory is the same as
        # incoming one, i.e. new pools in it are not overwritten by old pools
        self._test_update_db_subnet(pool_mock, subnet, expected_subnet,
                                    old_pools)

    @mock.patch('neutron.ipam.driver.Pool')
    def test_update_db_subnet_new_pools_exception(self, pool_mock):
        context = mock.Mock()
        mocks = self._prepare_mocks_with_pool_mock(pool_mock)
        mocks['ipam'] = ipam_pluggable_backend.IpamPluggableBackend()

        new_port = {'fixed_ips': [{'ip_address': '192.168.1.20',
                                   'subnet_id': uuidutils.generate_uuid()},
                                  {'ip_address': '192.168.1.50',
                                   'subnet_id': uuidutils.generate_uuid()}]}
        db_port = port_obj.Port(context,
                                id=uuidutils.generate_uuid(),
                                network_id=uuidutils.generate_uuid())
        old_port = {'fixed_ips': [{'ip_address': '192.168.1.10',
                                   'subnet_id': uuidutils.generate_uuid()},
                                  {'ip_address': '192.168.1.50',
                                   'subnet_id': uuidutils.generate_uuid()}]}
        changes = mocks['ipam'].Changes(
            add=[{'ip_address': '192.168.1.20',
                  'subnet_id': uuidutils.generate_uuid()}],
            original=[{'ip_address': '192.168.1.50',
                       'subnet_id': uuidutils.generate_uuid()}],
            remove=[{'ip_address': '192.168.1.10',
                     'subnet_id': uuidutils.generate_uuid()}])
        mocks['ipam']._delete_ip_allocation = mock.Mock()
        mocks['ipam']._make_port_dict = mock.Mock(return_value=old_port)
        mocks['ipam']._update_ips_for_port = mock.Mock(return_value=changes)
        mocks['ipam']._update_db_port = mock.Mock(
            side_effect=db_exc.DBDeadlock)
        # emulate raising exception on rollback actions
        mocks['ipam']._ipam_deallocate_ips = mock.Mock(side_effect=ValueError)
        mocks['ipam']._ipam_allocate_ips = mock.Mock(side_effect=ValueError)

        # Validate original exception (DBDeadlock) is not overridden by
        # exception raised on rollback (ValueError)
        with mock.patch.object(port_obj.IPAllocation, 'create'):
            self.assertRaises(db_exc.DBDeadlock,
                              mocks['ipam'].update_port_with_ips,
                              context,
                              None,
                              db_port,
                              new_port,
                              mock.Mock())
            mocks['ipam']._ipam_deallocate_ips.assert_called_once_with(
                context, mocks['driver'], db_port,
                changes.add, revert_on_fail=False)
        mocks['ipam']._ipam_allocate_ips.assert_called_once_with(
            context, mocks['driver'], db_port,
            changes.remove, revert_on_fail=False)


class TestRollback(test_db_base.NeutronDbPluginV2TestCase):
    def setUp(self):
        cfg.CONF.set_override('ipam_driver', 'internal')
        super(TestRollback, self).setUp()

    def test_ipam_rollback_not_broken_on_session_rollback(self):
        """Triggers an error that calls rollback on session."""
        with self.network() as net:
            with self.subnet(network=net, cidr='10.0.1.0/24') as subnet1:
                with self.subnet(network=net, cidr='10.0.2.0/24') as subnet2:
                    pass

        # If this test fails and this method appears in the server side stack
        # trace then IPAM rollback was likely tried using a session which had
        # already been rolled back by the DB exception.
        def rollback(func, *args, **kwargs):
            func(*args, **kwargs)

        # Ensure DBDuplicate exception is raised in the context where IPAM
        # rollback is triggered. It "breaks" the session because it triggers DB
        # rollback. Inserting a flush in _store_ip_allocation does this.
        orig = ipam_pluggable_backend.IpamPluggableBackend._store_ip_allocation

        def store(context, ip_address, *args, **kwargs):
            try:
                return orig(context, ip_address, *args, **kwargs)
            finally:
                context.session.flush()

        # Create a port to conflict with later. Simulates a race for addresses.
        result = self._create_port(
            self.fmt,
            net_id=net['network']['id'],
            fixed_ips=[{'subnet_id': subnet1['subnet']['id']},
                       {'subnet_id': subnet2['subnet']['id']}])
        port = self.deserialize(self.fmt, result)
        fixed_ips = port['port']['fixed_ips']

        # Hands out the same 2nd IP to create conflict and trigger rollback
        ips = [{'subnet_id': fixed_ips[0]['subnet_id'],
                'ip_address': fixed_ips[0]['ip_address']},
               {'subnet_id': fixed_ips[1]['subnet_id'],
                'ip_address': fixed_ips[1]['ip_address']}]

        def alloc(*args, **kwargs):
            def increment_address(a):
                a['ip_address'] = str(netaddr.IPAddress(a['ip_address']) + 1)
            # Increment 1st address to return a free address on the first call
            increment_address(ips[0])
            try:
                return copy.deepcopy(ips)
            finally:
                # Increment 2nd address to return free address on the 2nd call
                increment_address(ips[1])

        Backend = ipam_pluggable_backend.IpamPluggableBackend
        with mock.patch.object(Backend, '_store_ip_allocation', wraps=store),\
                mock.patch.object(Backend, '_safe_rollback', wraps=rollback),\
                mock.patch.object(Backend, '_allocate_ips_for_port',
                                  wraps=alloc):
            # Create port with two addresses. The wrapper lets one succeed
            # then simulates race for the second to trigger IPAM rollback.
            response = self._create_port(
                self.fmt,
                net_id=net['network']['id'],
                fixed_ips=[{'subnet_id': subnet1['subnet']['id']},
                           {'subnet_id': subnet2['subnet']['id']}])

        # When all goes well, retry kicks in and the operation is successful.
        self.assertEqual(webob.exc.HTTPCreated.code, response.status_int)
