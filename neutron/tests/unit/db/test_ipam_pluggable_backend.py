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

import mock
import netaddr
import webob.exc

from oslo_config import cfg
from oslo_utils import uuidutils

from neutron.common import exceptions as n_exc
from neutron.common import ipv6_utils
from neutron.db import ipam_backend_mixin
from neutron.db import ipam_pluggable_backend
from neutron.ipam import requests as ipam_req
from neutron.tests.unit.db import test_db_base_plugin_v2 as test_db_base


class UseIpamMixin(object):

    def setUp(self):
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
    def setUp(self):
        cfg.CONF.set_override("ipam_driver", 'internal')
        super(TestDbBasePluginIpam, self).setUp()
        self.tenant_id = uuidutils.generate_uuid()
        self.subnet_id = uuidutils.generate_uuid()

    def _prepare_mocks(self):
        mocks = {
            'driver': mock.Mock(),
            'subnet': mock.Mock(),
            'subnet_request': ipam_req.SpecificSubnetRequest(
                self.tenant_id,
                self.subnet_id,
                '10.0.0.0/24',
                '10.0.0.1',
                [netaddr.IPRange('10.0.0.2', '10.0.0.254')]),
        }
        mocks['driver'].get_subnet.return_value = mocks['subnet']
        mocks['driver'].allocate_subnet.return_value = mocks['subnet']
        mocks['driver'].get_subnet_request_factory = (
            ipam_req.SubnetRequestFactory)
        mocks['driver'].get_address_request_factory = (
            ipam_req.AddressRequestFactory)
        mocks['subnet'].get_details.return_value = mocks['subnet_request']
        return mocks

    def _prepare_ipam(self):
        mocks = self._prepare_mocks()
        mocks['ipam'] = ipam_pluggable_backend.IpamPluggableBackend()
        return mocks

    def _prepare_mocks_with_pool_mock(self, pool_mock):
        mocks = self._prepare_mocks()
        pool_mock.get_instance.return_value = mocks['driver']
        return mocks

    def _get_allocate_mock(self, auto_ip='10.0.0.2',
                           fail_ip='127.0.0.1',
                           error_message='SomeError'):
        def allocate_mock(request):
            if type(request) == ipam_req.SpecificAddressRequest:
                if request.address == netaddr.IPAddress(fail_ip):
                    raise n_exc.InvalidInput(error_message=error_message)
                else:
                    return str(request.address)
            else:
                return auto_ip

        return allocate_mock

    def _validate_allocate_calls(self, expected_calls, mocks):
        self.assertTrue(mocks['subnet'].allocate.called)

        actual_calls = mocks['subnet'].allocate.call_args_list
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
            mock.ANY, mocks['driver'], mock.ANY, ips)

        mocks['driver'].get_subnet.assert_called_once_with(subnet)

        self.assertTrue(mocks['subnet'].allocate.called)
        request = mocks['subnet'].allocate.call_args[0][0]

        return {'ips': allocated_ips,
                'request': request}

    def test_allocate_single_fixed_ip(self):
        mocks = self._prepare_ipam()
        ip = '192.168.15.123'
        mocks['subnet'].allocate.return_value = ip

        results = self._single_ip_allocate_helper(mocks,
                                                  ip,
                                                  '192.168.15.0/24',
                                                  self._gen_subnet_id())

        self.assertIsInstance(results['request'],
                              ipam_req.SpecificAddressRequest)
        self.assertEqual(netaddr.IPAddress(ip), results['request'].address)

        self.assertEqual(ip, results['ips'][0]['ip_address'],
                         'Should allocate the same ip as passed')

    def test_allocate_single_any_ip(self):
        mocks = self._prepare_ipam()
        network = '192.168.15.0/24'
        ip = '192.168.15.83'
        mocks['subnet'].allocate.return_value = ip

        results = self._single_ip_allocate_helper(mocks, '', network,
                                                  self._gen_subnet_id())

        self.assertIsInstance(results['request'], ipam_req.AnyAddressRequest)
        self.assertEqual(ip, results['ips'][0]['ip_address'])

    def test_allocate_eui64_ip(self):
        mocks = self._prepare_ipam()
        ip = {'subnet_id': self._gen_subnet_id(),
              'subnet_cidr': '2001:470:abcd::/64',
              'mac': '6c:62:6d:de:cf:49',
              'eui64_address': True}
        eui64_ip = ipv6_utils.get_ipv6_addr_by_EUI64(ip['subnet_cidr'],
                                                     ip['mac'])
        mocks['ipam']._ipam_allocate_ips(mock.ANY, mocks['driver'],
                                         mock.ANY, [ip])

        request = mocks['subnet'].allocate.call_args[0][0]
        self.assertIsInstance(request, ipam_req.AutomaticAddressRequest)
        self.assertEqual(eui64_ip, request.address)

    def test_allocate_multiple_ips(self):
        mocks = self._prepare_ipam()
        data = {'': ['172.23.128.0/17', self._gen_subnet_id()],
                '192.168.43.15': ['192.168.43.0/24', self._gen_subnet_id()],
                '8.8.8.8': ['8.0.0.0/8', self._gen_subnet_id()]}
        ips = self._convert_to_ips(data)
        mocks['subnet'].allocate.side_effect = self._get_allocate_mock(
            auto_ip='172.23.128.94')

        mocks['ipam']._ipam_allocate_ips(
            mock.ANY, mocks['driver'], mock.ANY, ips)
        get_calls = [mock.call(data[ip][1]) for ip in data]
        mocks['driver'].get_subnet.assert_has_calls(get_calls, any_order=True)

        self._validate_allocate_calls(ips, mocks)

    def test_allocate_multiple_ips_with_exception(self):
        mocks = self._prepare_ipam()

        auto_ip = '172.23.128.94'
        fail_ip = '192.168.43.15'
        data = {'': ['172.23.128.0/17', self._gen_subnet_id()],
                fail_ip: ['192.168.43.0/24', self._gen_subnet_id()],
                '8.8.8.8': ['8.0.0.0/8', self._gen_subnet_id()]}
        ips = self._convert_to_ips(data)
        mocks['subnet'].allocate.side_effect = self._get_allocate_mock(
            auto_ip=auto_ip, fail_ip=fail_ip)

        # Exception should be raised on attempt to allocate second ip.
        # Revert action should be performed for the already allocated ips,
        # In this test case only one ip should be deallocated
        # and original error should be reraised
        self.assertRaises(n_exc.InvalidInput,
                          mocks['ipam']._ipam_allocate_ips,
                          mock.ANY,
                          mocks['driver'],
                          mock.ANY,
                          ips)

        # get_subnet should be called only for the first two networks
        get_calls = [mock.call(data[ip][1]) for ip in ['', fail_ip]]
        mocks['driver'].get_subnet.assert_has_calls(get_calls, any_order=True)

        # Allocate should be called for the first two ips only
        self._validate_allocate_calls(ips[:-1], mocks)
        # Deallocate should be called for the first ip only
        mocks['subnet'].deallocate.assert_called_once_with(auto_ip)

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

    @mock.patch('neutron.ipam.driver.Pool')
    def test_ipam_subnet_deallocated_if_create_fails(self, pool_mock):
        mocks = self._prepare_mocks_with_pool_mock(pool_mock)
        cidr = '10.0.2.0/24'
        with mock.patch.object(
                ipam_backend_mixin.IpamBackendMixin, '_save_subnet',
                side_effect=ValueError), self.network() as network:
            self._create_subnet(self.fmt, network['network']['id'],
                                cidr, expected_res_status=500)
            pool_mock.get_instance.assert_any_call(None, mock.ANY)
            self.assertEqual(2, pool_mock.get_instance.call_count)
            self.assertTrue(mocks['driver'].allocate_subnet.called)
            request = mocks['driver'].allocate_subnet.call_args[0][0]
            self.assertIsInstance(request, ipam_req.SpecificSubnetRequest)
            self.assertEqual(netaddr.IPNetwork(cidr), request.subnet_cidr)
            # Verify remove ipam subnet was called
            mocks['driver'].remove_subnet.assert_called_once_with(
                self.subnet_id)

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
                                   cidr, ip_version=4)
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
                                   cidr, ip_version=4)
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
        mocks['subnet'].allocate.side_effect = self._get_allocate_mock(
            auto_ip=auto_ip)
        with self.subnet() as subnet:
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
        mocks['subnet'].allocate.side_effect = self._get_allocate_mock(
            auto_ip=auto_ip)
        with self.subnet() as subnet:
            with self.port(subnet=subnet) as port:
                ips = port['port']['fixed_ips']
                self.assertEqual(1, len(ips))
                self.assertEqual(ips[0]['ip_address'], auto_ip)
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
        mocks['subnet'].allocate.side_effect = self._get_allocate_mock(
            auto_ip=auto_ip)
        with self.subnet() as subnet:
            with self.port(subnet=subnet) as port:
                ips = port['port']['fixed_ips']
                self.assertEqual(1, len(ips))
                self.assertEqual(ips[0]['ip_address'], auto_ip)
                req = self.new_delete_request('ports', port['port']['id'])
                res = req.get_response(self.api)

                self.assertEqual(webob.exc.HTTPNoContent.code, res.status_int)
                mocks['subnet'].deallocate.assert_called_once_with(auto_ip)

    def test_recreate_port_ipam(self):
        ip = '10.0.0.2'
        with self.subnet() as subnet:
            with self.port(subnet=subnet) as port:
                ips = port['port']['fixed_ips']
                self.assertEqual(1, len(ips))
                self.assertEqual(ips[0]['ip_address'], ip)
                req = self.new_delete_request('ports', port['port']['id'])
                res = req.get_response(self.api)
                self.assertEqual(webob.exc.HTTPNoContent.code, res.status_int)
                with self.port(subnet=subnet, fixed_ips=ips) as port:
                    ips = port['port']['fixed_ips']
                    self.assertEqual(1, len(ips))
                    self.assertEqual(ips[0]['ip_address'], ip)
