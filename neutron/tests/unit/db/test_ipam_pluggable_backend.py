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

from oslo_utils import uuidutils

from neutron.common import exceptions as n_exc
from neutron.common import ipv6_utils
from neutron.db import ipam_pluggable_backend
from neutron.ipam import requests as ipam_req
from neutron.tests.unit.db import test_db_base_plugin_v2 as test_db_base


class TestDbBasePluginIpam(test_db_base.NeutronDbPluginV2TestCase):
    def setUp(self):
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
        assert mocks['subnet'].allocate.called

        actual_calls = mocks['subnet'].allocate.call_args_list
        self.assertEqual(len(expected_calls), len(actual_calls))

        i = 0
        for call in expected_calls:
            if call['ip_address']:
                self.assertEqual(ipam_req.SpecificAddressRequest,
                                 type(actual_calls[i][0][0]))
                self.assertEqual(netaddr.IPAddress(call['ip_address']),
                                 actual_calls[i][0][0].address)
            else:
                self.assertEqual(ipam_req.AnyAddressRequest,
                                 type(actual_calls[i][0][0]))
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

        assert mocks['subnet'].allocate.called
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

        self.assertEqual(ipam_req.SpecificAddressRequest,
                         type(results['request']))
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

        self.assertEqual(ipam_req.AnyAddressRequest, type(results['request']))
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
        self.assertEqual(ipam_req.AutomaticAddressRequest, type(request))
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
