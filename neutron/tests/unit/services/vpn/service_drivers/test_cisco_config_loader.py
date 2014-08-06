# Copyright 2014 Cisco Systems, Inc.  All rights reserved.
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

"""Test module for interim implementation - to be removed later.

This tests using an INI file to obtain Cisco CSR router information
for IPSec site-to-site connections. Once the Cisco L3 router plugin
blueprint has been up-streamed, this can be removed and production code
switched to use the L3 plugin methods for:

    get_host_for_router()
    get_active_routers_for_host()

TODO(pcm): remove module, when Cisco L3 router plugin is up-streamed.
"""

import os
import tempfile

import mock
from oslo.config import cfg

from neutron import context as ctx
from neutron.openstack.common import uuidutils
from neutron.services.vpn.device_drivers import (
    cisco_csr_rest_client as csr_client)
from neutron.services.vpn.service_drivers import (
    cisco_cfg_loader as cfg_loader)
from neutron.tests import base

_uuid = uuidutils.generate_uuid
FAKE_ROUTER_ID = _uuid()
CISCO_GET_ROUTER_IP = ('neutron.services.vpn.service_drivers.'
                       'cisco_cfg_loader._get_external_ip_for_router')
CISCO_GET_ROUTER_ID = ('neutron.services.vpn.service_drivers.'
                       'cisco_cfg_loader._get_router_id_via_external_ip')


def create_tempfile(contents):
    (fd, path) = tempfile.mkstemp(prefix='test', suffix='.conf')
    try:
        os.write(fd, contents.encode('utf-8'))
    finally:
        os.close(fd)
    return path


class TestCiscoCsrServiceDriverConfigLoading(base.BaseTestCase):

    def test_loading_csr_configuration(self):
        """Ensure that Cisco CSR configs can be loaded from config files."""
        cfg_file = create_tempfile(
            '[CISCO_CSR_REST:3.2.1.1]\n'
            'rest_mgmt = 10.20.30.1\n'
            'tunnel_ip = 3.2.1.3\n'
            'username = me\n'
            'password = secret\n'
            'host = compute-node\n'
            'tunnel_if = GigabitEthernet3\n'
            'timeout = 5.0\n')
        expected = {'3.2.1.1': {'rest_mgmt_ip': '10.20.30.1',
                                'tunnel_ip': '3.2.1.3',
                                'username': 'me',
                                'password': 'secret',
                                'host': 'compute-node',
                                'tunnel_if': 'GigabitEthernet3',
                                'timeout': 5.0}}
        csrs_found = cfg_loader.get_available_csrs_from_config([cfg_file])
        self.assertEqual(expected, csrs_found)

    def test_loading_config_without_timeout(self):
        """Cisco CSR config without timeout will use default timeout."""
        cfg_file = create_tempfile(
            '[CISCO_CSR_REST:3.2.1.1]\n'
            'rest_mgmt = 10.20.30.1\n'
            'tunnel_ip = 3.2.1.3\n'
            'username = me\n'
            'password = secret\n'
            'host = compute-node\n'
            'tunnel_if = GigabitEthernet3\n')
        expected = {'3.2.1.1': {'rest_mgmt_ip': '10.20.30.1',
                                'tunnel_ip': '3.2.1.3',
                                'username': 'me',
                                'password': 'secret',
                                'host': 'compute-node',
                                'tunnel_if': 'GigabitEthernet3',
                                'timeout': csr_client.TIMEOUT}}
        csrs_found = cfg_loader.get_available_csrs_from_config([cfg_file])
        self.assertEqual(expected, csrs_found)

    def test_skip_loading_duplicate_csr_configuration(self):
        """Failure test that duplicate configurations are ignored."""
        cfg_file = create_tempfile(
            '[CISCO_CSR_REST:3.2.1.1]\n'
            'rest_mgmt = 10.20.30.1\n'
            'tunnel_ip = 3.2.1.3\n'
            'username = me\n'
            'password = secret\n'
            'host = compute-node\n'
            'tunnel_if = GigabitEthernet3\n'
            'timeout = 5.0\n'
            '[CISCO_CSR_REST:3.2.1.1]\n'
            'rest_mgmt = 5.5.5.3\n'
            'tunnel_ip = 3.2.1.6\n'
            'username = me\n'
            'password = secret\n'
            'host = compute-node\n'
            'tunnel_if = GigabitEthernet3\n')
        expected = {'3.2.1.1': {'rest_mgmt_ip': '10.20.30.1',
                                'tunnel_ip': '3.2.1.3',
                                'username': 'me',
                                'password': 'secret',
                                'host': 'compute-node',
                                'tunnel_if': 'GigabitEthernet3',
                                'timeout': 5.0}}
        csrs_found = cfg_loader.get_available_csrs_from_config([cfg_file])
        self.assertEqual(expected, csrs_found)

    def test_fail_loading_config_with_invalid_timeout(self):
        """Failure test of invalid timeout in config info."""
        cfg_file = create_tempfile(
            '[CISCO_CSR_REST:3.2.1.1]\n'
            'rest_mgmt = 10.20.30.1\n'
            'tunnel_ip = 3.2.1.3\n'
            'username = me\n'
            'password = secret\n'
            'host = compute-node\n'
            'tunnel_if = GigabitEthernet3\n'
            'timeout = yes\n')
        csrs_found = cfg_loader.get_available_csrs_from_config([cfg_file])
        self.assertEqual({}, csrs_found)

    def test_fail_loading_config_missing_required_info(self):
        """Failure test of config missing required info."""
        cfg_file = create_tempfile(
            '[CISCO_CSR_REST:1.1.1.0]\n'
            # No rest_mgmt
            'tunnel_ip = 1.1.1.3\n'
            'username = me\n'
            'password = secret\n'
            'host = compute-node\n'
            'tunnel_if = GigabitEthernet3\n'
            'timeout = 5.0\n'

            '[CISCO_CSR_REST:2.2.2.0]\n'
            'rest_mgmt = 10.20.30.2\n'
            # No tunnel_ip
            'username = me\n'
            'password = secret\n'
            'host = compute-node\n'
            'tunnel_if = GigabitEthernet3\n'
            'timeout = 5.0\n'

            '[CISCO_CSR_REST:3.3.3.0]\n'
            'rest_mgmt = 10.20.30.3\n'
            'tunnel_ip = 3.3.3.3\n'
            # No username
            'password = secret\n'
            'host = compute-node\n'
            'tunnel_if = GigabitEthernet3\n'
            'timeout = 5.0\n'

            '[CISCO_CSR_REST:4.4.4.0]\n'
            'rest_mgmt = 10.20.30.4\n'
            'tunnel_ip = 4.4.4.4\n'
            'username = me\n'
            # No password
            'host = compute-node\n'
            'tunnel_if = GigabitEthernet3\n'
            'timeout = 5.0\n'

            '[CISCO_CSR_REST:5.5.5.0]\n'
            'rest_mgmt = 10.20.30.5\n'
            'tunnel_ip = 5.5.5.5'
            'username = me\n'
            'password = secret\n'
            # No host
            'tunnel_if = GigabitEthernet3\n'
            'timeout = 5.0\n'

            '[CISCO_CSR_REST:6.6.6.0]\n'
            'rest_mgmt = 10.20.30.6\n'
            'tunnel_ip = 6.6.6.6'
            'username = me\n'
            'password = secret\n'
            'host = compute-node\n'
            # No tunnel_if
            'timeout = 5.0\n')
        csrs_found = cfg_loader.get_available_csrs_from_config([cfg_file])
        self.assertEqual({}, csrs_found)

    def test_fail_loading_config_with_invalid_router_id(self):
        """Failure test of config with invalid rotuer ID."""
        cfg_file = create_tempfile(
            '[CISCO_CSR_REST:4.3.2.1.9]\n'
            'rest_mgmt = 10.20.30.1\n'
            'tunnel_ip = 4.3.2.3\n'
            'username = me\n'
            'password = secret\n'
            'host = compute-node\n'
            'tunnel_if = GigabitEthernet3\n'
            'timeout = 5.0\n')
        csrs_found = cfg_loader.get_available_csrs_from_config([cfg_file])
        self.assertEqual({}, csrs_found)

    def test_fail_loading_config_with_invalid_mgmt_ip(self):
        """Failure test of configuration with invalid management IP address."""
        cfg_file = create_tempfile(
            '[CISCO_CSR_REST:3.2.1.1]\n'
            'rest_mgmt = 1.1.1.1.1\n'
            'tunnel_ip = 3.2.1.3\n'
            'username = me\n'
            'password = secret\n'
            'host = compute-node\n'
            'tunnel_if = GigabitEthernet3\n'
            'timeout = 5.0\n')
        csrs_found = cfg_loader.get_available_csrs_from_config([cfg_file])
        self.assertEqual({}, csrs_found)

    def test_fail_loading_config_with_invalid_tunnel_ip(self):
        """Failure test of configuration with invalid tunnel IP address."""
        cfg_file = create_tempfile(
            '[CISCO_CSR_REST:3.2.1.1]\n'
            'rest_mgmt = 1.1.1.1\n'
            'tunnel_ip = 3.2.1.4.5\n'
            'username = me\n'
            'password = secret\n'
            'host = compute-node\n'
            'tunnel_if = GigabitEthernet3\n'
            'timeout = 5.0\n')
        csrs_found = cfg_loader.get_available_csrs_from_config([cfg_file])
        self.assertEqual({}, csrs_found)

    def test_failure_no_configurations_entries(self):
        """Failure test config file without any CSR definitions."""
        cfg_file = create_tempfile('NO CISCO SECTION AT ALL\n')
        csrs_found = cfg_loader.get_available_csrs_from_config([cfg_file])
        self.assertEqual({}, csrs_found)

    def test_failure_no_csr_configurations_entries(self):
        """Failure test config file without any CSR definitions."""
        cfg_file = create_tempfile('[SOME_CONFIG:123]\n'
                                   'username = me\n')
        csrs_found = cfg_loader.get_available_csrs_from_config([cfg_file])
        self.assertEqual({}, csrs_found)

    def test_missing_config_value(self):
        """Failure test of config file missing a value for attribute."""
        cfg_file = create_tempfile(
            '[CISCO_CSR_REST:3.2.1.1]\n'
            'rest_mgmt = \n'
            'tunnel_ip = 3.2.1.3\n'
            'username = me\n'
            'password = secret\n'
            'host = compute-node\n'
            'tunnel_if = GigabitEthernet3\n'
            'timeout = 5.0\n')
        csrs_found = cfg_loader.get_available_csrs_from_config([cfg_file])
        self.assertEqual({}, csrs_found)

    def test_ignores_invalid_attribute_in_config(self):
        """Test ignoring of config file with invalid attribute."""
        cfg_file = create_tempfile(
            '[CISCO_CSR_REST:3.2.1.1]\n'
            'rest_mgmt = 1.1.1.1\n'
            'bogus = abcdef\n'
            'tunnel_ip = 3.2.1.3\n'
            'username = me\n'
            'password = secret\n'
            'host = compute-node\n'
            'tunnel_if = GigabitEthernet3\n'
            'timeout = 15.5\n')
        expected = {'3.2.1.1': {'rest_mgmt_ip': '1.1.1.1',
                                'tunnel_ip': '3.2.1.3',
                                'username': 'me',
                                'password': 'secret',
                                'host': 'compute-node',
                                'tunnel_if': 'GigabitEthernet3',
                                'timeout': 15.5}}
        csrs_found = cfg_loader.get_available_csrs_from_config([cfg_file])
        self.assertEqual(expected, csrs_found)

    def test_invalid_management_interface(self):
        """Failure test of invalid management interface name."""
        cfg_file = create_tempfile(
            '[CISCO_CSR_REST:3.2.1.1]\n'
            'rest_mgmt = 1.1.1.1\n'
            'tunnel_ip = 3.2.1.3\n'
            'username = me\n'
            'password = secret\n'
            'host = compute-node\n'
            'tunnel_if = GigabitEthernet9\n'
            'timeout = 5.0\n')
        csrs_found = cfg_loader.get_available_csrs_from_config([cfg_file])
        self.assertEqual({}, csrs_found)


class TestCiscoCsrRouterInfo(base.BaseTestCase):

    def setUp(self):
        super(TestCiscoCsrRouterInfo, self).setUp()
        self.context = ctx.get_admin_context()

    def test_find_host_for_router(self):
        """Look up host in INI file for a router."""
        cfg_file = create_tempfile(
            '[CISCO_CSR_REST:3.2.1.1]\n'
            'rest_mgmt = 10.20.30.1\n'
            'tunnel_ip = 3.2.1.3\n'
            'username = me\n'
            'password = secret\n'
            'host = ubuntu\n'
            'tunnel_if = GigabitEthernet1\n'
            'mgmt_vlan = 100\n'
            'timeout = 5.0\n')
        cfg.CONF.set_override('config_file', [cfg_file])
        mock.patch(CISCO_GET_ROUTER_IP, return_value='3.2.1.1').start()
        self.assertEqual('ubuntu',
                         cfg_loader.get_host_for_router(self.context,
                                                        FAKE_ROUTER_ID))

    def test_failed_to_find_host_as_no_routers_in_ini(self):
        """Fail to find host, as no router info in INI file."""
        cfg_file = create_tempfile('\n')
        cfg.CONF.set_override('config_file', [cfg_file])
        mock.patch(CISCO_GET_ROUTER_IP, return_value='5.5.5.5').start()
        self.assertEqual('',
                         cfg_loader.get_host_for_router(self.context,
                                                        FAKE_ROUTER_ID))

    def test_failed_no_matching_router_to_obtain_host(self):
        """Fail to find INI info for router provided."""
        cfg_file = create_tempfile(
            '[CISCO_CSR_REST:3.2.1.1]\n'
            'rest_mgmt = 10.20.30.1\n'
            'tunnel_ip = 3.2.1.3\n'
            'username = me\n'
            'password = secret\n'
            'host = ubuntu\n'
            'tunnel_if = GigabitEthernet3\n'
            'timeout = 5.0\n')
        cfg.CONF.set_override('config_file', [cfg_file])
        mock.patch(CISCO_GET_ROUTER_IP, return_value='5.5.5.5').start()
        self.assertEqual('',
                         cfg_loader.get_host_for_router(self.context,
                                                        FAKE_ROUTER_ID))

    def test_failed_to_find_router_ip(self):
        """Fail to lookup router IP, preventing search in INI file."""
        cfg_file = create_tempfile(
            '[CISCO_CSR_REST:3.2.1.1]\n'
            'rest_mgmt = 10.20.30.1\n'
            'tunnel_ip = 3.2.1.3\n'
            'username = me\n'
            'password = secret\n'
            'host = ubuntu\n'
            'tunnel_if = GigabitEthernet3\n'
            'timeout = 5.0\n')
        cfg.CONF.set_override('config_file', [cfg_file])
        mock.patch(CISCO_GET_ROUTER_IP, return_value=None).start()
        self.assertEqual('',
                         cfg_loader.get_host_for_router(self.context,
                                                        FAKE_ROUTER_ID))

    def _get_router_id_from_external_ip(self, context, ip):
        if ip == '3.2.1.1':
            return '123'
        elif ip == '4.3.2.1':
            return '456'

    def test_get_one_active_router_for_host(self):
        """Get router info from INI for host specified."""
        cfg_file = create_tempfile(
            '[CISCO_CSR_REST:3.2.1.1]\n'
            'rest_mgmt = 10.20.30.1\n'
            'tunnel_ip = 3.2.1.3\n'
            'username = me\n'
            'password = secret\n'
            'host = ubuntu\n'
            'tunnel_if = GigabitEthernet2\n'
            'timeout = 5.0\n')
        cfg.CONF.set_override('config_file', [cfg_file])
        mock.patch(CISCO_GET_ROUTER_ID,
                   side_effect=self._get_router_id_from_external_ip).start()
        expected = {
            'id': '123',
            'hosting_device': {
                'management_ip_address': '10.20.30.1',
                'credentials': {'username': 'me', 'password': 'secret'}
            },
            'tunnel_if': 'GigabitEthernet2',
            'tunnel_ip': '3.2.1.3'
        }
        routers = cfg_loader.get_active_routers_for_host(self.context,
                                                         "ubuntu")
        self.assertEqual([expected], routers)

    def test_get_two_active_routers_for_host(self):
        """Get info for two routers, from INI file, for host specified."""
        cfg_file = create_tempfile(
            '[CISCO_CSR_REST:3.2.1.1]\n'
            'rest_mgmt = 10.20.30.1\n'
            'tunnel_ip = 3.2.1.1\n'
            'username = me\n'
            'password = secret\n'
            'host = ubuntu\n'
            'tunnel_if = GigabitEthernet2\n'
            'timeout = 5.0\n'
            '[CISCO_CSR_REST:4.3.2.1]\n'
            'rest_mgmt = 10.20.30.2\n'
            'tunnel_ip = 4.3.2.1\n'
            'username = you\n'
            'password = insecure\n'
            'host = ubuntu\n'
            'tunnel_if = GigabitEthernet3\n'
            'timeout = 5.0\n')
        cfg.CONF.set_override('config_file', [cfg_file])
        mock.patch(CISCO_GET_ROUTER_ID,
                   side_effect=self._get_router_id_from_external_ip).start()
        expected_a = {
            'id': '123',
            'hosting_device': {
                'management_ip_address': '10.20.30.1',
                'credentials': {'username': 'me', 'password': 'secret'}
            },
            'tunnel_if': 'GigabitEthernet2',
            'tunnel_ip': '3.2.1.1'
        }
        expected_b = {
            'id': '456',
            'hosting_device': {
                'management_ip_address': '10.20.30.2',
                'credentials': {'username': 'you', 'password': 'insecure'}
            },
            'tunnel_if': 'GigabitEthernet3',
            'tunnel_ip': '4.3.2.1'
        }
        routers = cfg_loader.get_active_routers_for_host(self.context,
                                                         "ubuntu")
        sorted_routers = sorted(routers, key=lambda key: key['id'])
        self.assertEqual([expected_a, expected_b], sorted_routers)

    def test_failure_to_find_routers_for_host(self):
        """Fail to find a router in INI with matching host name."""
        routers = cfg_loader.get_active_routers_for_host(self.context,
                                                         "bogus")
        self.assertEqual([], routers)

    def test_failure_to_lookup_router_id_for_host(self):
        """Fail to get router UUID for router in INI matching host name."""
        cfg_file = create_tempfile(
            '[CISCO_CSR_REST:6.6.6.1]\n'
            'rest_mgmt = 10.20.30.1\n'
            'tunnel_ip = 6.6.6.1\n'
            'username = me\n'
            'password = secret\n'
            'host = ubuntu\n'
            'tunnel_if = GigabitEthernet3\n'
            'timeout = 5.0\n')
        cfg.CONF.set_override('config_file', [cfg_file])
        mock.patch(CISCO_GET_ROUTER_ID,
                   side_effect=self._get_router_id_from_external_ip).start()
        routers = cfg_loader.get_active_routers_for_host(self.context,
                                                         "ubuntu")
        self.assertEqual([], routers)
