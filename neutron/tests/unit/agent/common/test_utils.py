# Copyright 2015 Red Hat, Inc.
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

import socket
from unittest import mock

from oslo_config import cfg

from neutron.agent.common import utils
from neutron.agent.linux import interface
from neutron.conf.agent import common as config
from neutron.conf.plugins.ml2 import config as ml2_config
from neutron.tests import base
from neutron.tests.unit import testlib_api


class TestLoadInterfaceDriver(base.BaseTestCase):

    def setUp(self):
        super().setUp()
        self.conf = config.setup_conf()
        config.register_interface_opts(self.conf)
        config.register_interface_driver_opts_helper(self.conf)

    def test_load_interface_driver_wrong_driver(self):
        self.conf.set_override('interface_driver', 'neutron.NonExistentDriver')
        with testlib_api.ExpectedException(SystemExit):
            utils.load_interface_driver(self.conf)

    def test_load_interface_driver_does_not_consume_irrelevant_errors(self):
        self.conf.set_override('interface_driver',
                               'neutron.agent.linux.interface.NullDriver')
        with mock.patch('oslo_utils.importutils.import_class',
                        side_effect=RuntimeError()):
            with testlib_api.ExpectedException(RuntimeError):
                utils.load_interface_driver(self.conf)

    def test_load_interface_driver_default(self):
        self.assertIsInstance(utils.load_interface_driver(self.conf),
                              interface.OVSInterfaceDriver)

    def test_load_interface_driver_success(self):
        self.conf.set_override('interface_driver',
                               'neutron.agent.linux.interface.NullDriver')
        self.assertIsInstance(utils.load_interface_driver(self.conf),
                              interface.NullDriver)

    def test_load_null_interface_driver_success(self):
        self.conf.set_override('interface_driver',
                               'null')
        self.assertIsInstance(utils.load_interface_driver(self.conf),
                              interface.NullDriver)

    def test_load_ovs_interface_driver_success(self):
        self.conf.set_override('interface_driver',
                               'openvswitch')
        self.assertIsInstance(utils.load_interface_driver(self.conf),
                              interface.OVSInterfaceDriver)

    def test_load_interface_driver_as_alias_wrong_driver(self):
        self.conf.set_override('interface_driver', 'openvswitchXX')
        with testlib_api.ExpectedException(SystemExit):
            utils.load_interface_driver(self.conf)


class TestGetHypervisorHostname(base.BaseTestCase):

    @mock.patch.object(socket, 'getaddrinfo')
    @mock.patch('socket.gethostname')
    def test_get_hypervisor_hostname_gethostname_fqdn(self, hostname_mock,
                                                      addrinfo_mock):
        hostname_mock.return_value = 'host.domain'
        self.assertEqual(
            'host.domain',
            utils.get_hypervisor_hostname())
        addrinfo_mock.assert_not_called()

    @mock.patch.object(socket, 'getaddrinfo')
    @mock.patch('socket.gethostname')
    def test_get_hypervisor_hostname_gethostname_localhost(self, hostname_mock,
                                                           addrinfo_mock):
        hostname_mock.return_value = 'localhost'
        self.assertEqual(
            'localhost',
            utils.get_hypervisor_hostname())
        addrinfo_mock.assert_not_called()

    @mock.patch.object(socket, 'getaddrinfo')
    @mock.patch('socket.gethostname')
    def test_get_hypervisor_hostname_getaddrinfo(self, hostname_mock,
                                                 addrinfo_mock):
        hostname_mock.return_value = 'host'
        addrinfo_mock.return_value = [(None, None, None, 'host.domain', None)]
        self.assertEqual(
            'host.domain',
            utils.get_hypervisor_hostname())
        addrinfo_mock.assert_called_once_with(
            host='host', port=None, family=socket.AF_UNSPEC,
            flags=socket.AI_CANONNAME)

    @mock.patch.object(socket, 'getaddrinfo')
    @mock.patch('socket.gethostname')
    def test_get_hypervisor_hostname_getaddrinfo_no_canonname(self,
                                                              hostname_mock,
                                                              addrinfo_mock):
        hostname_mock.return_value = 'host'
        addrinfo_mock.return_value = [(None, None, None, '', None)]
        self.assertEqual(
            'host',
            utils.get_hypervisor_hostname())
        addrinfo_mock.assert_called_once_with(
            host='host', port=None, family=socket.AF_UNSPEC,
            flags=socket.AI_CANONNAME)

    @mock.patch.object(socket, 'getaddrinfo')
    @mock.patch('socket.gethostname')
    def test_get_hypervisor_hostname_getaddrinfo_localhost(self, hostname_mock,
                                                           addrinfo_mock):
        hostname_mock.return_value = 'host'
        addrinfo_mock.return_value = [(None, None, None,
                                       'localhost', None)]
        self.assertEqual(
            'host',
            utils.get_hypervisor_hostname())
        addrinfo_mock.assert_called_once_with(
            host='host', port=None, family=socket.AF_UNSPEC,
            flags=socket.AI_CANONNAME)

    @mock.patch.object(socket, 'getaddrinfo')
    @mock.patch('socket.gethostname')
    def test_get_hypervisor_hostname_getaddrinfo_fail(self, hostname_mock,
                                                      addrinfo_mock):
        hostname_mock.return_value = 'host'
        addrinfo_mock.side_effect = OSError
        self.assertEqual(
            'host',
            utils.get_hypervisor_hostname())
        addrinfo_mock.assert_called_once_with(
            host='host', port=None, family=socket.AF_UNSPEC,
            flags=socket.AI_CANONNAME)


# TODO(bence romsics): rehome this to neutron_lib
class TestDefaultRpHypervisors(base.BaseTestCase):

    def setUp(self):
        super().setUp()
        ml2_config.register_ml2_plugin_opts()

    @mock.patch.object(utils, 'get_hypervisor_hostname',
                       return_value='thishost')
    def test_defaults(self, hostname_mock):

        self.assertEqual(
            {'eth0': 'thishost', 'eth1': 'thishost'},
            utils.default_rp_hypervisors(
                hypervisors={},
                device_mappings={'physnet0': ['eth0', 'eth1']},
                default_hypervisor=None,
            )
        )

        self.assertEqual(
            {'eth0': 'thathost', 'eth1': 'thishost'},
            utils.default_rp_hypervisors(
                hypervisors={'eth0': 'thathost'},
                device_mappings={'physnet0': ['eth0', 'eth1']},
                default_hypervisor=None,
            )
        )

        self.assertEqual(
            {'eth0': 'defaulthost', 'eth1': 'defaulthost'},
            utils.default_rp_hypervisors(
                hypervisors={},
                device_mappings={'physnet0': ['eth0', 'eth1']},
                default_hypervisor='defaulthost',
            )
        )

        self.assertEqual(
            {'eth0': 'thathost', 'eth1': 'defaulthost'},
            utils.default_rp_hypervisors(
                hypervisors={'eth0': 'thathost'},
                device_mappings={'physnet0': ['eth0', 'eth1']},
                default_hypervisor='defaulthost',
            )
        )

        rp_tunnelled = cfg.CONF.ml2.tunnelled_network_rp_name
        self.assertEqual(
            {'eth0': 'thathost', 'eth1': 'defaulthost',
             rp_tunnelled: 'defaulthost'},
            utils.default_rp_hypervisors(
                hypervisors={'eth0': 'thathost'},
                device_mappings={'physnet0': ['eth0', 'eth1']},
                default_hypervisor='defaulthost',
                tunnelled_network_rp_name=rp_tunnelled
            )
        )

        self.assertEqual(
            {'eth0': 'thathost', 'eth1': 'defaulthost',
             rp_tunnelled: 'thathost'},
            utils.default_rp_hypervisors(
                hypervisors={'eth0': 'thathost', rp_tunnelled: 'thathost'},
                device_mappings={'physnet0': ['eth0', 'eth1']},
                default_hypervisor='defaulthost',
                tunnelled_network_rp_name=rp_tunnelled
            )
        )
