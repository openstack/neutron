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

import mock

from neutron.agent.common import utils
from neutron.agent.linux import interface
from neutron.conf.agent import common as config
from neutron.tests import base
from neutron.tests.unit import testlib_api


class TestLoadInterfaceDriver(base.BaseTestCase):

    def setUp(self):
        super(TestLoadInterfaceDriver, self).setUp()
        self.conf = config.setup_conf()
        config.register_interface_opts(self.conf)
        config.register_interface_driver_opts_helper(self.conf)

    def test_load_interface_driver_not_set(self):
        with testlib_api.ExpectedException(SystemExit):
            utils.load_interface_driver(self.conf)

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

    def test_load_linuxbridge_interface_driver_success(self):
        self.conf.set_override('interface_driver',
                               'linuxbridge')
        self.assertIsInstance(utils.load_interface_driver(self.conf),
                              interface.BridgeInterfaceDriver)

    def test_load_ovs_interface_driver_success(self):
        self.conf.set_override('interface_driver',
                               'openvswitch')
        self.assertIsInstance(utils.load_interface_driver(self.conf),
                              interface.OVSInterfaceDriver)

    def test_load_interface_driver_as_alias_wrong_driver(self):
        self.conf.set_override('interface_driver', 'openvswitchXX')
        with testlib_api.ExpectedException(SystemExit):
            utils.load_interface_driver(self.conf)


class TestDefaultRpHypervisors(base.BaseTestCase):

    def test_defaults(self):
        this_host = socket.gethostname()

        self.assertEqual(
            {'eth0': this_host, 'eth1': this_host},
            utils.default_rp_hypervisors(
                hypervisors={},
                device_mappings={'physnet0': ['eth0', 'eth1']},
            )
        )

        self.assertEqual(
            {'eth0': 'thathost', 'eth1': this_host},
            utils.default_rp_hypervisors(
                hypervisors={'eth0': 'thathost'},
                device_mappings={'physnet0': ['eth0', 'eth1']},
            )
        )
