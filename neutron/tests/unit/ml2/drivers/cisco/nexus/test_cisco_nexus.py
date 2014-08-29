# Copyright (c) 2013 OpenStack Foundation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import collections
import mock
import testtools

from neutron.common import constants as n_const
from neutron.extensions import portbindings
from neutron.openstack.common import importutils
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2.drivers.cisco.nexus import constants
from neutron.plugins.ml2.drivers.cisco.nexus import exceptions
from neutron.plugins.ml2.drivers.cisco.nexus import mech_cisco_nexus
from neutron.plugins.ml2.drivers.cisco.nexus import nexus_db_v2
from neutron.plugins.ml2.drivers.cisco.nexus import nexus_network_driver
from neutron.tests.unit import testlib_api


NEXUS_IP_ADDRESS = '1.1.1.1'
NEXUS_IP_ADDRESS_PC = '2.2.2.2'
NEXUS_IP_ADDRESS_DUAL = '3.3.3.3'
HOST_NAME_1 = 'testhost1'
HOST_NAME_2 = 'testhost2'
HOST_NAME_PC = 'testpchost'
HOST_NAME_DUAL = 'testdualhost'
INSTANCE_1 = 'testvm1'
INSTANCE_2 = 'testvm2'
INSTANCE_PC = 'testpcvm'
INSTANCE_DUAL = 'testdualvm'
NEXUS_PORT_1 = 'ethernet:1/10'
NEXUS_PORT_2 = 'ethernet:1/20'
NEXUS_PORTCHANNELS = 'portchannel:2'
NEXUS_DUAL = 'ethernet:1/3,portchannel:2'
VLAN_ID_1 = 267
VLAN_ID_2 = 265
VLAN_ID_PC = 268
VLAN_ID_DUAL = 269
DEVICE_OWNER = 'compute:test'
NEXUS_SSH_PORT = '22'
PORT_STATE = n_const.PORT_STATUS_ACTIVE
NETWORK_TYPE = 'vlan'
NEXUS_DRIVER = ('neutron.plugins.ml2.drivers.cisco.nexus.'
                'nexus_network_driver.CiscoNexusDriver')


class FakeNetworkContext(object):

    """Network context for testing purposes only."""

    def __init__(self, segment_id):
        self._network_segments = {api.SEGMENTATION_ID: segment_id,
                                  api.NETWORK_TYPE: NETWORK_TYPE}

    @property
    def network_segments(self):
        return self._network_segments


class FakePortContext(object):

    """Port context for testing purposes only."""

    def __init__(self, device_id, host_name, network_context):
        self._port = {
            'status': PORT_STATE,
            'device_id': device_id,
            'device_owner': DEVICE_OWNER,
            portbindings.HOST_ID: host_name,
            portbindings.VIF_TYPE: portbindings.VIF_TYPE_OVS
        }
        self._network = network_context
        self._segment = network_context.network_segments

    @property
    def current(self):
        return self._port

    @property
    def network(self):
        return self._network

    @property
    def bound_segment(self):
        return self._segment


class TestCiscoNexusDevice(testlib_api.SqlTestCase):

    """Unit tests for Cisco ML2 Nexus device driver."""

    TestConfigObj = collections.namedtuple(
        'TestConfigObj',
        'nexus_ip_addr host_name nexus_port instance_id vlan_id')

    test_configs = {
        'test_config1': TestConfigObj(
            NEXUS_IP_ADDRESS,
            HOST_NAME_1,
            NEXUS_PORT_1,
            INSTANCE_1,
            VLAN_ID_1),
        'test_config2': TestConfigObj(
            NEXUS_IP_ADDRESS,
            HOST_NAME_2,
            NEXUS_PORT_2,
            INSTANCE_2,
            VLAN_ID_2),
        'test_config_portchannel': TestConfigObj(
            NEXUS_IP_ADDRESS_PC,
            HOST_NAME_PC,
            NEXUS_PORTCHANNELS,
            INSTANCE_PC,
            VLAN_ID_PC),
        'test_config_dual': TestConfigObj(
            NEXUS_IP_ADDRESS_DUAL,
            HOST_NAME_DUAL,
            NEXUS_DUAL,
            INSTANCE_DUAL,
            VLAN_ID_DUAL),
    }

    def setUp(self):
        """Sets up mock ncclient, and switch and credentials dictionaries."""
        super(TestCiscoNexusDevice, self).setUp()

        # Use a mock netconf client
        mock_ncclient = mock.Mock()
        mock.patch.object(nexus_network_driver.CiscoNexusDriver,
                          '_import_ncclient',
                          return_value=mock_ncclient).start()

        def new_nexus_init(mech_instance):
            mech_instance.driver = importutils.import_object(NEXUS_DRIVER)

            mech_instance._nexus_switches = {}
            for name, config in TestCiscoNexusDevice.test_configs.items():
                ip_addr = config.nexus_ip_addr
                host_name = config.host_name
                nexus_port = config.nexus_port
                mech_instance._nexus_switches[(ip_addr,
                                               host_name)] = nexus_port
                mech_instance._nexus_switches[(ip_addr,
                                               'ssh_port')] = NEXUS_SSH_PORT
                mech_instance._nexus_switches[(ip_addr,
                                               constants.USERNAME)] = 'admin'
                mech_instance._nexus_switches[(ip_addr,
                                              constants.PASSWORD)] = 'password'
            mech_instance.driver.nexus_switches = (
                mech_instance._nexus_switches)

        mock.patch.object(mech_cisco_nexus.CiscoNexusMechanismDriver,
                          '__init__', new=new_nexus_init).start()
        self._cisco_mech_driver = (mech_cisco_nexus.
                                   CiscoNexusMechanismDriver())

    def _create_delete_port(self, port_config):
        """Tests creation and deletion of a virtual port."""
        nexus_ip_addr = port_config.nexus_ip_addr
        host_name = port_config.host_name
        nexus_port = port_config.nexus_port
        instance_id = port_config.instance_id
        vlan_id = port_config.vlan_id

        network_context = FakeNetworkContext(vlan_id)
        port_context = FakePortContext(instance_id, host_name,
                                       network_context)

        self._cisco_mech_driver.update_port_precommit(port_context)
        self._cisco_mech_driver.update_port_postcommit(port_context)
        for port_id in nexus_port.split(','):
            bindings = nexus_db_v2.get_nexusport_binding(port_id,
                                                         vlan_id,
                                                         nexus_ip_addr,
                                                         instance_id)
            self.assertEqual(len(bindings), 1)

        self._cisco_mech_driver.delete_port_precommit(port_context)
        self._cisco_mech_driver.delete_port_postcommit(port_context)
        for port_id in nexus_port.split(','):
            with testtools.ExpectedException(
                    exceptions.NexusPortBindingNotFound):
                nexus_db_v2.get_nexusport_binding(port_id,
                                                  vlan_id,
                                                  nexus_ip_addr,
                                                  instance_id)

    def test_create_delete_ports(self):
        """Tests creation and deletion of two new virtual Ports."""
        self._create_delete_port(
            TestCiscoNexusDevice.test_configs['test_config1'])

        self._create_delete_port(
            TestCiscoNexusDevice.test_configs['test_config2'])

    def test_create_delete_portchannel(self):
        """Tests creation of a port over a portchannel."""
        self._create_delete_port(
            TestCiscoNexusDevice.test_configs['test_config_portchannel'])

    def test_create_delete_dual(self):
        """Tests creation and deletion of dual ports for single server"""
        self._create_delete_port(
            TestCiscoNexusDevice.test_configs['test_config_dual'])
