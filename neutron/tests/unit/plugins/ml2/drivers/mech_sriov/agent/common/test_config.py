# Copyright 2014 Mellanox Technologies, Ltd
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

from neutron_lib.utils import helpers
from oslo_config import cfg

from neutron.conf.plugins.ml2.drivers.mech_sriov import agent_common \
     as agent_common_config
from neutron.plugins.ml2.drivers.mech_sriov.agent.common import config
from neutron.plugins.ml2.drivers.mech_sriov.agent \
    import sriov_nic_agent as agent
from neutron.tests import base


class TestSriovAgentConfig(base.BaseTestCase):
    EXCLUDE_DEVICES_LIST = ['p7p1:0000:07:00.1;0000:07:00.2',
                            'p3p1:0000:04:00.3']

    EXCLUDE_DEVICES_LIST_INVALID = ['p7p2:0000:07:00.1;0000:07:00.2']

    EXCLUDE_DEVICES_WITH_SPACES_LIST = ['p7p1: 0000:07:00.1 ; 0000:07:00.2',
                                        'p3p1:0000:04:00.3 ']

    EXCLUDE_DEVICES_WITH_SPACES_ERROR = ['p7p1',
                                         'p3p1:0000:04:00.3 ']

    EXCLUDE_DEVICES = {'p7p1': set(['0000:07:00.1', '0000:07:00.2']),
                       'p3p1': set(['0000:04:00.3'])}

    DEVICE_MAPPING_LIST = ['physnet7:p7p1',
                           'physnet3:p3p1']

    DEVICE_MAPPING_WITH_ERROR_LIST = ['physnet7',
                                      'physnet3:p3p1']

    DEVICE_MAPPING_WITH_SPACES_LIST = ['physnet7 : p7p1',
                                       'physnet3 : p3p1 ']
    DEVICE_MAPPING = {'physnet7': ['p7p1'],
                      'physnet3': ['p3p1']}

    def test_defaults(self):
        self.assertEqual(agent_common_config.DEFAULT_DEVICE_MAPPINGS,
                         cfg.CONF.SRIOV_NIC.physical_device_mappings)
        self.assertEqual(agent_common_config.DEFAULT_EXCLUDE_DEVICES,
                         cfg.CONF.SRIOV_NIC.exclude_devices)
        self.assertEqual(2,
                         cfg.CONF.AGENT.polling_interval)

    def test_device_mappings(self):
        cfg.CONF.set_override('physical_device_mappings',
                              self.DEVICE_MAPPING_LIST,
                              'SRIOV_NIC')
        device_mappings = helpers.parse_mappings(
            cfg.CONF.SRIOV_NIC.physical_device_mappings, unique_keys=False)
        self.assertEqual(self.DEVICE_MAPPING, device_mappings)

    def test_device_mappings_with_error(self):
        cfg.CONF.set_override('physical_device_mappings',
                              self.DEVICE_MAPPING_WITH_ERROR_LIST,
                              'SRIOV_NIC')
        self.assertRaises(ValueError, helpers.parse_mappings,
                          cfg.CONF.SRIOV_NIC.physical_device_mappings,
                          unique_keys=False)

    def test_device_mappings_with_spaces(self):
        cfg.CONF.set_override('physical_device_mappings',
                              self.DEVICE_MAPPING_WITH_SPACES_LIST,
                              'SRIOV_NIC')
        device_mappings = helpers.parse_mappings(
            cfg.CONF.SRIOV_NIC.physical_device_mappings, unique_keys=False)
        self.assertEqual(self.DEVICE_MAPPING, device_mappings)

    def test_exclude_devices(self):
        cfg.CONF.set_override('exclude_devices',
                              self.EXCLUDE_DEVICES_LIST,
                              'SRIOV_NIC')
        exclude_devices = config.parse_exclude_devices(
            cfg.CONF.SRIOV_NIC.exclude_devices)
        self.assertEqual(self.EXCLUDE_DEVICES, exclude_devices)

    def test_exclude_devices_with_spaces(self):
        cfg.CONF.set_override('exclude_devices',
                              self.EXCLUDE_DEVICES_WITH_SPACES_LIST,
                              'SRIOV_NIC')
        exclude_devices = config.parse_exclude_devices(
            cfg.CONF.SRIOV_NIC.exclude_devices)
        self.assertEqual(self.EXCLUDE_DEVICES, exclude_devices)

    def test_exclude_devices_with_error(self):
        cfg.CONF.set_override('exclude_devices',
                              self.EXCLUDE_DEVICES_WITH_SPACES_ERROR,
                              'SRIOV_NIC')
        self.assertRaises(ValueError, config.parse_exclude_devices,
                          cfg.CONF.SRIOV_NIC.exclude_devices)

    def test_validate_config_ok(self):
        cfg.CONF.set_override('physical_device_mappings',
                              self.DEVICE_MAPPING_LIST,
                              'SRIOV_NIC')
        cfg.CONF.set_override('exclude_devices',
                              self.EXCLUDE_DEVICES_LIST,
                              'SRIOV_NIC')
        config_parser = agent.SriovNicAgentConfigParser()
        config_parser.parse()
        device_mappings = config_parser.device_mappings
        exclude_devices = config_parser.exclude_devices
        self.assertEqual(self.EXCLUDE_DEVICES, exclude_devices)
        self.assertEqual(self.DEVICE_MAPPING, device_mappings)

    def test_validate_config_fail(self):
        cfg.CONF.set_override('physical_device_mappings',
                              self.DEVICE_MAPPING_LIST,
                              'SRIOV_NIC')
        cfg.CONF.set_override('exclude_devices',
                              self.EXCLUDE_DEVICES_LIST_INVALID,
                              'SRIOV_NIC')
        config_parser = agent.SriovNicAgentConfigParser()
        self.assertRaises(ValueError, config_parser.parse)
