# Copyright (c) 2013 OpenStack Foundation
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

from neutron_lib.api.definitions import portbindings
from neutron_lib import constants

from neutron.plugins.ml2.drivers.linuxbridge.mech_driver \
    import mech_linuxbridge
from neutron.tests.unit.plugins.ml2 import _test_mech_agent as base


class LinuxbridgeMechanismBaseTestCase(base.AgentMechanismBaseTestCase):
    VIF_TYPE = portbindings.VIF_TYPE_BRIDGE
    CAP_PORT_FILTER = True
    AGENT_TYPE = constants.AGENT_TYPE_LINUXBRIDGE

    GOOD_MAPPINGS = {'fake_physical_network': 'fake_interface'}
    GOOD_TUNNEL_TYPES = ['gre', 'vxlan']
    GOOD_CONFIGS = {'interface_mappings': GOOD_MAPPINGS,
                    'tunnel_types': GOOD_TUNNEL_TYPES}

    BAD_MAPPINGS = {'wrong_physical_network': 'wrong_interface'}
    BAD_TUNNEL_TYPES = ['bad_tunnel_type']
    BAD_CONFIGS = {'interface_mappings': BAD_MAPPINGS,
                   'tunnel_types': BAD_TUNNEL_TYPES}

    AGENTS = [{'alive': True,
               'configurations': GOOD_CONFIGS,
               'host': 'host',
               'agent_type': AGENT_TYPE,
               }]
    AGENTS_DEAD = [{'alive': False,
                    'configurations': GOOD_CONFIGS,
                    'host': 'dead_host',
                    'agent_type': AGENT_TYPE,
                    }]
    AGENTS_BAD = [{'alive': False,
                   'configurations': GOOD_CONFIGS,
                   'host': 'bad_host_1',
                   'agent_type': AGENT_TYPE,
                   },
                  {'alive': True,
                   'configurations': BAD_CONFIGS,
                   'host': 'bad_host_2',
                   'agent_type': AGENT_TYPE,
                   }]

    def setUp(self):
        super(LinuxbridgeMechanismBaseTestCase, self).setUp()
        self.driver = mech_linuxbridge.LinuxbridgeMechanismDriver()
        self.driver.initialize()


class LinuxbridgeMechanismGenericTestCase(LinuxbridgeMechanismBaseTestCase,
                                          base.AgentMechanismGenericTestCase):
    pass


class LinuxbridgeMechanismLocalTestCase(LinuxbridgeMechanismBaseTestCase,
                                        base.AgentMechanismLocalTestCase):
    pass


class LinuxbridgeMechanismFlatTestCase(LinuxbridgeMechanismBaseTestCase,
                                       base.AgentMechanismFlatTestCase):
    pass


class LinuxbridgeMechanismVlanTestCase(LinuxbridgeMechanismBaseTestCase,
                                       base.AgentMechanismVlanTestCase):
    pass


class LinuxbridgeMechanismGreTestCase(LinuxbridgeMechanismBaseTestCase,
                                      base.AgentMechanismGreTestCase):
    pass
