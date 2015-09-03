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

from oslo_config import cfg

from neutron.common import constants
from neutron.extensions import portbindings
from neutron.plugins.ml2.drivers.openvswitch.mech_driver \
    import mech_openvswitch
from neutron.tests.unit.plugins.ml2 import _test_mech_agent as base


class OpenvswitchMechanismBaseTestCase(base.AgentMechanismBaseTestCase):
    VIF_TYPE = portbindings.VIF_TYPE_OVS
    VIF_DETAILS = {portbindings.CAP_PORT_FILTER: True,
                   portbindings.OVS_HYBRID_PLUG: True}
    AGENT_TYPE = constants.AGENT_TYPE_OVS

    GOOD_MAPPINGS = {'fake_physical_network': 'fake_bridge'}
    GOOD_TUNNEL_TYPES = ['gre', 'vxlan']
    GOOD_CONFIGS = {'bridge_mappings': GOOD_MAPPINGS,
                    'tunnel_types': GOOD_TUNNEL_TYPES}

    BAD_MAPPINGS = {'wrong_physical_network': 'wrong_bridge'}
    BAD_TUNNEL_TYPES = ['bad_tunnel_type']
    BAD_CONFIGS = {'bridge_mappings': BAD_MAPPINGS,
                   'tunnel_types': BAD_TUNNEL_TYPES}

    AGENTS = [{'alive': True,
               'configurations': GOOD_CONFIGS,
               'host': 'host'}]
    AGENTS_DEAD = [{'alive': False,
                    'configurations': GOOD_CONFIGS,
                    'host': 'dead_host'}]
    AGENTS_BAD = [{'alive': False,
                   'configurations': GOOD_CONFIGS,
                   'host': 'bad_host_1'},
                  {'alive': True,
                   'configurations': BAD_CONFIGS,
                   'host': 'bad_host_2'}]

    def setUp(self):
        super(OpenvswitchMechanismBaseTestCase, self).setUp()
        self.driver = mech_openvswitch.OpenvswitchMechanismDriver()
        self.driver.initialize()


class OpenvswitchMechanismSGDisabledBaseTestCase(
    OpenvswitchMechanismBaseTestCase):
    VIF_DETAILS = {portbindings.CAP_PORT_FILTER: False,
                   portbindings.OVS_HYBRID_PLUG: False}

    def setUp(self):
        cfg.CONF.set_override('enable_security_group',
                              False,
                              group='SECURITYGROUP')
        super(OpenvswitchMechanismSGDisabledBaseTestCase, self).setUp()


class OpenvswitchMechanismGenericTestCase(OpenvswitchMechanismBaseTestCase,
                                          base.AgentMechanismGenericTestCase):
    pass


class OpenvswitchMechanismLocalTestCase(OpenvswitchMechanismBaseTestCase,
                                        base.AgentMechanismLocalTestCase):
    pass


class OpenvswitchMechanismFlatTestCase(OpenvswitchMechanismBaseTestCase,
                                       base.AgentMechanismFlatTestCase):
    pass


class OpenvswitchMechanismVlanTestCase(OpenvswitchMechanismBaseTestCase,
                                       base.AgentMechanismVlanTestCase):
    pass


class OpenvswitchMechanismGreTestCase(OpenvswitchMechanismBaseTestCase,
                                      base.AgentMechanismGreTestCase):
    pass


class OpenvswitchMechanismSGDisabledLocalTestCase(
    OpenvswitchMechanismSGDisabledBaseTestCase,
    base.AgentMechanismLocalTestCase):
    pass
