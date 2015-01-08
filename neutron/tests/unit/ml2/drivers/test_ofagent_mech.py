# Copyright (c) 2014 OpenStack Foundation
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
from neutron.plugins.ml2.drivers import mech_ofagent
from neutron.tests.unit.ml2 import _test_mech_agent as base


class OfagentMechanismBaseTestCase(base.AgentMechanismBaseTestCase):
    VIF_TYPE = portbindings.VIF_TYPE_OVS
    VIF_DETAILS = {portbindings.CAP_PORT_FILTER: True,
                   portbindings.OVS_HYBRID_PLUG: True}
    AGENT_TYPE = constants.AGENT_TYPE_OFA

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
        super(OfagentMechanismBaseTestCase, self).setUp()
        self.driver = mech_ofagent.OfagentMechanismDriver()
        self.driver.initialize()


class OfagentMechanismSGDisabledBaseTestCase(OfagentMechanismBaseTestCase):
    VIF_DETAILS = {portbindings.CAP_PORT_FILTER: False,
                   portbindings.OVS_HYBRID_PLUG: False}

    def setUp(self):
        cfg.CONF.set_override('enable_security_group',
                              False,
                              group='SECURITYGROUP')
        super(OfagentMechanismSGDisabledBaseTestCase, self).setUp()


class OfagentMechanismGenericTestCase(OfagentMechanismBaseTestCase,
                                      base.AgentMechanismGenericTestCase):
    pass


class OfagentMechanismLocalTestCase(OfagentMechanismBaseTestCase,
                                    base.AgentMechanismLocalTestCase):
    pass


class OfagentMechanismFlatTestCase(OfagentMechanismBaseTestCase,
                                   base.AgentMechanismFlatTestCase):
    pass


class OfagentMechanismVlanTestCase(OfagentMechanismBaseTestCase,
                                   base.AgentMechanismVlanTestCase):
    pass


class OfagentMechanismGreTestCase(OfagentMechanismBaseTestCase,
                                  base.AgentMechanismGreTestCase):
    pass


class OfagentMechanismSGDisabledLocalTestCase(
    OfagentMechanismSGDisabledBaseTestCase,
    base.AgentMechanismLocalTestCase):
    pass
