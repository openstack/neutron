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

from neutron.common import constants
from neutron.extensions import portbindings
from neutron.plugins.ml2.drivers import mech_hyperv
from neutron.tests.unit.ml2 import _test_mech_agent as base


class HypervMechanismBaseTestCase(base.AgentMechanismBaseTestCase):
    VIF_TYPE = portbindings.VIF_TYPE_HYPERV
    CAP_PORT_FILTER = False
    AGENT_TYPE = constants.AGENT_TYPE_HYPERV

    GOOD_MAPPINGS = {'fake_physical_network': 'fake_vswitch'}
    GOOD_CONFIGS = {'vswitch_mappings': GOOD_MAPPINGS}

    BAD_MAPPINGS = {'wrong_physical_network': 'wrong_vswitch'}
    BAD_CONFIGS = {'vswitch_mappings': BAD_MAPPINGS}

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
        super(HypervMechanismBaseTestCase, self).setUp()
        self.driver = mech_hyperv.HypervMechanismDriver()
        self.driver.initialize()


class HypervMechanismGenericTestCase(HypervMechanismBaseTestCase,
                                     base.AgentMechanismGenericTestCase):
    pass


class HypervMechanismLocalTestCase(HypervMechanismBaseTestCase,
                                   base.AgentMechanismLocalTestCase):
    pass


class HypervMechanismFlatTestCase(HypervMechanismBaseTestCase,
                                  base.AgentMechanismFlatTestCase):
    pass


class HypervMechanismVlanTestCase(HypervMechanismBaseTestCase,
                                  base.AgentMechanismVlanTestCase):
    pass
