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
import sys

import mock
from neutron.extensions import portbindings
from neutron.plugins.ml2 import driver_api as api
from neutron.tests.unit.plugins.ml2 import _test_mech_agent as base

m_const_mock = mock.Mock()

with mock.patch.dict(sys.modules,
                    {'networking_mlnx': mock.Mock(),
                     'networking_mlnx.plugins': mock.Mock(),
                     'networking_mlnx.plugins.ml2': mock.Mock(),
                     'networking_mlnx.plugins.ml2.drivers': mock.Mock(),
                     'networking_mlnx.plugins.ml2.drivers.mlnx':
                        m_const_mock}):
    from neutron.plugins.ml2.drivers.mlnx import mech_mlnx


class MlnxMechanismBaseTestCase(base.AgentMechanismBaseTestCase):
    VIF_TYPE = mech_mlnx.VIF_TYPE_IB_HOSTDEV
    CAP_PORT_FILTER = False
    AGENT_TYPE = mech_mlnx.AGENT_TYPE_MLNX
    VNIC_TYPE = portbindings.VNIC_DIRECT

    GOOD_MAPPINGS = {'fake_physical_network': 'fake_bridge'}
    GOOD_CONFIGS = {'interface_mappings': GOOD_MAPPINGS}

    BAD_MAPPINGS = {'wrong_physical_network': 'wrong_bridge'}
    BAD_CONFIGS = {'interface_mappings': BAD_MAPPINGS}

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
        super(MlnxMechanismBaseTestCase, self).setUp()
        self.driver = mech_mlnx.MlnxMechanismDriver()
        self.driver.initialize()


class MlnxMechanismGenericTestCase(MlnxMechanismBaseTestCase,
                                   base.AgentMechanismGenericTestCase):
    pass


class MlnxMechanismLocalTestCase(MlnxMechanismBaseTestCase,
                                 base.AgentMechanismLocalTestCase):
    pass


class MlnxMechanismFlatTestCase(MlnxMechanismBaseTestCase,
                                base.AgentMechanismFlatTestCase):
    pass


class MlnxMechanismVlanTestCase(MlnxMechanismBaseTestCase,
                                base.AgentMechanismVlanTestCase):
    pass


class MlnxMechanismVifDetailsTestCase(MlnxMechanismBaseTestCase):
    def setUp(self):
        super(MlnxMechanismVifDetailsTestCase, self).setUp()

    def test_vif_details_contains_physical_net(self):
        VLAN_SEGMENTS = [{api.ID: 'vlan_segment_id',
                          api.NETWORK_TYPE: 'vlan',
                          api.PHYSICAL_NETWORK: 'fake_physical_network',
                          api.SEGMENTATION_ID: 1234}]

        context = base.FakePortContext(self.AGENT_TYPE,
                                       self.AGENTS,
                                       VLAN_SEGMENTS,
                                       portbindings.VNIC_DIRECT)
        segment = VLAN_SEGMENTS[0]
        agent = self.AGENTS[0]
        self.driver.try_to_bind_segment_for_agent(context, segment, agent)
        set({"physical_network": "fake_physical_network"}).issubset(
            set(context._bound_vif_details.items()))
