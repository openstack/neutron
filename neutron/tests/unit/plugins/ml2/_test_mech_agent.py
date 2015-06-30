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


from neutron.extensions import portbindings
from neutron.plugins.ml2 import driver_api as api
from neutron.tests import base

NETWORK_ID = "fake_network"
PORT_ID = "fake_port"


class FakeNetworkContext(api.NetworkContext):
    def __init__(self, segments):
        self._network_segments = segments

    @property
    def current(self):
        return {'id': NETWORK_ID}

    @property
    def original(self):
        return None

    @property
    def network_segments(self):
        return self._network_segments


class FakePortContext(api.PortContext):
    def __init__(self, agent_type, agents, segments,
                 vnic_type=portbindings.VNIC_NORMAL):
        self._agent_type = agent_type
        self._agents = agents
        self._network_context = FakeNetworkContext(segments)
        self._bound_vnic_type = vnic_type
        self._bound_segment_id = None
        self._bound_vif_type = None
        self._bound_vif_details = None

    @property
    def current(self):
        return {'id': PORT_ID,
                'binding:vnic_type': self._bound_vnic_type}

    @property
    def original(self):
        return None

    @property
    def status(self):
        return 'DOWN'

    @property
    def original_status(self):
        return None

    @property
    def network(self):
        return self._network_context

    @property
    def binding_levels(self):
        if self._bound_segment:
            return [{
                api.BOUND_DRIVER: 'fake_driver',
                api.BOUND_SEGMENT: self._expand_segment(self._bound_segment)
            }]

    @property
    def original_binding_levels(self):
        return None

    @property
    def top_bound_segment(self):
        return self._expand_segment(self._bound_segment)

    @property
    def original_top_bound_segment(self):
        return None

    @property
    def bottom_bound_segment(self):
        return self._expand_segment(self._bound_segment)

    @property
    def original_bottom_bound_segment(self):
        return None

    def _expand_segment(self, segment_id):
        for segment in self._network_context.network_segments:
            if segment[api.ID] == self._bound_segment_id:
                return segment

    @property
    def host(self):
        return ''

    @property
    def original_host(self):
        return None

    @property
    def vif_type(self):
        return portbindings.UNBOUND

    @property
    def original_vif_type(self):
        return portbindings.UNBOUND

    @property
    def vif_details(self):
        return None

    @property
    def original_vif_details(self):
        return None

    @property
    def segments_to_bind(self):
        return self._network_context.network_segments

    def host_agents(self, agent_type):
        if agent_type == self._agent_type:
            return self._agents
        else:
            return []

    def set_binding(self, segment_id, vif_type, vif_details):
        self._bound_segment_id = segment_id
        self._bound_vif_type = vif_type
        self._bound_vif_details = vif_details

    def continue_binding(self, segment_id, next_segments_to_bind):
        pass

    def allocate_dynamic_segment(self, segment):
        pass

    def release_dynamic_segment(self, segment_id):
        pass


class AgentMechanismBaseTestCase(base.BaseTestCase):
    # The following must be overridden for the specific mechanism
    # driver being tested:
    VIF_TYPE = None
    VIF_DETAILS = None
    AGENT_TYPE = None
    AGENTS = None
    AGENTS_DEAD = None
    AGENTS_BAD = None
    VNIC_TYPE = portbindings.VNIC_NORMAL

    def _check_unbound(self, context):
        self.assertIsNone(context._bound_segment_id)
        self.assertIsNone(context._bound_vif_type)
        self.assertIsNone(context._bound_vif_details)

    def _check_bound(self, context, segment):
        self.assertEqual(context._bound_segment_id, segment[api.ID])
        self.assertEqual(context._bound_vif_type, self.VIF_TYPE)
        vif_details = context._bound_vif_details
        self.assertIsNotNone(vif_details)
        # NOTE(r-mibu): The following five lines are just for backward
        # compatibility.  In this class, HAS_PORT_FILTER has been replaced
        # by VIF_DETAILS which can be set expected vif_details to check,
        # but all replacement of HAS_PORT_FILTER in successor has not been
        # completed.
        if self.VIF_DETAILS is None:
            expected = getattr(self, 'CAP_PORT_FILTER', None)
            port_filter = vif_details[portbindings.CAP_PORT_FILTER]
            self.assertEqual(expected, port_filter)
            return
        self.assertEqual(self.VIF_DETAILS, vif_details)


class AgentMechanismGenericTestCase(AgentMechanismBaseTestCase):
    UNKNOWN_TYPE_SEGMENTS = [{api.ID: 'unknown_segment_id',
                              api.NETWORK_TYPE: 'no_such_type'}]

    def test_unknown_type(self):
        context = FakePortContext(self.AGENT_TYPE,
                                  self.AGENTS,
                                  self.UNKNOWN_TYPE_SEGMENTS,
                                  vnic_type=self.VNIC_TYPE)
        self.driver.bind_port(context)
        self._check_unbound(context)


class AgentMechanismLocalTestCase(AgentMechanismBaseTestCase):
    LOCAL_SEGMENTS = [{api.ID: 'unknown_segment_id',
                       api.NETWORK_TYPE: 'no_such_type'},
                      {api.ID: 'local_segment_id',
                       api.NETWORK_TYPE: 'local'}]

    def test_type_local(self):
        context = FakePortContext(self.AGENT_TYPE,
                                  self.AGENTS,
                                  self.LOCAL_SEGMENTS,
                                  vnic_type=self.VNIC_TYPE)
        self.driver.bind_port(context)
        self._check_bound(context, self.LOCAL_SEGMENTS[1])

    def test_type_local_dead(self):
        context = FakePortContext(self.AGENT_TYPE,
                                  self.AGENTS_DEAD,
                                  self.LOCAL_SEGMENTS,
                                  vnic_type=self.VNIC_TYPE)
        self.driver.bind_port(context)
        self._check_unbound(context)


class AgentMechanismFlatTestCase(AgentMechanismBaseTestCase):
    FLAT_SEGMENTS = [{api.ID: 'unknown_segment_id',
                      api.NETWORK_TYPE: 'no_such_type'},
                     {api.ID: 'flat_segment_id',
                      api.NETWORK_TYPE: 'flat',
                      api.PHYSICAL_NETWORK: 'fake_physical_network'}]

    def test_type_flat(self):
        context = FakePortContext(self.AGENT_TYPE,
                                  self.AGENTS,
                                  self.FLAT_SEGMENTS,
                                  vnic_type=self.VNIC_TYPE)
        self.driver.bind_port(context)
        self._check_bound(context, self.FLAT_SEGMENTS[1])

    def test_type_flat_bad(self):
        context = FakePortContext(self.AGENT_TYPE,
                                  self.AGENTS_BAD,
                                  self.FLAT_SEGMENTS,
                                  vnic_type=self.VNIC_TYPE)
        self.driver.bind_port(context)
        self._check_unbound(context)


class AgentMechanismVlanTestCase(AgentMechanismBaseTestCase):
    VLAN_SEGMENTS = [{api.ID: 'unknown_segment_id',
                      api.NETWORK_TYPE: 'no_such_type'},
                     {api.ID: 'vlan_segment_id',
                      api.NETWORK_TYPE: 'vlan',
                      api.PHYSICAL_NETWORK: 'fake_physical_network',
                      api.SEGMENTATION_ID: 1234}]

    def test_type_vlan(self):
        context = FakePortContext(self.AGENT_TYPE,
                                  self.AGENTS,
                                  self.VLAN_SEGMENTS,
                                  vnic_type=self.VNIC_TYPE)
        self.driver.bind_port(context)
        self._check_bound(context, self.VLAN_SEGMENTS[1])

    def test_type_vlan_bad(self):
        context = FakePortContext(self.AGENT_TYPE,
                                  self.AGENTS_BAD,
                                  self.VLAN_SEGMENTS,
                                  vnic_type=self.VNIC_TYPE)
        self.driver.bind_port(context)
        self._check_unbound(context)


class AgentMechanismGreTestCase(AgentMechanismBaseTestCase):
    GRE_SEGMENTS = [{api.ID: 'unknown_segment_id',
                     api.NETWORK_TYPE: 'no_such_type'},
                    {api.ID: 'gre_segment_id',
                     api.NETWORK_TYPE: 'gre',
                     api.SEGMENTATION_ID: 1234}]

    def test_type_gre(self):
        context = FakePortContext(self.AGENT_TYPE,
                                  self.AGENTS,
                                  self.GRE_SEGMENTS)
        self.driver.bind_port(context)
        self._check_bound(context, self.GRE_SEGMENTS[1])

    def test_type_gre_bad(self):
        context = FakePortContext(self.AGENT_TYPE,
                                  self.AGENTS_BAD,
                                  self.GRE_SEGMENTS)
        self.driver.bind_port(context)
        self._check_unbound(context)
