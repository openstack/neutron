# Copyright (C) 2013 Midokura PTE LTD
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

import mock
import uuid


def get_bridge_mock(id=None, **kwargs):
    if id is None:
        id = str(uuid.uuid4())

    bridge = mock.Mock()
    bridge.get_id.return_value = id
    bridge.get_tenant_id.return_value = kwargs.get("tenant_id", "test-tenant")
    bridge.get_name.return_value = kwargs.get("name", "net")
    bridge.get_ports.return_value = []
    bridge.get_peer_ports.return_value = []
    bridge.get_admin_state_up.return_value = kwargs.get("admin_state_up", True)
    return bridge


def get_bridge_port_mock(id=None, bridge_id=None, **kwargs):
    if id is None:
        id = str(uuid.uuid4())
    if bridge_id is None:
        bridge_id = str(uuid.uuid4())

    port = mock.Mock()
    port.get_id.return_value = id
    port.get_bridge_id.return_value = bridge_id
    port.get_admin_state_up.return_value = kwargs.get("admin_state_up", True)
    port.get_type.return_value = "Bridge"
    port.create.return_value = port
    return port


def get_chain_mock(id=None, tenant_id='test-tenant', name='chain',
                   rules=None):
    if id is None:
        id = str(uuid.uuid4())

    if rules is None:
        rules = []

    chain = mock.Mock()
    chain.get_id.return_value = id
    chain.get_tenant_id.return_value = tenant_id
    chain.get_name.return_value = name
    chain.get_rules.return_value = rules
    return chain


def get_port_group_mock(id=None, tenant_id='test-tenant', name='pg'):
    if id is None:
        id = str(uuid.uuid4())

    port_group = mock.Mock()
    port_group.get_id.return_value = id
    port_group.get_tenant_id.return_value = tenant_id
    port_group.get_name.return_value = name
    return port_group


def get_router_mock(id=None, **kwargs):
    if id is None:
        id = str(uuid.uuid4())

    router = mock.Mock()
    router.get_id.return_value = id
    router.get_tenant_id.return_value = kwargs.get("tenant_id", "test-tenant")
    router.get_name.return_value = kwargs.get("name", "router")
    router.get_ports.return_value = []
    router.get_peer_ports.return_value = []
    router.get_routes.return_value = []
    router.get_admin_state_up.return_value = kwargs.get("admin_state_up", True)
    return router


def get_rule_mock(id=None, chain_id=None, properties=None):
    if id is None:
        id = str(uuid.uuid4())

    if chain_id is None:
        chain_id = str(uuid.uuid4())

    if properties is None:
        properties = {}

    rule = mock.Mock()
    rule.get_id.return_value = id
    rule.get_chain_id.return_value = chain_id
    rule.get_properties.return_value = properties
    return rule


def get_subnet_mock(bridge_id=None, gateway_ip='10.0.0.1',
                    subnet_prefix='10.0.0.0', subnet_len=int(24)):
    if bridge_id is None:
        bridge_id = str(uuid.uuid4())

    subnet = mock.Mock()
    subnet.get_id.return_value = subnet_prefix + '/' + str(subnet_len)
    subnet.get_bridge_id.return_value = bridge_id
    subnet.get_default_gateway.return_value = gateway_ip
    subnet.get_subnet_prefix.return_value = subnet_prefix
    subnet.get_subnet_length.return_value = subnet_len
    return subnet


class MidonetLibMockConfig():

    def __init__(self, inst):
        self.inst = inst

    def _create_bridge(self, **kwargs):
        return get_bridge_mock(**kwargs)

    def _create_router(self, **kwargs):
        return get_router_mock(**kwargs)

    def _create_subnet(self, bridge, gateway_ip, subnet_prefix, subnet_len):
        return get_subnet_mock(bridge.get_id(), gateway_ip=gateway_ip,
                               subnet_prefix=subnet_prefix,
                               subnet_len=subnet_len)

    def _add_bridge_port(self, bridge, **kwargs):
        return get_bridge_port_mock(bridge_id=bridge.get_id(), **kwargs)

    def _get_bridge(self, id):
        return get_bridge_mock(id=id)

    def _get_port(self, id):
        return get_bridge_port_mock(id=id)

    def _get_router(self, id):
        return get_router_mock(id=id)

    def _update_bridge(self, id, **kwargs):
        return get_bridge_mock(id=id, **kwargs)

    def setup(self):
        # Bridge methods side effects
        self.inst.create_bridge.side_effect = self._create_bridge
        self.inst.get_bridge.side_effect = self._get_bridge
        self.inst.update_bridge.side_effect = self._update_bridge

        # Subnet methods side effects
        self.inst.create_subnet.side_effect = self._create_subnet

        # Port methods side effects
        ex_bp = self.inst.add_bridge_port
        ex_bp.side_effect = self._add_bridge_port
        self.inst.get_port.side_effect = self._get_port

        # Router methods side effects
        self.inst.create_router.side_effect = self._create_router
        self.inst.get_router.side_effect = self._get_router


class MidoClientMockConfig():

    def __init__(self, inst):
        self.inst = inst
        self.chains_in = None
        self.port_groups_in = None
        self.chains_out = None
        self.rules_out = None
        self.port_groups_out = None

    def _get_query_tenant_id(self, query):
        if query is not None and query['tenant_id']:
            tenant_id = query['tenant_id']
        else:
            tenant_id = 'test-tenant'
        return tenant_id

    def _get_bridge(self, id):
        return get_bridge_mock(id=id)

    def _get_chain(self, id, query=None):
        if not self.chains_in:
            return []

        tenant_id = self._get_query_tenant_id(query)
        for chain in self.chains_in:
            chain_id = chain['id']
            if chain_id is id:
                rule_mocks = []
                if 'rules' in chain:
                    for rule in chain['rules']:
                        rule_mocks.append(
                            get_rule_mock(id=rule['id'],
                                          chain_id=id,
                                          properties=rule['properties']))

                return get_chain_mock(id=chain_id, name=chain['name'],
                                      tenant_id=tenant_id, rules=rule_mocks)
        return None

    def _get_chains(self, query=None):
        if not self.chains_in:
            return []

        tenant_id = self._get_query_tenant_id(query)
        self.chains_out = []
        self.rules_out = []
        for chain in self.chains_in:
            chain_id = chain['id']

            rule_mocks = []
            if 'rules' in chain:
                for rule in chain['rules']:
                    rule_mocks.append(
                        get_rule_mock(id=rule['id'],
                                      chain_id=id,
                                      properties=rule['properties']))
                    self.rules_out += rule_mocks

            self.chains_out.append(get_chain_mock(id=chain_id,
                                                  name=chain['name'],
                                                  tenant_id=tenant_id,
                                                  rules=rule_mocks))
        return self.chains_out

    def _get_port_groups(self, query=None):
        if not self.port_groups_in:
            return []

        tenant_id = self._get_query_tenant_id(query)
        self.port_groups_out = []
        for port_group in self.port_groups_in:
            self.port_groups_out.append(get_port_group_mock(
                id=port_group['id'], name=port_group['name'],
                tenant_id=tenant_id))
        return self.port_groups_out

    def _get_router(self, id):
        return get_router_mock(id=id)

    def _add_bridge_port(self, bridge):
        return get_bridge_port_mock(bridge_id=bridge.get_id())

    def setup(self):
        self.inst.get_bridge.side_effect = self._get_bridge
        self.inst.get_chains.side_effect = self._get_chains
        self.inst.get_chain.side_effect = self._get_chain
        self.inst.get_port_groups.side_effect = self._get_port_groups
        self.inst.get_router.side_effect = self._get_router
        self.inst.add_bridge_port.side_effect = self._add_bridge_port
