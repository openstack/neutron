# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (C) 2012 Midokura Japan K.K.
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
#
# @author: Ryu Ishimoto, Midokura Japan KK
# @author: Tomoe Sugihara, Midokura Japan KK

import uuid

import mock

from quantum.plugins.midonet import midonet_lib
from quantum.tests import base


class MidonetLibTestCase(base.BaseTestCase):

    def setUp(self):
        super(MidonetLibTestCase, self).setUp()
        self.mock_api = mock.Mock()

    def _create_mock_chains(self, sg_id, sg_name):
        mock_in_chain = mock.Mock()
        mock_in_chain.get_name.return_value = "OS_SG_%s_%s_IN" % (sg_id,
                                                                  sg_name)
        mock_out_chain = mock.Mock()
        mock_out_chain.get_name.return_value = "OS_SG_%s_%s_OUT" % (sg_id,
                                                                    sg_name)
        return (mock_in_chain, mock_out_chain)

    def _create_mock_router_chains(self, router_id):
        mock_in_chain = mock.Mock()
        mock_in_chain.get_name.return_value = "OS_ROUTER_IN_%s" % (router_id)

        mock_out_chain = mock.Mock()
        mock_out_chain.get_name.return_value = "OS_ROUTER_OUT_%s" % (router_id)
        return (mock_in_chain, mock_out_chain)

    def _create_mock_port_group(self, sg_id, sg_name):
        mock_pg = mock.Mock()
        mock_pg.get_name.return_value = "OS_SG_%s_%s" % (sg_id, sg_name)
        return mock_pg

    def _create_mock_rule(self, rule_id):
        mock_rule = mock.Mock()
        mock_rule.get_properties.return_value = {"os_sg_rule_id": rule_id}
        return mock_rule


class MidonetChainManagerTestCase(MidonetLibTestCase):

    def setUp(self):
        super(MidonetChainManagerTestCase, self).setUp()
        self.mgr = midonet_lib.ChainManager(self.mock_api)

    def test_create_for_sg(self):
        tenant_id = 'test_tenant'
        sg_id = str(uuid.uuid4())
        sg_name = 'test_sg_name'
        calls = [mock.call.add_chain().tenant_id(tenant_id)]

        self.mgr.create_for_sg(tenant_id, sg_id, sg_name)

        self.mock_api.assert_has_calls(calls)

    def test_delete_for_sg(self):
        tenant_id = 'test_tenant'
        sg_id = str(uuid.uuid4())
        sg_name = 'test_sg_name'
        in_chain, out_chain = self._create_mock_chains(sg_id, sg_name)

        # Mock get_chains returned values
        self.mock_api.get_chains.return_value = [in_chain, out_chain]

        self.mgr.delete_for_sg(tenant_id, sg_id, sg_name)

        self.mock_api.assert_has_calls(mock.call.get_chains(
            {"tenant_id": tenant_id}))
        in_chain.delete.assert_called_once_with()
        out_chain.delete.assert_called_once_with()

    def test_get_router_chains(self):
        tenant_id = 'test_tenant'
        router_id = str(uuid.uuid4())
        in_chain, out_chain = self._create_mock_router_chains(router_id)

        # Mock get_chains returned values
        self.mock_api.get_chains.return_value = [in_chain, out_chain]

        chains = self.mgr.get_router_chains(tenant_id, router_id)

        self.mock_api.assert_has_calls(mock.call.get_chains(
            {"tenant_id": tenant_id}))
        self.assertEqual(len(chains), 2)
        self.assertEqual(chains['in'], in_chain)
        self.assertEqual(chains['out'], out_chain)

    def test_create_router_chains(self):
        tenant_id = 'test_tenant'
        router_id = str(uuid.uuid4())
        calls = [mock.call.add_chain().tenant_id(tenant_id)]

        self.mgr.create_router_chains(tenant_id, router_id)

        self.mock_api.assert_has_calls(calls)

    def test_get_sg_chains(self):
        tenant_id = 'test_tenant'
        sg_id = str(uuid.uuid4())
        in_chain, out_chain = self._create_mock_chains(sg_id, 'foo')

        # Mock get_chains returned values
        self.mock_api.get_chains.return_value = [in_chain, out_chain]

        chains = self.mgr.get_sg_chains(tenant_id, sg_id)

        self.mock_api.assert_has_calls(mock.call.get_chains(
            {"tenant_id": tenant_id}))
        self.assertEqual(len(chains), 2)
        self.assertEqual(chains['in'], in_chain)
        self.assertEqual(chains['out'], out_chain)


class MidonetPortGroupManagerTestCase(MidonetLibTestCase):

    def setUp(self):
        super(MidonetPortGroupManagerTestCase, self).setUp()
        self.mgr = midonet_lib.PortGroupManager(self.mock_api)

    def test_create(self):
        tenant_id = 'test_tenant'
        sg_id = str(uuid.uuid4())
        sg_name = 'test_sg'
        pg_mock = self._create_mock_port_group(sg_id, sg_name)
        rv = self.mock_api.add_port_group.return_value.tenant_id.return_value
        rv.name.return_value = pg_mock

        self.mgr.create(tenant_id, sg_id, sg_name)

        pg_mock.create.assert_called_once_with()

    def test_delete(self):
        tenant_id = 'test_tenant'
        sg_id = str(uuid.uuid4())
        sg_name = 'test_sg'
        pg_mock1 = self._create_mock_port_group(sg_id, sg_name)
        pg_mock2 = self._create_mock_port_group(sg_id, sg_name)
        self.mock_api.get_port_groups.return_value = [pg_mock1, pg_mock2]

        self.mgr.delete(tenant_id, sg_id, sg_name)

        self.mock_api.assert_has_calls(mock.call.get_port_groups(
            {"tenant_id": tenant_id}))
        pg_mock1.delete.assert_called_once_with()
        pg_mock2.delete.assert_called_once_with()

    def test_get_for_sg(self):
        tenant_id = 'test_tenant'
        sg_id = str(uuid.uuid4())
        pg_mock = self._create_mock_port_group(sg_id, 'foo')
        self.mock_api.get_port_groups.return_value = [pg_mock]

        pg = self.mgr.get_for_sg(tenant_id, sg_id)

        self.assertEqual(pg, pg_mock)


class MidonetRuleManagerTestCase(MidonetLibTestCase):

    def setUp(self):
        super(MidonetRuleManagerTestCase, self).setUp()
        self.mgr = midonet_lib.RuleManager(self.mock_api)
        self.mgr.chain_manager = mock.Mock()
        self.mgr.pg_manager = mock.Mock()

    def _create_test_rule(self, tenant_id, sg_id, rule_id, direction="egress",
                          protocol="tcp", port_min=1, port_max=65535,
                          src_ip='192.168.1.0/24', src_group_id=None,
                          ethertype=0x0800):
        return {"tenant_id": tenant_id, "security_group_id": sg_id,
                "rule_id": rule_id, "direction": direction,
                "protocol": protocol,
                "source_ip_prefix": src_ip, "source_group_id": src_group_id,
                "port_range_min": port_min, "port_range_max": port_max,
                "ethertype": ethertype, "id": rule_id, "external_id": None}

    def test_create_for_sg_rule(self):
        tenant_id = 'test_tenant'
        sg_id = str(uuid.uuid4())
        rule_id = str(uuid.uuid4())
        in_chain, out_chain = self._create_mock_chains(sg_id, 'foo')
        self.mgr.chain_manager.get_sg_chains.return_value = {"in": in_chain,
                                                             "out": out_chain}
        props = {"os_sg_rule_id": rule_id}
        rule = self._create_test_rule(tenant_id, sg_id, rule_id)
        calls = [mock.call.add_rule().port_group(None).type(
            'accept').nw_proto(6).nw_src_address(
                '192.168.1.0').nw_src_length(24).tp_src_start(
                    None).tp_src_end(None).tp_dst_start(1).tp_dst_end(
                        65535).properties(props).create()]

        self.mgr.create_for_sg_rule(rule)

        in_chain.assert_has_calls(calls)

    def test_delete_for_sg_rule(self):
        tenant_id = 'test_tenant'
        sg_id = str(uuid.uuid4())
        rule_id = str(uuid.uuid4())
        in_chain, out_chain = self._create_mock_chains(sg_id, 'foo')
        self.mgr.chain_manager.get_sg_chains.return_value = {"in": in_chain,
                                                             "out": out_chain}

        # Mock the rules returned for each chain
        mock_rule_in = self._create_mock_rule(rule_id)
        mock_rule_out = self._create_mock_rule(rule_id)
        in_chain.get_rules.return_value = [mock_rule_in]
        out_chain.get_rules.return_value = [mock_rule_out]

        rule = self._create_test_rule(tenant_id, sg_id, rule_id)
        self.mgr.delete_for_sg_rule(rule)

        mock_rule_in.delete.assert_called_once_with()
        mock_rule_out.delete.assert_called_once_with()
