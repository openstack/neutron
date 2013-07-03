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


import mock
import testtools
import webob.exc as w_exc

from neutron.openstack.common import uuidutils
from neutron.plugins.midonet import midonet_lib
import neutron.tests.unit.midonet.mock_lib as mock_lib


def _create_test_chain(id, name, tenant_id):
    return {'id': id, 'name': name, 'tenant_id': tenant_id}


def _create_test_port_group(sg_id, sg_name, id, tenant_id):
    return {"id": id, "name": "OS_SG_%s_%s" % (sg_id, sg_name),
            "tenant_id": tenant_id}


def _create_test_router_in_chain(router_id, id, tenant_id):
    name = "OS_ROUTER_IN_%s" % router_id
    return _create_test_chain(id, name, tenant_id)


def _create_test_router_out_chain(router_id, id, tenant_id):
    name = "OS_ROUTER_OUT_%s" % router_id
    return _create_test_chain(id, name, tenant_id)


def _create_test_rule(id, chain_id, properties):
    return {"id": id, "chain_id": chain_id, "properties": properties}


def _create_test_sg_in_chain(sg_id, sg_name, id, tenant_id):
    if sg_name:
        name = "OS_SG_%s_%s_IN" % (sg_id, sg_name)
    else:
        name = "OS_SG_%s_IN" % sg_id
    return _create_test_chain(id, name, tenant_id)


def _create_test_sg_out_chain(sg_id, sg_name, id, tenant_id):
    if sg_name:
        name = "OS_SG_%s_%s_OUT" % (sg_id, sg_name)
    else:
        name = "OS_SG_%s_OUT" % sg_id
    return _create_test_chain(id, name, tenant_id)


def _create_test_sg_rule(tenant_id, sg_id, id,
                         direction="egress", protocol="tcp", port_min=1,
                         port_max=65535, src_ip='192.168.1.0/24',
                         src_group_id=None, ethertype=0x0800, properties=None):
    return {"tenant_id": tenant_id, "security_group_id": sg_id,
            "id": id, "direction": direction, "protocol": protocol,
            "remote_ip_prefix": src_ip, "remote_group_id": src_group_id,
            "port_range_min": port_min, "port_range_max": port_max,
            "ethertype": ethertype, "external_id": None}


def _create_test_sg_chain_rule(id, chain_id, sg_rule_id):
    props = {"os_sg_rule_id": sg_rule_id}
    return _create_test_rule(id, chain_id, props)


class MidoClientTestCase(testtools.TestCase):

    def setUp(self):
        super(MidoClientTestCase, self).setUp()
        self._tenant_id = 'test-tenant'
        self.mock_api = mock.Mock()
        self.mock_api_cfg = mock_lib.MidoClientMockConfig(self.mock_api)
        self.mock_api_cfg.setup()
        self.client = midonet_lib.MidoClient(self.mock_api)

    def test_create_for_sg(self):
        sg_id = uuidutils.generate_uuid()
        sg_name = 'test-sg'
        calls = [mock.call.add_chain().tenant_id(self._tenant_id),
                 mock.call.add_port_group().tenant_id(self._tenant_id)]

        self.client.create_for_sg(self._tenant_id, sg_id, sg_name)

        self.mock_api.assert_has_calls(calls, any_order=True)

    def test_create_for_sg_rule(self):
        sg_id = uuidutils.generate_uuid()
        sg_name = 'test-sg'
        in_chain_id = uuidutils.generate_uuid()
        out_chain_id = uuidutils.generate_uuid()
        self.mock_api_cfg.chains_in = [
            _create_test_sg_in_chain(sg_id, sg_name, in_chain_id,
                                     self._tenant_id),
            _create_test_sg_out_chain(sg_id, sg_name, out_chain_id,
                                      self._tenant_id)]

        sg_rule_id = uuidutils.generate_uuid()
        sg_rule = _create_test_sg_rule(self._tenant_id, sg_id, sg_rule_id)

        props = {"os_sg_rule_id": sg_rule_id}
        calls = [mock.call.add_rule().port_group(None).type(
            'accept').nw_proto(6).nw_src_address(
                '192.168.1.0').nw_src_length(24).tp_src_start(
                    None).tp_src_end(None).tp_dst_start(1).tp_dst_end(
                        65535).properties(props).create()]

        self.client.create_for_sg_rule(sg_rule)

        # Egress chain rule added
        self.mock_api_cfg.chains_out[0].assert_has_calls(calls)

    def test_create_router_chains(self):
        router = mock_lib.get_router_mock(tenant_id=self._tenant_id)
        api_calls = [mock.call.add_chain().tenant_id(self._tenant_id)]
        router_calls = [
            mock.call.inbound_filter_id().outbound_filter_id().update()]

        self.client.create_router_chains(router)

        self.mock_api.assert_has_calls(api_calls)
        router.assert_has_calls(router_calls)

    def test_delete_for_sg(self):
        sg_id = uuidutils.generate_uuid()
        sg_name = 'test-sg'
        in_chain_id = uuidutils.generate_uuid()
        out_chain_id = uuidutils.generate_uuid()
        pg_id = uuidutils.generate_uuid()
        self.mock_api_cfg.chains_in = [
            _create_test_sg_in_chain(sg_id, sg_name, in_chain_id,
                                     self._tenant_id),
            _create_test_sg_out_chain(sg_id, sg_name, out_chain_id,
                                      self._tenant_id)]
        self.mock_api_cfg.port_groups_in = [
            _create_test_port_group(sg_id, sg_name, pg_id, self._tenant_id)]

        calls = [mock.call.get_chains({"tenant_id": self._tenant_id}),
                 mock.call.delete_chain(in_chain_id),
                 mock.call.delete_chain(out_chain_id),
                 mock.call.get_port_groups({"tenant_id": self._tenant_id}),
                 mock.call.delete_port_group(pg_id)]

        self.client.delete_for_sg(self._tenant_id, sg_id, sg_name)

        self.mock_api.assert_has_calls(calls)

    def test_delete_for_sg_rule(self):
        sg_id = uuidutils.generate_uuid()
        sg_name = 'test-sg'
        in_chain_id = uuidutils.generate_uuid()
        out_chain_id = uuidutils.generate_uuid()
        self.mock_api_cfg.chains_in = [
            _create_test_sg_in_chain(sg_id, sg_name, in_chain_id,
                                     self._tenant_id),
            _create_test_sg_out_chain(sg_id, sg_name, out_chain_id,
                                      self._tenant_id)]

        rule_id = uuidutils.generate_uuid()
        sg_rule_id = uuidutils.generate_uuid()
        rule = _create_test_sg_chain_rule(rule_id, in_chain_id, sg_rule_id)
        self.mock_api_cfg.chains_in[0]['rules'] = [rule]
        sg_rule = _create_test_sg_rule(self._tenant_id, sg_id, sg_rule_id)

        self.client.delete_for_sg_rule(sg_rule)

        self.mock_api.delete_rule.assert_called_once_with(rule_id)

    def test_get_bridge(self):
        bridge_id = uuidutils.generate_uuid()

        bridge = self.client.get_bridge(bridge_id)

        self.assertIsNotNone(bridge)
        self.assertEqual(bridge.get_id(), bridge_id)

    def test_get_bridge_error(self):
        self.mock_api.get_bridge.side_effect = w_exc.HTTPInternalServerError()
        self.assertRaises(midonet_lib.MidonetApiException,
                          self.client.get_bridge, uuidutils.generate_uuid())

    def test_get_bridge_not_found(self):
        self.mock_api.get_bridge.side_effect = w_exc.HTTPNotFound()
        self.assertRaises(midonet_lib.MidonetResourceNotFound,
                          self.client.get_bridge, uuidutils.generate_uuid())

    def test_get_port_groups_for_sg(self):
        sg_id = uuidutils.generate_uuid()
        pg_id = uuidutils.generate_uuid()
        self.mock_api_cfg.port_groups_in = [
            _create_test_port_group(sg_id, 'test-sg', pg_id, self._tenant_id)]

        pg = self.client.get_port_groups_for_sg(self._tenant_id, sg_id)

        self.assertIsNotNone(pg)
        self.assertEqual(pg.get_id(), pg_id)

    def _create_test_rule(self, tenant_id, sg_id, rule_id, direction="egress",
                          protocol="tcp", port_min=1, port_max=65535,
                          src_ip='192.168.1.0/24', src_group_id=None,
                          ethertype=0x0800):
        return {"tenant_id": tenant_id, "security_group_id": sg_id,
                "rule_id": rule_id, "direction": direction,
                "protocol": protocol,
                "remote_ip_prefix": src_ip, "remote_group_id": src_group_id,
                "port_range_min": port_min, "port_range_max": port_max,
                "ethertype": ethertype, "id": rule_id, "external_id": None}

    def test_get_router_error(self):
        self.mock_api.get_router.side_effect = w_exc.HTTPInternalServerError()
        self.assertRaises(midonet_lib.MidonetApiException,
                          self.client.get_router, uuidutils.generate_uuid())

    def test_get_router_not_found(self):
        self.mock_api.get_router.side_effect = w_exc.HTTPNotFound()
        self.assertRaises(midonet_lib.MidonetResourceNotFound,
                          self.client.get_router, uuidutils.generate_uuid())

    def test_get_router_chains(self):
        router_id = uuidutils.generate_uuid()
        in_chain_id = uuidutils.generate_uuid()
        out_chain_id = uuidutils.generate_uuid()
        self.mock_api_cfg.chains_in = [
            _create_test_router_in_chain(router_id, in_chain_id,
                                         self._tenant_id),
            _create_test_router_out_chain(router_id, out_chain_id,
                                          self._tenant_id)]

        chains = self.client.get_router_chains(self._tenant_id, router_id)

        self.mock_api.assert_has_calls(mock.call.get_chains(
            {"tenant_id": self._tenant_id}))
        self.assertEqual(len(chains), 2)
        self.assertIn('in', chains)
        self.assertIn('out', chains)
        self.assertEqual(chains['in'].get_id(), in_chain_id)
        self.assertEqual(chains['out'].get_id(), out_chain_id)

    def test_get_sg_chains(self):
        sg_id = uuidutils.generate_uuid()
        sg_name = 'test-sg'
        in_chain_id = uuidutils.generate_uuid()
        out_chain_id = uuidutils.generate_uuid()
        self.mock_api_cfg.chains_in = [
            _create_test_sg_in_chain(sg_id, sg_name, in_chain_id,
                                     self._tenant_id),
            _create_test_sg_out_chain(sg_id, sg_name, out_chain_id,
                                      self._tenant_id)]

        chains = self.client.get_sg_chains(self._tenant_id, sg_id)

        self.mock_api.assert_has_calls(mock.call.get_chains(
            {"tenant_id": self._tenant_id}))
        self.assertEqual(len(chains), 2)
        self.assertIn('in', chains)
        self.assertIn('out', chains)
        self.assertEqual(chains['in'].get_id(), in_chain_id)
        self.assertEqual(chains['out'].get_id(), out_chain_id)
