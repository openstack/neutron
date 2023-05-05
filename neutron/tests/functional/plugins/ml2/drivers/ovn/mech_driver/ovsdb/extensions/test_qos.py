# Copyright 2020 Red Hat, Inc.
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

import copy
from unittest import mock

from neutron_lib.api.definitions import external_net
from neutron_lib.api.definitions import provider_net as pnet
from neutron_lib import constants
from neutron_lib.services.qos import constants as qos_constants
from ovsdbapp.backend.ovs_idl import idlutils

from neutron.common.ovn import constants as ovn_const
from neutron.common.ovn import utils as ovn_utils
from neutron.common import utils
from neutron.db import l3_db
from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb.extensions \
    import qos as qos_extension
from neutron.tests.functional import base


QOS_RULE_BW_1 = {'max_kbps': 200, 'max_burst_kbps': 100}
QOS_RULE_BW_2 = {'max_kbps': 300}
QOS_RULE_DSCP_1 = {'dscp_mark': 16}
QOS_RULE_DSCP_2 = {'dscp_mark': 20}
QOS_RULE_MINBW_1 = {'min_kbps': 500}

QOS_RULES_0 = {
    constants.EGRESS_DIRECTION: {
        qos_constants.RULE_TYPE_BANDWIDTH_LIMIT: QOS_RULE_BW_1,
        qos_constants.RULE_TYPE_DSCP_MARKING: QOS_RULE_DSCP_1,
        qos_constants.RULE_TYPE_MINIMUM_BANDWIDTH: QOS_RULE_MINBW_1},
    constants.INGRESS_DIRECTION: {
        qos_constants.RULE_TYPE_BANDWIDTH_LIMIT: QOS_RULE_BW_2}
}

QOS_RULES_1 = {
    constants.EGRESS_DIRECTION: {
        qos_constants.RULE_TYPE_BANDWIDTH_LIMIT: QOS_RULE_BW_1,
        qos_constants.RULE_TYPE_DSCP_MARKING: QOS_RULE_DSCP_1},
    constants.INGRESS_DIRECTION: {
        qos_constants.RULE_TYPE_BANDWIDTH_LIMIT: QOS_RULE_BW_2}
}

QOS_RULES_2 = {
    constants.EGRESS_DIRECTION: {
        qos_constants.RULE_TYPE_BANDWIDTH_LIMIT: QOS_RULE_BW_2,
        qos_constants.RULE_TYPE_DSCP_MARKING: QOS_RULE_DSCP_2}
}

QOS_RULES_3 = {
    constants.INGRESS_DIRECTION: {
        qos_constants.RULE_TYPE_BANDWIDTH_LIMIT: QOS_RULE_BW_1}
}


class TestOVNClientQosExtensionBase(base.TestOVNFunctionalBase):

    def _check_rules(self, rules, port_id, network_id, fip_id=None,
                     ip_address=None, check_min_rate=True,
                     expected_ext_ids=None):
        egress_ovn_rule = self.qos_driver._ovn_qos_rule(
            constants.EGRESS_DIRECTION, rules.get(constants.EGRESS_DIRECTION),
            port_id, network_id, fip_id=fip_id, ip_address=ip_address)
        ingress_ovn_rule = self.qos_driver._ovn_qos_rule(
            constants.INGRESS_DIRECTION,
            rules.get(constants.INGRESS_DIRECTION), port_id, network_id,
            fip_id=fip_id, ip_address=ip_address)

        with self.nb_api.transaction(check_error=True):
            ls = self.qos_driver.nb_idl.lookup(
                'Logical_Switch', ovn_utils.ovn_name(network_id))
            try:
                lsp = self.qos_driver.nb_idl.lsp_get(port_id).execute(
                    check_error=True)
            except idlutils.RowNotFound:
                # A LSP is created only in the tests that apply QoS rules to
                # an internal port. Any L3 QoS test (router gateway port or
                # floating IP), won't have a LSP associated and won't check
                # min-rate rules.
                pass

            self.assertEqual(len(rules), len(ls.qos_rules))
            for rule in ls.qos_rules:
                if expected_ext_ids:
                    self.assertDictEqual(expected_ext_ids, rule.external_ids)
                ref_rule = (egress_ovn_rule if rule.direction == 'from-lport'
                            else ingress_ovn_rule)
                action = {}
                if 'dscp' in ref_rule:
                    action = {'dscp': ref_rule['dscp']}
                bandwidth = {}
                if 'rate' in ref_rule:
                    bandwidth['rate'] = ref_rule['rate']
                    if ref_rule.get('burst'):
                        bandwidth['burst'] = ref_rule['burst']
                self.assertIn(port_id, rule.match)
                self.assertEqual(action, rule.action)
                self.assertEqual(bandwidth, rule.bandwidth)
            min_rate = rules.get(constants.EGRESS_DIRECTION, {}).get(
                qos_constants.RULE_TYPE_MINIMUM_BANDWIDTH)
            if min_rate is not None and check_min_rate:
                min_ovn = lsp.options.get(ovn_const.LSP_OPTIONS_QOS_MIN_RATE)
                self.assertEqual(str(min_rate['min_kbps']), min_ovn)


class TestOVNClientQosExtension(TestOVNClientQosExtensionBase):

    def setUp(self, maintenance_worker=False):
        super(TestOVNClientQosExtension, self).setUp(
            maintenance_worker=maintenance_worker)
        self._add_logical_switch()
        self.qos_driver = qos_extension.OVNClientQosExtension(
            nb_idl=self.nb_api)
        self.gw_port_id = 'gw_port_id'
        self._mock_get_router = mock.patch.object(l3_db.L3_NAT_dbonly_mixin,
                                                  '_get_router')
        self.mock_get_router = self._mock_get_router.start()
        self.mock_get_router.return_value = {'gw_port_id': self.gw_port_id}
        self._mock_qos_rules = mock.patch.object(self.qos_driver,
                                                 '_qos_rules')
        self.mock_qos_rules = self._mock_qos_rules.start()
        self.fip = {'router_id': 'router_id', 'qos_policy_id': 'qos_policy_id',
                    'floating_network_id': self.network_1,
                    'id': 'fip_id', 'floating_ip_address': '1.2.3.4'}

    def _add_logical_switch(self):
        self.network_1 = 'network_1'
        with self.nb_api.transaction(check_error=True) as txn:
            txn.add(self.nb_api.ls_add(ovn_utils.ovn_name(self.network_1)))

    def _add_logical_switch_port(self, port_id):
        with self.nb_api.transaction(check_error=True) as txn:
            txn.add(self.nb_api.lsp_add(
                ovn_utils.ovn_name(self.network_1), port_id,
                options={'requested-chassis': 'compute1'}))

    def test__update_port_qos_rules(self):
        port = 'port1'
        self._add_logical_switch_port(port)

        def update_and_check(qos_rules):
            with self.nb_api.transaction(check_error=True) as txn:
                _qos_rules = copy.deepcopy(qos_rules)
                for direction in constants.VALID_DIRECTIONS:
                    _qos_rules[direction] = _qos_rules.get(direction, {})
                self.mock_qos_rules.return_value = _qos_rules
                self.qos_driver._update_port_qos_rules(
                    txn, port, self.network_1, 'qos1', None)
            self._check_rules(qos_rules, port, self.network_1)

        update_and_check(QOS_RULES_0)
        update_and_check(QOS_RULES_1)
        update_and_check(QOS_RULES_2)
        update_and_check(QOS_RULES_3)
        update_and_check({})

    def _update_fip_and_check(self, fip, qos_rules):
        with self.nb_api.transaction(check_error=True) as txn:
            _qos_rules = copy.deepcopy(qos_rules)
            for direction in constants.VALID_DIRECTIONS:
                _qos_rules[direction] = _qos_rules.get(direction, {})
            self.mock_qos_rules.return_value = _qos_rules
            self.qos_driver.update_floatingip(txn, fip)
        self._check_rules(qos_rules, self.gw_port_id, self.network_1,
                          fip_id='fip_id', ip_address='1.2.3.4')

    def test_create_floatingip(self):
        self._update_fip_and_check(self.fip, QOS_RULES_1)

    def test_update_floatingip(self):
        fip_updated = copy.deepcopy(self.fip)
        fip_updated['qos_policy_id'] = 'another_qos_policy'
        self._update_fip_and_check(self.fip, QOS_RULES_1)
        self._update_fip_and_check(fip_updated, QOS_RULES_2)
        self._update_fip_and_check(fip_updated, QOS_RULES_3)
        self._update_fip_and_check(fip_updated, {})

    def test_delete_floatingip(self):
        self._update_fip_and_check(self.fip, QOS_RULES_1)
        fip_dict = {'floating_network_id': self.fip['floating_network_id'],
                    'id': self.fip['id']}
        self._update_fip_and_check(fip_dict, {})


class TestOVNClientQosExtensionEndToEnd(TestOVNClientQosExtensionBase):

    def setUp(self, maintenance_worker=False):
        super(TestOVNClientQosExtensionEndToEnd, self).setUp(
            maintenance_worker=maintenance_worker)
        self.qos_driver = self.l3_plugin._ovn_client._qos_driver
        self._mock_qos_rules = mock.patch.object(self.qos_driver, '_qos_rules')
        self.mock_qos_rules = self._mock_qos_rules.start()

    def _create_router(self, name, gw_info=None, az_hints=None):
        router = {'router':
                  {'name': name,
                   'admin_state_up': True,
                   'tenant_id': self._tenant_id}}
        if az_hints:
            router['router']['availability_zone_hints'] = az_hints
        if gw_info:
            router['router']['external_gateway_info'] = gw_info
        return self.l3_plugin.create_router(self.context, router)

    def _create_ext_network(self, name, net_type, physnet, seg,
                            gateway, cidr):
        arg_list = (pnet.NETWORK_TYPE, external_net.EXTERNAL,)
        net_arg = {pnet.NETWORK_TYPE: net_type,
                   external_net.EXTERNAL: True}
        if seg:
            arg_list = arg_list + (pnet.SEGMENTATION_ID,)
            net_arg[pnet.SEGMENTATION_ID] = seg
        if physnet:
            arg_list = arg_list + (pnet.PHYSICAL_NETWORK,)
            net_arg[pnet.PHYSICAL_NETWORK] = physnet
        network = self._make_network(self.fmt, name, True,
                                     as_admin=True,
                                     arg_list=arg_list, **net_arg)
        if cidr:
            self._make_subnet(self.fmt, network, gateway, cidr,
                              ip_version=constants.IP_VERSION_4)
        return network

    def test_create_router_gateway_ip_qos(self):
        _qos_rules = copy.deepcopy(QOS_RULES_1)
        for direction in constants.VALID_DIRECTIONS:
            _qos_rules[direction] = _qos_rules.get(direction, {})
        self.mock_qos_rules.return_value = _qos_rules

        network = self._create_ext_network(
            utils.get_rand_name(), 'flat', 'physnet4',
            None, "110.0.0.1", "110.0.0.0/24")
        gw_info = {'network_id': network['network']['id']}
        router = self._create_router(utils.get_rand_name(), gw_info=gw_info)

        self._check_rules(
            _qos_rules, router['gw_port_id'],
            network['network']['id'],
            check_min_rate=False,
            expected_ext_ids={
                ovn_const.OVN_ROUTER_ID_EXT_ID_KEY: router['id']})
        self.l3_plugin.delete_router(self.context, router['id'])

    def test_delete_router_gateway_ip_qos_rules_removed(self):
        _qos_rules = copy.deepcopy(QOS_RULES_1)
        for direction in constants.VALID_DIRECTIONS:
            _qos_rules[direction] = _qos_rules.get(direction, {})
        self.mock_qos_rules.return_value = _qos_rules

        network = self._create_ext_network(
            utils.get_rand_name(), 'flat', 'physnet4',
            None, "120.0.0.1", "120.0.0.0/24")
        gw_info = {'network_id': network['network']['id']}
        router = self._create_router(utils.get_rand_name(), gw_info=gw_info)

        self._check_rules(
            _qos_rules, router['gw_port_id'],
            network['network']['id'],
            check_min_rate=False,
            expected_ext_ids={
                ovn_const.OVN_ROUTER_ID_EXT_ID_KEY: router['id']})
        ls = self.qos_driver.nb_idl.lookup(
            'Logical_Switch', ovn_utils.ovn_name(network['network']['id']))
        self.assertNotEqual(
            ls.qos_rules,
            [])

        self.l3_plugin.delete_router(self.context, router['id'])
        self.assertEqual(
            [],
            ls.qos_rules)

    def test_update_gateway_ip_qos(self):
        network = self._create_ext_network(
            utils.get_rand_name(), 'flat', 'physnet4',
            None, "130.0.0.1", "130.0.0.0/24")
        gw_info = {'network_id': network['network']['id']}
        router = self._create_router(utils.get_rand_name(), gw_info=gw_info)

        ls = self.qos_driver.nb_idl.lookup(
            'Logical_Switch', ovn_utils.ovn_name(network['network']['id']))
        self.assertEqual(
            [],
            ls.qos_rules)

        def update_and_check(qos_rules):
            _qos_rules = copy.deepcopy(qos_rules)
            for direction in constants.VALID_DIRECTIONS:
                _qos_rules[direction] = _qos_rules.get(direction, {})
            self.mock_qos_rules.return_value = _qos_rules
            self.l3_plugin.update_router(
                self.context, router['id'],
                {'router': {'admin_state_up': False}})
            self.l3_plugin.update_router(
                self.context, router['id'],
                {'router': {'admin_state_up': True}})
            self._check_rules(
                qos_rules, router['gw_port_id'], network['network']['id'],
                check_min_rate=False,
                expected_ext_ids={
                    ovn_const.OVN_ROUTER_ID_EXT_ID_KEY: router['id']})

        update_and_check(QOS_RULES_0)
        update_and_check(QOS_RULES_1)
        update_and_check(QOS_RULES_2)
        update_and_check(QOS_RULES_3)
        update_and_check({})

        self.l3_plugin.delete_router(self.context, router['id'])
