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

from neutron_lib import constants
from neutron_lib.services.qos import constants as qos_constants

from neutron.common.ovn import utils as ovn_utils
from neutron.db import l3_db
from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb.extensions \
    import qos as qos_extension
from neutron.tests.functional import base


QOS_RULE_BW_1 = {'max_kbps': 200, 'max_burst_kbps': 100}
QOS_RULE_BW_2 = {'max_kbps': 300}
QOS_RULE_DSCP_1 = {'dscp_mark': 16}
QOS_RULE_DSCP_2 = {'dscp_mark': 20}

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
        qos_constants.RULE_TYPE_BANDWIDTH_LIMIT: QOS_RULE_BW_1,
        qos_constants.RULE_TYPE_DSCP_MARKING: QOS_RULE_DSCP_1}
}


class _OVNClient(object):

    def __init__(self, nd_idl):
        self._nb_idl = nd_idl


class TestOVNClientQosExtension(base.TestOVNFunctionalBase):

    def setUp(self, maintenance_worker=False):
        super(TestOVNClientQosExtension, self).setUp(
            maintenance_worker=maintenance_worker)
        self._add_logical_switch()
        _ovn_client = _OVNClient(self.nb_api)
        self.qos_driver = qos_extension.OVNClientQosExtension(_ovn_client)
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

    def _check_rules(self, rules, port_id, network_id, fip_id=None,
                     ip_address=None):
        egress_ovn_rule = self.qos_driver._ovn_qos_rule(
            constants.EGRESS_DIRECTION, rules.get(constants.EGRESS_DIRECTION),
            port_id, network_id, fip_id=fip_id, ip_address=ip_address)
        ingress_ovn_rule = self.qos_driver._ovn_qos_rule(
            constants.INGRESS_DIRECTION,
            rules.get(constants.INGRESS_DIRECTION), port_id, network_id,
            fip_id=fip_id, ip_address=ip_address)

        with self.nb_api.transaction(check_error=True):
            ls = self.qos_driver._driver._nb_idl.lookup(
                'Logical_Switch', ovn_utils.ovn_name(self.network_1))
            self.assertEqual(len(rules), len(ls.qos_rules))
            for rule in ls.qos_rules:
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

    def test__update_port_qos_rules(self):
        port = 'port1'

        def update_and_check(qos_rules):
            with self.nb_api.transaction(check_error=True) as txn:
                self.mock_qos_rules.return_value = qos_rules
                self.qos_driver._update_port_qos_rules(
                    txn, port, self.network_1, 'qos1', None)
            self._check_rules(qos_rules, port, self.network_1)

        update_and_check(QOS_RULES_1)
        update_and_check(QOS_RULES_2)
        update_and_check(QOS_RULES_3)
        update_and_check({})

    def _update_fip_and_check(self, fip, qos_rules):
        with self.nb_api.transaction(check_error=True) as txn:
            self.mock_qos_rules.return_value = qos_rules
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
