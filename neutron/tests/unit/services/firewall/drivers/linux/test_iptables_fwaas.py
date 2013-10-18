# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013 Dell Inc.
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
# @author: Rajesh Mohan, Rajesh_Mohan3@Dell.com, DELL Inc.

import mock
from mock import call
from oslo.config import cfg

from neutron.agent.common import config as a_cfg
import neutron.services.firewall.drivers.linux.iptables_fwaas as fwaas
from neutron.tests import base
from neutron.tests.unit import test_api_v2


_uuid = test_api_v2._uuid
FAKE_SRC_PREFIX = '10.0.0.0/24'
FAKE_DST_PREFIX = '20.0.0.0/24'
FAKE_PROTOCOL = 'tcp'
FAKE_SRC_PORT = 5000
FAKE_DST_PORT = 22
FAKE_FW_ID = 'fake-fw-uuid'


class IptablesFwaasTestCase(base.BaseTestCase):
    def setUp(self):
        super(IptablesFwaasTestCase, self).setUp()
        cfg.CONF.register_opts(a_cfg.ROOT_HELPER_OPTS, 'AGENT')
        self.utils_exec_p = mock.patch(
            'neutron.agent.linux.utils.execute')
        self.utils_exec = self.utils_exec_p.start()
        self.addCleanup(self.utils_exec_p.stop)
        self.iptables_cls_p = mock.patch(
            'neutron.agent.linux.iptables_manager.IptablesManager')
        self.iptables_cls_p.start()
        self.addCleanup(self.iptables_cls_p.stop)
        self.firewall = fwaas.IptablesFwaasDriver()

    def _fake_rules_v4(self, fwid, apply_list):
        rule_list = []
        rule1 = {'enabled': True,
                 'action': 'allow',
                 'ip_version': 4,
                 'protocol': 'tcp',
                 'destination_port': '80',
                 'source_ip_address': '10.24.4.2'}
        rule2 = {'enabled': True,
                 'action': 'deny',
                 'ip_version': 4,
                 'protocol': 'tcp',
                 'destination_port': '22'}
        ingress_chain = ('iv4%s' % fwid)[:11]
        egress_chain = ('ov4%s' % fwid)[:11]
        for router_info_inst in apply_list:
            v4filter_inst = router_info_inst.iptables_manager.ipv4['filter']
            v4filter_inst.chains.append(ingress_chain)
            v4filter_inst.chains.append(egress_chain)
        rule_list.append(rule1)
        rule_list.append(rule2)
        return rule_list

    def _fake_firewall_no_rule(self):
        rule_list = []
        fw_inst = {'id': FAKE_FW_ID,
                   'admin_state_up': True,
                   'tenant_id': 'tenant-uuid',
                   'firewall_rule_list': rule_list}
        return fw_inst

    def _fake_firewall(self, rule_list):
        fw_inst = {'id': FAKE_FW_ID,
                   'admin_state_up': True,
                   'tenant_id': 'tenant-uuid',
                   'firewall_rule_list': rule_list}
        return fw_inst

    def _fake_firewall_with_admin_down(self, rule_list):
        fw_inst = {'id': FAKE_FW_ID,
                   'admin_state_up': False,
                   'tenant_id': 'tenant-uuid',
                   'firewall_rule_list': rule_list}
        return fw_inst

    def _fake_apply_list(self, router_count=1):
        apply_list = []
        while router_count > 0:
            iptables_inst = mock.Mock()
            v4filter_inst = mock.Mock()
            v6filter_inst = mock.Mock()
            v4filter_inst.chains = []
            v6filter_inst.chains = []
            iptables_inst.ipv4 = {'filter': v4filter_inst}
            iptables_inst.ipv6 = {'filter': v6filter_inst}
            router_info_inst = mock.Mock()
            router_info_inst.iptables_manager = iptables_inst
            apply_list.append(router_info_inst)
            router_count -= 1
        return apply_list

    def _setup_firewall_with_rules(self, func, router_count=1):
        apply_list = self._fake_apply_list(router_count=router_count)
        rule_list = self._fake_rules_v4(FAKE_FW_ID, apply_list)
        firewall = self._fake_firewall(rule_list)
        func(apply_list, firewall)
        invalid_rule = '-m state --state INVALID -j DROP'
        est_rule = '-m state --state ESTABLISHED,RELATED -j ACCEPT'
        rule1 = '-p tcp --dport 80  -s 10.24.4.2  -j ACCEPT'
        rule2 = '-p tcp --dport 22    -j DROP'
        ingress_chain = 'iv4%s' % firewall['id']
        egress_chain = 'ov4%s' % firewall['id']
        bname = fwaas.iptables_manager.binary_name
        ipt_mgr_ichain = '%s-%s' % (bname, ingress_chain[:11])
        ipt_mgr_echain = '%s-%s' % (bname, egress_chain[:11])
        for router_info_inst in apply_list:
            v4filter_inst = router_info_inst.iptables_manager.ipv4['filter']
            calls = [call.ensure_remove_chain('iv4fake-fw-uuid'),
                     call.ensure_remove_chain('ov4fake-fw-uuid'),
                     call.ensure_remove_chain('fwaas-default-policy'),
                     call.add_chain('fwaas-default-policy'),
                     call.add_rule('fwaas-default-policy', '-j DROP'),
                     call.add_chain(ingress_chain),
                     call.add_rule(ingress_chain, invalid_rule),
                     call.add_rule(ingress_chain, est_rule),
                     call.add_chain(egress_chain),
                     call.add_rule(egress_chain, invalid_rule),
                     call.add_rule(egress_chain, est_rule),
                     call.add_rule(ingress_chain, rule1),
                     call.add_rule(egress_chain, rule1),
                     call.add_rule(ingress_chain, rule2),
                     call.add_rule(egress_chain, rule2),
                     call.add_rule('FORWARD',
                                   '-o qr-+ -j %s' % ipt_mgr_ichain),
                     call.add_rule('FORWARD',
                                   '-i qr-+ -j %s' % ipt_mgr_echain),
                     call.add_rule('FORWARD',
                                   '-o qr-+ -j %s-fwaas-defau' % bname),
                     call.add_rule('FORWARD',
                                   '-i qr-+ -j %s-fwaas-defau' % bname)]
            v4filter_inst.assert_has_calls(calls)

    def test_create_firewall_no_rules(self):
        apply_list = self._fake_apply_list()
        firewall = self._fake_firewall_no_rule()
        self.firewall.create_firewall(apply_list, firewall)
        invalid_rule = '-m state --state INVALID -j DROP'
        est_rule = '-m state --state ESTABLISHED,RELATED -j ACCEPT'
        ingress_chain = ('iv4%s' % firewall['id'])
        egress_chain = ('ov4%s' % firewall['id'])
        bname = fwaas.iptables_manager.binary_name
        calls = [call.ensure_remove_chain('iv4fake-fw-uuid'),
                 call.ensure_remove_chain('ov4fake-fw-uuid'),
                 call.ensure_remove_chain('fwaas-default-policy'),
                 call.add_chain('fwaas-default-policy'),
                 call.add_rule('fwaas-default-policy', '-j DROP'),
                 call.add_chain(ingress_chain),
                 call.add_rule(ingress_chain, invalid_rule),
                 call.add_rule(ingress_chain, est_rule),
                 call.add_chain(egress_chain),
                 call.add_rule(egress_chain, invalid_rule),
                 call.add_rule(egress_chain, est_rule),
                 call.add_rule('FORWARD', '-o qr-+ -j %s-fwaas-defau' % bname),
                 call.add_rule('FORWARD', '-i qr-+ -j %s-fwaas-defau' % bname)]
        apply_list[0].iptables_manager.ipv4['filter'].assert_has_calls(calls)

    def test_create_firewall_with_rules(self):
        self._setup_firewall_with_rules(self.firewall.create_firewall)

    def test_create_firewall_with_rules_two_routers(self):
        self._setup_firewall_with_rules(self.firewall.create_firewall,
                                        router_count=2)

    def test_update_firewall_with_rules(self):
        self._setup_firewall_with_rules(self.firewall.update_firewall)

    def test_delete_firewall(self):
        apply_list = self._fake_apply_list()
        firewall = self._fake_firewall_no_rule()
        self.firewall.delete_firewall(apply_list, firewall)
        ingress_chain = 'iv4%s' % firewall['id']
        egress_chain = 'ov4%s' % firewall['id']
        calls = [call.ensure_remove_chain(ingress_chain),
                 call.ensure_remove_chain(egress_chain),
                 call.ensure_remove_chain('fwaas-default-policy')]
        apply_list[0].iptables_manager.ipv4['filter'].assert_has_calls(calls)

    def test_create_firewall_with_admin_down(self):
        apply_list = self._fake_apply_list()
        rule_list = self._fake_rules_v4(FAKE_FW_ID, apply_list)
        firewall = self._fake_firewall_with_admin_down(rule_list)
        self.firewall.create_firewall(apply_list, firewall)
        calls = [call.ensure_remove_chain('iv4fake-fw-uuid'),
                 call.ensure_remove_chain('ov4fake-fw-uuid'),
                 call.ensure_remove_chain('fwaas-default-policy'),
                 call.add_chain('fwaas-default-policy'),
                 call.add_rule('fwaas-default-policy', '-j DROP')]
        apply_list[0].iptables_manager.ipv4['filter'].assert_has_calls(calls)
