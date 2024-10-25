# Copyright (C) 2013 eNovance SAS <licensing@enovance.com>
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import copy
from unittest import mock

from oslo_config import cfg

from neutron.conf.services import metering_agent as metering_agent_config
from neutron.services.metering.drivers.iptables import iptables_driver
from neutron.tests import base


TEST_ROUTERS = [
    {'_metering_labels': [
        {'id': 'c5df2fe5-c600-4a2a-b2f4-c0fb6df73c83',
         'rules': [{
             'direction': 'ingress',
             'excluded': False,
             'id': '7f1a261f-2489-4ed1-870c-a62754501379',
             'metering_label_id': 'c5df2fe5-c600-4a2a-b2f4-c0fb6df73c83',
             'remote_ip_prefix': '10.0.0.0/24'}]}],
     'admin_state_up': True,
     'gw_port_id': '6d411f48-ecc7-45e0-9ece-3b5bdb54fcee',
     'id': '473ec392-1711-44e3-b008-3251ccfc5099',
     'name': 'router1',
     'distributed': False,
     'status': 'ACTIVE',
     'project_id': '6c5f5d2a1fa2441e88e35422926f48e8'},
    {'_metering_labels': [
        {'id': 'eeef45da-c600-4a2a-b2f4-c0fb6df73c83',
         'rules': [{
             'direction': 'egress',
             'excluded': False,
             'id': 'fa2441e8-2489-4ed1-870c-a62754501379',
             'metering_label_id': 'eeef45da-c600-4a2a-b2f4-c0fb6df73c83',
             'remote_ip_prefix': '20.0.0.0/24'}]}],
     'admin_state_up': True,
     'gw_port_id': '7d411f48-ecc7-45e0-9ece-3b5bdb54fcee',
     'id': '373ec392-1711-44e3-b008-3251ccfc5099',
     'name': 'router2',
     'status': 'ACTIVE',
     'distributed': False,
     'project_id': '6c5f5d2a1fa2441e88e35422926f48e8'},
]

TEST_DVR_ROUTER = [
    {'_metering_labels': [
        {'id': 'c5df2fe5-c610-4a2a-b2f4-c0fb6df73c83',
         'rules': [{
             'direction': 'ingress',
             'excluded': False,
             'id': '7f1a261f-2600-4ed1-870c-a62754501379',
             'metering_label_id': 'c5df2fe5-c700-4a2a-b2f4-c0fb6df73c83',
             'remote_ip_prefix': '10.0.0.0/24'}]}],
     'admin_state_up': True,
     'gw_port_id': '6d411f48-ecc7-45e0-9ece-3b5bdb54fcee',
     'id': '473ec392-2711-44e3-b008-3251ccfc5099',
     'name': 'router-test',
     'distributed': True,
     'status': 'ACTIVE',
     'project_id': '6c5f5d2a1fa2441e88e35422926f48e8'}]

TEST_ROUTERS_WITH_ONE_RULE = [
    {'_metering_labels': [
        {'id': 'c5df2fe5-c600-4a2a-b2f4-c0fb6df73c83',
         'rule': {
             'direction': 'ingress',
             'excluded': False,
             'id': '7f1a261f-2489-4ed1-870c-a62754501379',
             'metering_label_id': 'c5df2fe5-c600-4a2a-b2f4-c0fb6df73c83',
             'remote_ip_prefix': '30.0.0.0/24'}}],
     'admin_state_up': True,
     'gw_port_id': '6d411f48-ecc7-45e0-9ece-3b5bdb54fcee',
     'id': '473ec392-1711-44e3-b008-3251ccfc5099',
     'name': 'router1',
     'status': 'ACTIVE',
     'distributed': False,
     'project_id': '6c5f5d2a1fa2441e88e35422926f48e8'},
    {'_metering_labels': [
        {'id': 'eeef45da-c600-4a2a-b2f4-c0fb6df73c83',
         'rule': {
             'direction': 'egress',
             'excluded': False,
             'id': 'fa2441e8-2489-4ed1-870c-a62754501379',
             'metering_label_id': 'eeef45da-c600-4a2a-b2f4-c0fb6df73c83',
             'remote_ip_prefix': '40.0.0.0/24'}}],
     'admin_state_up': True,
     'gw_port_id': '7d411f48-ecc7-45e0-9ece-3b5bdb54fcee',
     'id': '373ec392-1711-44e3-b008-3251ccfc5099',
     'name': 'router2',
     'distributed': False,
     'status': 'ACTIVE',
     'project_id': '6c5f5d2a1fa2441e88e35422926f48e8'},
]

TEST_ROUTERS_WITH_NEW_LABEL = [
    {'_metering_labels': [
        {'id': 'e27fe2df-376e-4ac7-ae13-92f050a21f84',
         'rule': {
             'direction': 'ingress',
             'excluded': False,
             'id': '7f1a261f-2489-4ed1-870c-a62754501379',
             'metering_label_id': 'e27fe2df-376e-4ac7-ae13-92f050a21f84',
             'remote_ip_prefix': '50.0.0.0/24'}}],
     'admin_state_up': True,
     'gw_port_id': '6d411f48-ecc7-45e0-9ece-3b5bdb54fcee',
     'id': '473ec392-1711-44e3-b008-3251ccfc5099',
     'name': 'router1',
     'status': 'ACTIVE',
     'project_id': '6c5f5d2a1fa2441e88e35422926f48e8'}]


class IptablesDriverTestCase(base.BaseTestCase):
    def setUp(self):
        super().setUp()
        self.utils_exec_p = mock.patch(
            'neutron.agent.linux.utils.execute')
        self.utils_exec = self.utils_exec_p.start()
        self.iptables_cls_p = mock.patch(
            'neutron.agent.linux.iptables_manager.IptablesManager')
        self.iptables_cls = self.iptables_cls_p.start()
        self.iptables_inst = mock.Mock()
        self.v4filter_inst = mock.Mock()
        self.v6filter_inst = mock.Mock()
        self.namespace_exists_p = mock.patch(
            'neutron.agent.linux.ip_lib.network_namespace_exists')
        self.namespace_exists = self.namespace_exists_p.start()
        self.snat_ns_name_p = mock.patch(
            'neutron.agent.l3.dvr_snat_ns.SnatNamespace.get_snat_ns_name')
        self.snat_ns_name = self.snat_ns_name_p.start()
        self.v4filter_inst.chains = []
        self.v6filter_inst.chains = []
        self.iptables_inst.ipv4 = {'filter': self.v4filter_inst}
        self.iptables_inst.ipv6 = {'filter': self.v6filter_inst}
        self.iptables_cls.return_value = self.iptables_inst
        cfg.CONF.set_override('interface_driver',
                              'neutron.agent.linux.interface.NullDriver')

        metering_agent_config.register_metering_agent_opts()
        cfg.CONF.set_override('granular_traffic_data', False)

        self.metering = iptables_driver.IptablesMeteringDriver('metering',
                                                               cfg.CONF)

    def test_create_stateless_iptables_manager(self):
        routers = TEST_ROUTERS[:1]
        self.namespace_exists.return_value = True
        self.metering.add_metering_label(None, routers)
        self.assertEqual(1, self.iptables_cls.call_count)
        self.iptables_cls.assert_called_with(
            binary_name=mock.ANY,
            namespace=mock.ANY,
            state_less=True,
            use_ipv6=mock.ANY)
        rm = iptables_driver.RouterWithMetering(self.metering.conf, routers[0])
        self.assertTrue(rm.iptables_manager)
        self.assertIsNone(rm.snat_iptables_manager)

    def test_iptables_manager_never_create_with_no_valid_namespace(self):
        routers = TEST_ROUTERS[:1]
        self.namespace_exists.return_value = False
        self.metering.add_metering_label(None, routers)
        self.assertFalse(self.iptables_cls.called)
        rm = iptables_driver.RouterWithMetering(self.metering.conf, routers[0])
        self.assertIsNone(rm.iptables_manager)
        self.assertIsNone(rm.snat_iptables_manager)

    def test_create_iptables_manager_for_distributed_routers(self):
        routers = TEST_DVR_ROUTER[:1]
        self.namespace_exists.return_value = True
        snat_ns_name = 'snat-' + routers[0]['id']
        self.snat_ns_name.return_value = snat_ns_name
        self.metering.add_metering_label(None, routers)
        self.assertEqual(2, self.iptables_cls.call_count)
        rm = iptables_driver.RouterWithMetering(self.metering.conf, routers[0])
        self.assertTrue(rm.iptables_manager)
        self.assertTrue(rm.snat_iptables_manager)

    def test_add_metering_label(self):
        routers = TEST_ROUTERS[:1]

        self.namespace_exists.return_value = True
        self.metering.add_metering_label(None, routers)
        calls = [mock.call.add_chain('neutron-meter-l-c5df2fe5-c60',
                                     wrap=False),
                 mock.call.add_chain('neutron-meter-r-c5df2fe5-c60',
                                     wrap=False),
                 mock.call.add_rule('neutron-meter-FORWARD', '-j '
                                    'neutron-meter-r-c5df2fe5-c60',
                                    wrap=False),
                 mock.call.add_rule('neutron-meter-l-c5df2fe5-c60',
                                    '',
                                    wrap=False)]

        self.v4filter_inst.assert_has_calls(calls)

    def test_add_metering_label_dvr_routers(self):
        routers = TEST_DVR_ROUTER[:1]

        self.namespace_exists.return_value = True
        snat_ns_name = 'snat-' + routers[0]['id']
        self.snat_ns_name.return_value = snat_ns_name
        self.metering._process_ns_specific_metering_label = mock.Mock()
        self.metering.add_metering_label(None, routers)
        rm = iptables_driver.RouterWithMetering(self.metering.conf, routers[0])
        ext_dev, ext_snat_dev = self.metering.get_external_device_names(rm)
        self.assertEqual(
            2, self.metering._process_ns_specific_metering_label.call_count)
        # check and validate the right device being passed based on the
        # namespace.
        self.assertEqual(
            self.metering._process_ns_specific_metering_label.mock_calls,
            [mock.call(
                 routers[0], ext_dev, rm.iptables_manager),
             mock.call(
                 routers[0], ext_snat_dev, rm.snat_iptables_manager)])

    def test_add_metering_label_legacy_routers(self):
        routers = TEST_ROUTERS[:1]

        self.namespace_exists.return_value = True
        self.metering._process_ns_specific_metering_label = mock.Mock()
        self.metering.add_metering_label(None, routers)
        rm = iptables_driver.RouterWithMetering(self.metering.conf, routers[0])
        ext_dev, _ = self.metering.get_external_device_names(rm)
        self.assertEqual(
            self.metering._process_ns_specific_metering_label.mock_calls,
            [mock.call(routers[0], ext_dev, rm.iptables_manager)])

    def test_add_metering_label_when_no_namespace(self):
        routers = TEST_ROUTERS[:1]

        self.namespace_exists.return_value = False
        self.metering._process_metering_label = mock.Mock()
        self.metering.add_metering_label(None, routers)
        rm = iptables_driver.RouterWithMetering(self.metering.conf, routers[0])
        self.assertIsNone(rm.iptables_manager)
        self.assertIsNone(rm.snat_iptables_manager)
        self.assertFalse(self.metering._process_metering_label.called)

    def test_process_metering_label_rules(self):
        self.namespace_exists.return_value = True
        self.metering.add_metering_label(None, TEST_ROUTERS)

        calls = [mock.call.add_chain('neutron-meter-l-c5df2fe5-c60',
                                     wrap=False),
                 mock.call.add_chain('neutron-meter-r-c5df2fe5-c60',
                                     wrap=False),
                 mock.call.add_rule('neutron-meter-FORWARD', '-j '
                                    'neutron-meter-r-c5df2fe5-c60',
                                    wrap=False),
                 mock.call.add_rule('neutron-meter-l-c5df2fe5-c60',
                                    '',
                                    wrap=False),
                 mock.call.add_rule('neutron-meter-r-c5df2fe5-c60',
                                    '-d 10.0.0.0/24 -i qg-6d411f48-ec'
                                    ' -j neutron-meter-l-c5df2fe5-c60',
                                    wrap=False, top=False),
                 mock.call.add_chain('neutron-meter-l-eeef45da-c60',
                                     wrap=False),
                 mock.call.add_chain('neutron-meter-r-eeef45da-c60',
                                     wrap=False),
                 mock.call.add_rule('neutron-meter-FORWARD', '-j '
                                    'neutron-meter-r-eeef45da-c60',
                                    wrap=False),
                 mock.call.add_rule('neutron-meter-l-eeef45da-c60',
                                    '',
                                    wrap=False),
                 mock.call.add_rule('neutron-meter-r-eeef45da-c60',
                                    '-s 20.0.0.0/24 -o qg-7d411f48-ec'
                                    ' -j neutron-meter-l-eeef45da-c60',
                                    wrap=False, top=False)]

        self.v4filter_inst.assert_has_calls(calls)

    def test_process_metering_label_rules_with_no_gateway_router(self):
        routers = copy.deepcopy(TEST_ROUTERS)
        for router in routers:
            router['gw_port_id'] = None

        self.namespace_exists.return_value = True
        self.metering.add_metering_label(None, routers)

        calls = [mock.call.add_chain('neutron-meter-l-c5df2fe5-c60',
                                     wrap=False),
                 mock.call.add_chain('neutron-meter-r-c5df2fe5-c60',
                                     wrap=False),
                 mock.call.add_rule('neutron-meter-FORWARD', '-j '
                                    'neutron-meter-r-c5df2fe5-c60',
                                    wrap=False),
                 mock.call.add_rule('neutron-meter-l-c5df2fe5-c60',
                                    '',
                                    wrap=False),
                 mock.call.add_chain('neutron-meter-l-eeef45da-c60',
                                     wrap=False),
                 mock.call.add_chain('neutron-meter-r-eeef45da-c60',
                                     wrap=False),
                 mock.call.add_rule('neutron-meter-FORWARD', '-j '
                                    'neutron-meter-r-eeef45da-c60',
                                    wrap=False),
                 mock.call.add_rule('neutron-meter-l-eeef45da-c60',
                                    '',
                                    wrap=False)]

        self.v4filter_inst.assert_has_calls(calls, any_order=False)

    def test_add_metering_label_with_rules(self):
        routers = copy.deepcopy(TEST_ROUTERS)
        routers[1]['_metering_labels'][0]['rules'][0].update({
            'direction': 'ingress',
            'excluded': True,
        })

        self.namespace_exists.return_value = True
        self.metering.add_metering_label(None, routers)
        calls = [mock.call.add_chain('neutron-meter-l-c5df2fe5-c60',
                                     wrap=False),
                 mock.call.add_chain('neutron-meter-r-c5df2fe5-c60',
                                     wrap=False),
                 mock.call.add_rule('neutron-meter-FORWARD', '-j '
                                    'neutron-meter-r-c5df2fe5-c60',
                                    wrap=False),
                 mock.call.add_rule('neutron-meter-l-c5df2fe5-c60',
                                    '',
                                    wrap=False),
                 mock.call.add_rule('neutron-meter-r-c5df2fe5-c60',
                                    '-d 10.0.0.0/24 -i qg-6d411f48-ec'
                                    ' -j neutron-meter-l-c5df2fe5-c60',
                                    wrap=False, top=False),
                 mock.call.add_chain('neutron-meter-l-eeef45da-c60',
                                     wrap=False),
                 mock.call.add_chain('neutron-meter-r-eeef45da-c60',
                                     wrap=False),
                 mock.call.add_rule('neutron-meter-FORWARD', '-j '
                                    'neutron-meter-r-eeef45da-c60',
                                    wrap=False),
                 mock.call.add_rule('neutron-meter-l-eeef45da-c60',
                                    '',
                                    wrap=False),
                 mock.call.add_rule('neutron-meter-r-eeef45da-c60',
                                    '-d 20.0.0.0/24 -i qg-7d411f48-ec'
                                    ' -j RETURN',
                                    wrap=False, top=True)]

        self.v4filter_inst.assert_has_calls(calls)

    def test_update_metering_label_rules(self):
        routers = TEST_ROUTERS[:1]

        self.namespace_exists.return_value = True
        self.metering.add_metering_label(None, routers)

        updates = copy.deepcopy(routers)
        updates[0]['_metering_labels'][0]['rules'] = [{
            'direction': 'egress',
            'excluded': True,
            'id': '7f1a261f-2489-4ed1-870c-a62754501379',
            'metering_label_id': 'c5df2fe5-c600-4a2a-b2f4-c0fb6df73c83',
            'remote_ip_prefix': '10.0.0.0/24'},
            {'direction': 'ingress',
             'excluded': False,
             'id': '6f1a261f-2489-4ed1-870c-a62754501379',
             'metering_label_id': 'c5df2fe5-c600-4a2a-b2f4-c0fb6df73c83',
             'remote_ip_prefix': '20.0.0.0/24'}]

        self.metering.update_metering_label_rules(None, updates)

        calls = [mock.call.add_chain('neutron-meter-l-c5df2fe5-c60',
                                     wrap=False),
                 mock.call.add_chain('neutron-meter-r-c5df2fe5-c60',
                                     wrap=False),
                 mock.call.add_rule('neutron-meter-FORWARD', '-j '
                                    'neutron-meter-r-c5df2fe5-c60',
                                    wrap=False),
                 mock.call.add_rule('neutron-meter-l-c5df2fe5-c60',
                                    '',
                                    wrap=False),
                 mock.call.add_rule('neutron-meter-r-c5df2fe5-c60',
                                    '-d 10.0.0.0/24 -i qg-6d411f48-ec'
                                    ' -j neutron-meter-l-c5df2fe5-c60',
                                    wrap=False, top=False),
                 mock.call.empty_chain('neutron-meter-r-c5df2fe5-c60',
                                       wrap=False),
                 mock.call.add_rule('neutron-meter-r-c5df2fe5-c60',
                                    '-s 10.0.0.0/24 -o qg-6d411f48-ec'
                                    ' -j RETURN',
                                    wrap=False, top=True),
                 mock.call.add_rule('neutron-meter-r-c5df2fe5-c60',
                                    '-d 20.0.0.0/24 -i qg-6d411f48-ec -j '
                                    'neutron-meter-l-c5df2fe5-c60',
                                    wrap=False, top=False)]

        self.v4filter_inst.assert_has_calls(calls)

    def test_remove_metering_label_rule_in_update(self):
        routers = copy.deepcopy(TEST_ROUTERS[:1])
        routers[0]['_metering_labels'][0]['rules'].append({
            'direction': 'ingress',
            'excluded': False,
            'id': 'aaaa261f-2489-4ed1-870c-a62754501379',
            'metering_label_id': 'c5df2fe5-c600-4a2a-b2f4-c0fb6df73c83',
            'remote_ip_prefix': '20.0.0.0/24',
        })

        self.namespace_exists.return_value = True
        self.metering.add_metering_label(None, routers)

        del routers[0]['_metering_labels'][0]['rules'][1]

        self.metering.update_metering_label_rules(None, routers)
        calls = [mock.call.add_chain('neutron-meter-l-c5df2fe5-c60',
                                     wrap=False),
                 mock.call.add_chain('neutron-meter-r-c5df2fe5-c60',
                                     wrap=False),
                 mock.call.add_rule('neutron-meter-FORWARD', '-j '
                                    'neutron-meter-r-c5df2fe5-c60',
                                    wrap=False),
                 mock.call.add_rule('neutron-meter-l-c5df2fe5-c60',
                                    '',
                                    wrap=False),
                 mock.call.add_rule('neutron-meter-r-c5df2fe5-c60',
                                    '-d 10.0.0.0/24 -i qg-6d411f48-ec'
                                    ' -j neutron-meter-l-c5df2fe5-c60',
                                    wrap=False, top=False),
                 mock.call.add_rule('neutron-meter-r-c5df2fe5-c60',
                                    '-d 20.0.0.0/24 -i qg-6d411f48-ec'
                                    ' -j neutron-meter-l-c5df2fe5-c60',
                                    wrap=False, top=False),
                 mock.call.empty_chain('neutron-meter-r-c5df2fe5-c60',
                                       wrap=False),
                 mock.call.add_rule('neutron-meter-r-c5df2fe5-c60',
                                    '-d 10.0.0.0/24 -i qg-6d411f48-ec'
                                    ' -j neutron-meter-l-c5df2fe5-c60',
                                    wrap=False, top=False)]

        self.v4filter_inst.assert_has_calls(calls)

    def test_add_metering_label_rule(self):
        new_routers_rules = TEST_ROUTERS_WITH_ONE_RULE
        self.metering.update_routers(None, TEST_ROUTERS)
        self.namespace_exists.return_value = True
        self.metering.add_metering_label_rule(None, new_routers_rules)
        calls = [
                 mock.call.add_rule('neutron-meter-r-c5df2fe5-c60',
                                    '-d 30.0.0.0/24 -i qg-6d411f48-ec'
                                    ' -j neutron-meter-l-c5df2fe5-c60',
                                    wrap=False, top=False),
                 mock.call.add_rule('neutron-meter-r-eeef45da-c60',
                                    '-s 40.0.0.0/24 -o qg-7d411f48-ec'
                                    ' -j neutron-meter-l-eeef45da-c60',
                                    wrap=False, top=False),
                ]
        self.v4filter_inst.assert_has_calls(calls)

    def test_add_metering_label_rule_without_label(self):
        new_routers_rules = TEST_ROUTERS_WITH_NEW_LABEL
        # clear all the metering labels
        for r in TEST_ROUTERS:
            rm = iptables_driver.RouterWithMetering(self.metering.conf, r)
            rm.metering_labels = {}

        self.metering.update_routers(None, TEST_ROUTERS)
        self.metering.add_metering_label_rule(None, new_routers_rules)
        calls = [
                 mock.call.add_chain('neutron-meter-l-e27fe2df-376',
                                     wrap=False),
                 mock.call.add_chain('neutron-meter-r-e27fe2df-376',
                                     wrap=False),
                 mock.call.add_rule('neutron-meter-FORWARD',
                                    '-j neutron-meter-r-e27fe2df-376',
                                    wrap=False),
                 mock.call.add_rule('neutron-meter-l-e27fe2df-376',
                                    '',
                                    wrap=False),
                 mock.call.add_rule('neutron-meter-r-e27fe2df-376',
                                    '-d 50.0.0.0/24 '
                                    '-i qg-6d411f48-ec '
                                    '-j neutron-meter-l-e27fe2df-376',
                                    top=False,
                                    wrap=False)
                ]
        self.v4filter_inst.assert_has_calls(calls)

    def test_add_metering_label_rule_dvr_router(self):
        routers = TEST_DVR_ROUTER
        self.metering.update_routers(None, TEST_DVR_ROUTER)
        self.namespace_exists.return_value = True
        self.metering._process_metering_rule_action_based_on_ns = mock.Mock()
        self.metering.add_metering_label_rule(None, routers)
        rm = iptables_driver.RouterWithMetering(self.metering.conf, routers[0])
        ext_dev, ext_snat_dev = self.metering.get_external_device_names(rm)
        self.assertEqual(
            2,
            self.metering._process_metering_rule_action_based_on_ns.call_count)
        # check and validate the right device being passed based on the
        # namespace.
        self.assertEqual(
            self.metering._process_metering_rule_action_based_on_ns.mock_calls,
            [mock.call(
                 routers[0], 'create', ext_dev, rm.iptables_manager),
             mock.call(
                 routers[0], 'create', ext_snat_dev,
                 rm.snat_iptables_manager)])

    def test_remove_metering_label_rule_dvr_router(self):
        routers = TEST_DVR_ROUTER
        self.metering.update_routers(None, TEST_DVR_ROUTER)
        self.namespace_exists.return_value = True
        self.metering.add_metering_label_rule(None, routers)
        self.metering._process_metering_rule_action_based_on_ns = mock.Mock()
        self.metering.remove_metering_label_rule(None, routers)
        rm = iptables_driver.RouterWithMetering(self.metering.conf, routers[0])
        ext_dev, ext_snat_dev = self.metering.get_external_device_names(rm)
        self.assertEqual(
            2,
            self.metering._process_metering_rule_action_based_on_ns.call_count)
        # check and validate the right device being passed based on the
        # namespace.
        self.assertEqual(
            self.metering._process_metering_rule_action_based_on_ns.mock_calls,
            [mock.call(
                 routers[0], 'delete', ext_dev, rm.iptables_manager),
             mock.call(
                 routers[0], 'delete', ext_snat_dev,
                 rm.snat_iptables_manager)])

    def test_remove_metering_label_rule(self):
        new_routers_rules = TEST_ROUTERS_WITH_ONE_RULE
        self.metering.update_routers(None, TEST_ROUTERS)
        self.namespace_exists.return_value = True
        self.metering.add_metering_label_rule(None, new_routers_rules)
        self.metering.remove_metering_label_rule(None, new_routers_rules)
        calls = [
            mock.call.remove_rule('neutron-meter-r-c5df2fe5-c60',
                                  '-d 30.0.0.0/24 -i qg-6d411f48-ec'
                                  ' -j neutron-meter-l-c5df2fe5-c60',
                                  wrap=False, top=False),
            mock.call.remove_rule('neutron-meter-r-eeef45da-c60',
                                  '-s 40.0.0.0/24 -o qg-7d411f48-ec'
                                  ' -j neutron-meter-l-eeef45da-c60',
                                  wrap=False, top=False)
                ]
        self.v4filter_inst.assert_has_calls(calls)

    def test_remove_metering_label(self):
        routers = TEST_ROUTERS[:1]

        self.namespace_exists.return_value = True
        self.metering.add_metering_label(None, routers)
        self.metering.remove_metering_label(None, routers)
        calls = [mock.call.add_chain('neutron-meter-l-c5df2fe5-c60',
                                     wrap=False),
                 mock.call.add_chain('neutron-meter-r-c5df2fe5-c60',
                                     wrap=False),
                 mock.call.add_rule('neutron-meter-FORWARD', '-j '
                                    'neutron-meter-r-c5df2fe5-c60',
                                    wrap=False),
                 mock.call.add_rule('neutron-meter-l-c5df2fe5-c60',
                                    '',
                                    wrap=False),
                 mock.call.add_rule('neutron-meter-r-c5df2fe5-c60',
                                    '-d 10.0.0.0/24 -i qg-6d411f48-ec'
                                    ' -j neutron-meter-l-c5df2fe5-c60',
                                    wrap=False, top=False),
                 mock.call.remove_chain('neutron-meter-l-c5df2fe5-c60',
                                        wrap=False),
                 mock.call.remove_chain('neutron-meter-r-c5df2fe5-c60',
                                        wrap=False)]

        self.v4filter_inst.assert_has_calls(calls)

    def test_remove_metering_label_with_dvr_routers(self):
        routers = TEST_DVR_ROUTER[:1]

        self.namespace_exists.return_value = True
        self.metering.add_metering_label(None, routers)
        self.metering._process_ns_specific_disassociate_metering_label = (
            mock.Mock())
        self.metering.remove_metering_label(None, routers)
        self.assertEqual(
            2, (self.metering.
                _process_ns_specific_disassociate_metering_label.call_count))

    def test_update_routers(self):
        routers = copy.deepcopy(TEST_ROUTERS)
        routers[1]['_metering_labels'][0]['rules'][0].update({
            'direction': 'ingress',
            'excluded': True,
        })

        self.namespace_exists.return_value = True
        self.metering.add_metering_label(None, routers)

        updates = copy.deepcopy(routers)
        updates[0]['gw_port_id'] = '587b63c1-22a3-40b3-9834-486d1fb215a5'

        self.metering.update_routers(None, updates)
        calls = [mock.call.add_chain('neutron-meter-l-c5df2fe5-c60',
                                     wrap=False),
                 mock.call.add_chain('neutron-meter-r-c5df2fe5-c60',
                                     wrap=False),
                 mock.call.add_rule('neutron-meter-FORWARD', '-j '
                                    'neutron-meter-r-c5df2fe5-c60',
                                    wrap=False),
                 mock.call.add_rule('neutron-meter-l-c5df2fe5-c60',
                                    '',
                                    wrap=False),
                 mock.call.add_rule('neutron-meter-r-c5df2fe5-c60',
                                    '-d 10.0.0.0/24 -i qg-6d411f48-ec'
                                    ' -j neutron-meter-l-c5df2fe5-c60',
                                    wrap=False, top=False),
                 mock.call.add_chain('neutron-meter-l-eeef45da-c60',
                                     wrap=False),
                 mock.call.add_chain('neutron-meter-r-eeef45da-c60',
                                     wrap=False),
                 mock.call.add_rule('neutron-meter-FORWARD', '-j '
                                    'neutron-meter-r-eeef45da-c60',
                                    wrap=False),
                 mock.call.add_rule('neutron-meter-l-eeef45da-c60',
                                    '',
                                    wrap=False),
                 mock.call.add_rule('neutron-meter-r-eeef45da-c60',
                                    '-d 20.0.0.0/24 -i qg-7d411f48-ec'
                                    ' -j RETURN',
                                    wrap=False, top=True),
                 mock.call.remove_chain('neutron-meter-l-c5df2fe5-c60',
                                        wrap=False),
                 mock.call.remove_chain('neutron-meter-r-c5df2fe5-c60',
                                        wrap=False),
                 mock.call.add_chain('neutron-meter-l-c5df2fe5-c60',
                                     wrap=False),
                 mock.call.add_chain('neutron-meter-r-c5df2fe5-c60',
                                     wrap=False),
                 mock.call.add_rule('neutron-meter-FORWARD', '-j '
                                    'neutron-meter-r-c5df2fe5-c60',
                                    wrap=False),
                 mock.call.add_rule('neutron-meter-l-c5df2fe5-c60',
                                    '',
                                    wrap=False),
                 mock.call.add_rule('neutron-meter-r-c5df2fe5-c60',
                                    '-d 10.0.0.0/24 -i qg-587b63c1-22'
                                    ' -j neutron-meter-l-c5df2fe5-c60',
                                    wrap=False, top=False)]

        self.v4filter_inst.assert_has_calls(calls)

    def test_update_routers_removal(self):
        routers = TEST_ROUTERS

        self.namespace_exists.return_value = True
        self.metering.add_metering_label(None, routers)

        # Remove router id '373ec392-1711-44e3-b008-3251ccfc5099'
        updates = TEST_ROUTERS[:1]

        self.metering.update_routers(None, updates)
        calls = [mock.call.remove_chain('neutron-meter-l-eeef45da-c60',
                                        wrap=False),
                 mock.call.remove_chain('neutron-meter-r-eeef45da-c60',
                                        wrap=False)]

        self.v4filter_inst.assert_has_calls(calls)

    def test_get_traffic_counters_with_missing_chain(self):
        for r in TEST_ROUTERS:
            rm = iptables_driver.RouterWithMetering(self.metering.conf, r)
            rm.metering_labels = {r['_metering_labels'][0]['id']: 'fake'}
            self.metering.routers[r['id']] = rm

        mocked_method = self.iptables_cls.return_value.get_traffic_counters
        mocked_method.side_effect = [{'pkts': 1, 'bytes': 8},
                                     RuntimeError('Failed to find the chain')]

        counters = self.metering.get_traffic_counters(None, TEST_ROUTERS)
        expected_label_id = TEST_ROUTERS[0]['_metering_labels'][0]['id']
        self.assertIn(expected_label_id, counters)
        self.assertEqual(1, counters[expected_label_id]['pkts'])
        self.assertEqual(8, counters[expected_label_id]['bytes'])

    def test_sync_router_namespaces(self):
        routers = TEST_DVR_ROUTER[:1]

        self.metering._process_ns_specific_metering_label = mock.Mock()
        self.namespace_exists.return_value = False
        self.metering.add_metering_label(None, routers)
        rm = self.metering.routers[routers[0]['id']]
        self.assertEqual(
            0, self.metering._process_ns_specific_metering_label.call_count)
        self.assertIsNone(rm.snat_iptables_manager)
        self.assertIsNone(rm.iptables_manager)

        self.namespace_exists.side_effect = [True, False]
        self.metering.sync_router_namespaces(None, routers)
        self.assertIsNotNone(rm.snat_iptables_manager)
        self.assertIsNone(rm.iptables_manager)
        self.assertEqual(
            1, self.metering._process_ns_specific_metering_label.call_count)

        self.namespace_exists.side_effect = [True]
        self.metering.sync_router_namespaces(None, routers)
        self.assertIsNotNone(rm.snat_iptables_manager)
        self.assertIsNotNone(rm.iptables_manager)
        self.assertEqual(
            3, self.metering._process_ns_specific_metering_label.call_count)

        # syncing again should have no effect
        self.namespace_exists.side_effect = [RuntimeError('Unexpected call')]
        self.metering.sync_router_namespaces(None, routers)
        self.assertIsNotNone(rm.snat_iptables_manager)
        self.assertIsNotNone(rm.iptables_manager)
        self.assertEqual(
            3, self.metering._process_ns_specific_metering_label.call_count)

    def test_get_traffic_counters_granular_data(self):
        for r in TEST_ROUTERS:
            rm = iptables_driver.RouterWithMetering(self.metering.conf, r)
            rm.metering_labels = {r['_metering_labels'][0]['id']: 'fake'}
            self.metering.routers[r['id']] = rm

        mocked_method = self.iptables_cls.return_value.get_traffic_counters
        mocked_method.side_effect = [{'pkts': 2, 'bytes': 5},
                                     {'pkts': 4, 'bytes': 3}]

        old_granular_traffic_data = self.metering.granular_traffic_data

        expected_total_number_of_data_granularities = 9
        expected_response = {
            "router-373ec392-1711-44e3-b008-3251ccfc5099": {
                "pkts": 4,
                "bytes": 3,
                "traffic-counter-granularity": "router"
            },
            "label-c5df2fe5-c600-4a2a-b2f4-c0fb6df73c83": {
                "pkts": 2,
                "bytes": 5,
                "traffic-counter-granularity": "label"
            },
            "router-473ec392-1711-44e3-b008-3251ccfc5099-"
            "label-c5df2fe5-c600-4a2a-b2f4-c0fb6df73c83": {
                "pkts": 2,
                "bytes": 5,
                "traffic-counter-granularity": "label_router"
            },
            "label-eeef45da-c600-4a2a-b2f4-c0fb6df73c83": {
                "pkts": 4,
                "bytes": 3,
                "traffic-counter-granularity": "label"
            },
            "project-6c5f5d2a1fa2441e88e35422926f48e8-"
            "label-eeef45da-c600-4a2a-b2f4-c0fb6df73c83": {
                "pkts": 4,
                "bytes": 3,
                "traffic-counter-granularity": "label_project"

            },
            "router-473ec392-1711-44e3-b008-3251ccfc5099": {
                "pkts": 2,
                "bytes": 5,
                "traffic-counter-granularity": "router"
            },
            "project-6c5f5d2a1fa2441e88e35422926f48e8": {
                "pkts": 6,
                "bytes": 8,
                "traffic-counter-granularity": "project"
            },
            "router-373ec392-1711-44e3-b008-3251ccfc5099-"
            "label-eeef45da-c600-4a2a-b2f4-c0fb6df73c83": {
                "pkts": 4,
                "bytes": 3,
                "traffic-counter-granularity": "label_router"
            },
            "project-6c5f5d2a1fa2441e88e35422926f48e8-"
            "label-c5df2fe5-c600-4a2a-b2f4-c0fb6df73c83": {
                "pkts": 2,
                "bytes": 5,
                "traffic-counter-granularity": "label_project"
            }
        }
        try:
            self.metering.granular_traffic_data = True
            counters = self.metering.get_traffic_counters(None, TEST_ROUTERS)

            self.assertEqual(expected_total_number_of_data_granularities,
                             len(counters))
            self.assertEqual(expected_response, counters)
        finally:
            self.metering.granular_traffic_data = old_granular_traffic_data

    def test_get_traffic_counters_legacy_mode(self):
        for r in TEST_ROUTERS:
            rm = iptables_driver.RouterWithMetering(self.metering.conf, r)
            rm.metering_labels = {r['_metering_labels'][0]['id']: 'fake'}
            self.metering.routers[r['id']] = rm

        mocked_method = self.iptables_cls.return_value.get_traffic_counters
        mocked_method.side_effect = [{'pkts': 2, 'bytes': 5},
                                     {'pkts': 4, 'bytes': 3}]

        old_granular_traffic_data = self.metering.granular_traffic_data

        expected_total_number_of_data_granularity = 2

        expected_response = {
            'eeef45da-c600-4a2a-b2f4-c0fb6df73c83': {'pkts': 4, 'bytes': 3},
            'c5df2fe5-c600-4a2a-b2f4-c0fb6df73c83': {'pkts': 2, 'bytes': 5}}
        try:
            self.metering.granular_traffic_data = False
            counters = self.metering.get_traffic_counters(None, TEST_ROUTERS)
            self.assertEqual(expected_total_number_of_data_granularity,
                             len(counters))
            self.assertEqual(expected_response, counters)
        finally:
            self.metering.granular_traffic_data = old_granular_traffic_data
