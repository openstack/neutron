# Copyright (C) 2013 eNovance SAS <licensing@enovance.com>
#
# Author: Sylvain Afchain <sylvain.afchain@enovance.com>
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

import mock
from mock import call
from oslo.config import cfg

from neutron.services.metering.drivers.iptables import iptables_driver
from neutron.tests import base
from neutron.tests.unit import test_api_v2

_uuid = test_api_v2._uuid


class IptablesDriverTestCase(base.BaseTestCase):
    def setUp(self):
        super(IptablesDriverTestCase, self).setUp()
        self.utils_exec_p = mock.patch(
            'neutron.agent.linux.utils.execute')
        self.utils_exec = self.utils_exec_p.start()
        self.addCleanup(self.utils_exec_p.stop)
        self.iptables_cls_p = mock.patch(
            'neutron.agent.linux.iptables_manager.IptablesManager')
        self.iptables_cls = self.iptables_cls_p.start()
        self.addCleanup(self.iptables_cls_p.stop)
        self.iptables_inst = mock.Mock()
        self.v4filter_inst = mock.Mock()
        self.v6filter_inst = mock.Mock()
        self.v4filter_inst.chains = []
        self.v6filter_inst.chains = []
        self.iptables_inst.ipv4 = {'filter': self.v4filter_inst}
        self.iptables_inst.ipv6 = {'filter': self.v6filter_inst}
        self.iptables_cls.return_value = self.iptables_inst
        cfg.CONF.set_override('interface_driver',
                              'neutron.agent.linux.interface.NullDriver')
        cfg.CONF.set_override('root_helper',
                              'fake_sudo',
                              'AGENT')
        self.metering = iptables_driver.IptablesMeteringDriver('metering',
                                                               cfg.CONF)

    def test_root_helper(self):
        routers = [{'_metering_labels': [
            {'id': 'c5df2fe5-c600-4a2a-b2f4-c0fb6df73c83',
             'rules': []}],
            'admin_state_up': True,
            'gw_port_id': '7d411f48-ecc7-45e0-9ece-3b5bdb54fcee',
            'id': '473ec392-1711-44e3-b008-3251ccfc5099',
            'name': 'router1',
            'status': 'ACTIVE',
            'tenant_id': '6c5f5d2a1fa2441e88e35422926f48e8'}]
        self.metering.add_metering_label(None, routers)

        self.iptables_cls.assert_called_with(root_helper='fake_sudo',
                                             namespace=mock.ANY,
                                             binary_name=mock.ANY,
                                             use_ipv6=mock.ANY)

    def test_add_metering_label(self):
        routers = [{'_metering_labels': [
            {'id': 'c5df2fe5-c600-4a2a-b2f4-c0fb6df73c83',
             'rules': []}],
            'admin_state_up': True,
            'gw_port_id': '7d411f48-ecc7-45e0-9ece-3b5bdb54fcee',
            'id': '473ec392-1711-44e3-b008-3251ccfc5099',
            'name': 'router1',
            'status': 'ACTIVE',
            'tenant_id': '6c5f5d2a1fa2441e88e35422926f48e8'}]

        self.metering.add_metering_label(None, routers)
        calls = [call.add_chain('neutron-meter-l-c5df2fe5-c60', wrap=False),
                 call.add_chain('neutron-meter-r-c5df2fe5-c60', wrap=False),
                 call.add_rule('neutron-meter-FORWARD', '-j '
                               'neutron-meter-r-c5df2fe5-c60', wrap=False),
                 call.add_rule('neutron-meter-l-c5df2fe5-c60',
                               '',
                               wrap=False)]

        self.v4filter_inst.assert_has_calls(calls)

    def test_process_metering_label_rules(self):
        routers = [{'_metering_labels': [
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
            'status': 'ACTIVE',
            'tenant_id': '6c5f5d2a1fa2441e88e35422926f48e8'},
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
             'tenant_id': '6c5f5d2a1fa2441e88e35422926f48e8'}]
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
                                    '-i qg-6d411f48-ec -d 10.0.0.0/24'
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
                                    '-o qg-7d411f48-ec -s 20.0.0.0/24'
                                    ' -j neutron-meter-l-eeef45da-c60',
                                    wrap=False, top=False)]

        self.v4filter_inst.assert_has_calls(calls)

    def test_add_metering_label_with_rules(self):
        routers = [{'_metering_labels': [
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
            'status': 'ACTIVE',
            'tenant_id': '6c5f5d2a1fa2441e88e35422926f48e8'},
            {'_metering_labels': [
             {'id': 'eeef45da-c600-4a2a-b2f4-c0fb6df73c83',
              'rules': [{
                  'direction': 'ingress',
                  'excluded': True,
                  'id': 'fa2441e8-2489-4ed1-870c-a62754501379',
                  'metering_label_id': 'eeef45da-c600-4a2a-b2f4-c0fb6df73c83',
                  'remote_ip_prefix': '20.0.0.0/24'}]}],
             'admin_state_up': True,
             'gw_port_id': '7d411f48-ecc7-45e0-9ece-3b5bdb54fcee',
             'id': '373ec392-1711-44e3-b008-3251ccfc5099',
             'name': 'router2',
             'status': 'ACTIVE',
             'tenant_id': '6c5f5d2a1fa2441e88e35422926f48e8'}]

        self.metering.add_metering_label(None, routers)
        calls = [call.add_chain('neutron-meter-l-c5df2fe5-c60', wrap=False),
                 call.add_chain('neutron-meter-r-c5df2fe5-c60', wrap=False),
                 call.add_rule('neutron-meter-FORWARD', '-j '
                               'neutron-meter-r-c5df2fe5-c60', wrap=False),
                 call.add_rule('neutron-meter-l-c5df2fe5-c60',
                               '',
                               wrap=False),
                 call.add_rule('neutron-meter-r-c5df2fe5-c60',
                               '-i qg-6d411f48-ec -d 10.0.0.0/24'
                               ' -j neutron-meter-l-c5df2fe5-c60',
                               wrap=False, top=False),
                 call.add_chain('neutron-meter-l-eeef45da-c60', wrap=False),
                 call.add_chain('neutron-meter-r-eeef45da-c60', wrap=False),
                 call.add_rule('neutron-meter-FORWARD', '-j '
                               'neutron-meter-r-eeef45da-c60', wrap=False),
                 call.add_rule('neutron-meter-l-eeef45da-c60',
                               '',
                               wrap=False),
                 call.add_rule('neutron-meter-r-eeef45da-c60',
                               '-i qg-7d411f48-ec -d 20.0.0.0/24 -j RETURN',
                               wrap=False, top=True)]

        self.v4filter_inst.assert_has_calls(calls)

    def test_update_metering_label_rules(self):
        routers = [{'_metering_labels': [
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
            'status': 'ACTIVE',
            'tenant_id': '6c5f5d2a1fa2441e88e35422926f48e8'}]

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

        calls = [call.add_chain('neutron-meter-l-c5df2fe5-c60', wrap=False),
                 call.add_chain('neutron-meter-r-c5df2fe5-c60', wrap=False),
                 call.add_rule('neutron-meter-FORWARD', '-j '
                               'neutron-meter-r-c5df2fe5-c60', wrap=False),
                 call.add_rule('neutron-meter-l-c5df2fe5-c60',
                               '',
                               wrap=False),
                 call.add_rule('neutron-meter-r-c5df2fe5-c60',
                               '-i qg-6d411f48-ec -d 10.0.0.0/24'
                               ' -j neutron-meter-l-c5df2fe5-c60',
                               wrap=False, top=False),
                 call.empty_chain('neutron-meter-r-c5df2fe5-c60', wrap=False),
                 call.add_rule('neutron-meter-r-c5df2fe5-c60',
                               '-o qg-6d411f48-ec -s 10.0.0.0/24 -j RETURN',
                               wrap=False, top=True),
                 call.add_rule('neutron-meter-r-c5df2fe5-c60',
                               '-i qg-6d411f48-ec -d 20.0.0.0/24 -j '
                               'neutron-meter-l-c5df2fe5-c60',
                               wrap=False, top=False)]

        self.v4filter_inst.assert_has_calls(calls)

    def test_remove_metering_label_rule(self):
        routers = [{'_metering_labels': [
            {'id': 'c5df2fe5-c600-4a2a-b2f4-c0fb6df73c83',
             'rules': [{
                 'direction': 'ingress',
                 'excluded': False,
                 'id': '7f1a261f-2489-4ed1-870c-a62754501379',
                 'metering_label_id': 'c5df2fe5-c600-4a2a-b2f4-c0fb6df73c83',
                 'remote_ip_prefix': '10.0.0.0/24'},
                 {'direction': 'ingress',
                  'excluded': False,
                  'id': 'aaaa261f-2489-4ed1-870c-a62754501379',
                  'metering_label_id': 'c5df2fe5-c600-4a2a-b2f4-c0fb6df73c83',
                  'remote_ip_prefix': '20.0.0.0/24'}]
             }],
            'admin_state_up': True,
            'gw_port_id': '7d411f48-ecc7-45e0-9ece-3b5bdb54fcee',
            'id': '473ec392-1711-44e3-b008-3251ccfc5099',
            'name': 'router1',
            'status': 'ACTIVE',
            'tenant_id': '6c5f5d2a1fa2441e88e35422926f48e8'}]

        self.metering.add_metering_label(None, routers)

        routers = [{'_metering_labels': [
            {'id': 'c5df2fe5-c600-4a2a-b2f4-c0fb6df73c83',
             'rules': [{
                 'direction': 'ingress',
                 'excluded': False,
                 'id': '7f1a261f-2489-4ed1-870c-a62754501379',
                 'metering_label_id': 'c5df2fe5-c600-4a2a-b2f4-c0fb6df73c83',
                 'remote_ip_prefix': '10.0.0.0/24'}]
             }],
            'admin_state_up': True,
            'gw_port_id': '7d411f48-ecc7-45e0-9ece-3b5bdb54fcee',
            'id': '473ec392-1711-44e3-b008-3251ccfc5099',
            'name': 'router1',
            'status': 'ACTIVE',
            'tenant_id': '6c5f5d2a1fa2441e88e35422926f48e8'}]

        self.metering.update_metering_label_rules(None, routers)
        calls = [call.add_chain('neutron-meter-l-c5df2fe5-c60', wrap=False),
                 call.add_chain('neutron-meter-r-c5df2fe5-c60', wrap=False),
                 call.add_rule('neutron-meter-FORWARD', '-j '
                               'neutron-meter-r-c5df2fe5-c60', wrap=False),
                 call.add_rule('neutron-meter-l-c5df2fe5-c60',
                               '',
                               wrap=False),
                 call.add_rule('neutron-meter-r-c5df2fe5-c60',
                               '-i qg-7d411f48-ec -d 10.0.0.0/24'
                               ' -j neutron-meter-l-c5df2fe5-c60',
                               wrap=False, top=False),
                 call.add_rule('neutron-meter-r-c5df2fe5-c60',
                               '-i qg-7d411f48-ec -d 20.0.0.0/24'
                               ' -j neutron-meter-l-c5df2fe5-c60',
                               wrap=False, top=False),
                 call.empty_chain('neutron-meter-r-c5df2fe5-c60', wrap=False),
                 call.add_rule('neutron-meter-r-c5df2fe5-c60',
                               '-i qg-7d411f48-ec -d 10.0.0.0/24'
                               ' -j neutron-meter-l-c5df2fe5-c60',
                               wrap=False, top=False)]

        self.v4filter_inst.assert_has_calls(calls)

    def test_remove_metering_label(self):
        routers = [{'_metering_labels': [
            {'id': 'c5df2fe5-c600-4a2a-b2f4-c0fb6df73c83',
             'rules': [{
                 'direction': 'ingress',
                 'excluded': False,
                 'id': '7f1a261f-2489-4ed1-870c-a62754501379',
                 'metering_label_id': 'c5df2fe5-c600-4a2a-b2f4-c0fb6df73c83',
                 'remote_ip_prefix': '10.0.0.0/24'}]
             }],
            'admin_state_up': True,
            'gw_port_id': '7d411f48-ecc7-45e0-9ece-3b5bdb54fcee',
            'id': '473ec392-1711-44e3-b008-3251ccfc5099',
            'name': 'router1',
            'status': 'ACTIVE',
            'tenant_id': '6c5f5d2a1fa2441e88e35422926f48e8'}]

        self.metering.add_metering_label(None, routers)
        self.metering.remove_metering_label(None, routers)
        calls = [call.add_chain('neutron-meter-l-c5df2fe5-c60', wrap=False),
                 call.add_chain('neutron-meter-r-c5df2fe5-c60', wrap=False),
                 call.add_rule('neutron-meter-FORWARD', '-j '
                               'neutron-meter-r-c5df2fe5-c60', wrap=False),
                 call.add_rule('neutron-meter-l-c5df2fe5-c60',
                               '',
                               wrap=False),
                 call.add_rule('neutron-meter-r-c5df2fe5-c60',
                               '-i qg-7d411f48-ec -d 10.0.0.0/24'
                               ' -j neutron-meter-l-c5df2fe5-c60',
                               wrap=False, top=False),
                 call.remove_chain('neutron-meter-l-c5df2fe5-c60', wrap=False),
                 call.remove_chain('neutron-meter-r-c5df2fe5-c60', wrap=False)]

        self.v4filter_inst.assert_has_calls(calls)

    def test_update_routers(self):
        routers = [{'_metering_labels': [
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
            'status': 'ACTIVE',
            'tenant_id': '6c5f5d2a1fa2441e88e35422926f48e8'},
            {'_metering_labels': [
             {'id': 'eeef45da-c600-4a2a-b2f4-c0fb6df73c83',
              'rules': [{
                  'direction': 'ingress',
                  'excluded': True,
                  'id': 'fa2441e8-2489-4ed1-870c-a62754501379',
                  'metering_label_id': 'eeef45da-c600-4a2a-b2f4-c0fb6df73c83',
                  'remote_ip_prefix': '20.0.0.0/24'}]}],
             'admin_state_up': True,
             'gw_port_id': '7d411f48-ecc7-45e0-9ece-3b5bdb54fcee',
             'id': '373ec392-1711-44e3-b008-3251ccfc5099',
             'name': 'router2',
             'status': 'ACTIVE',
             'tenant_id': '6c5f5d2a1fa2441e88e35422926f48e8'}]

        self.metering.add_metering_label(None, routers)

        updates = copy.deepcopy(routers)
        updates[0]['gw_port_id'] = '587b63c1-22a3-40b3-9834-486d1fb215a5'

        self.metering.update_routers(None, updates)
        calls = [call.add_chain('neutron-meter-l-c5df2fe5-c60', wrap=False),
                 call.add_chain('neutron-meter-r-c5df2fe5-c60', wrap=False),
                 call.add_rule('neutron-meter-FORWARD', '-j '
                               'neutron-meter-r-c5df2fe5-c60', wrap=False),
                 call.add_rule('neutron-meter-l-c5df2fe5-c60',
                               '',
                               wrap=False),
                 call.add_rule('neutron-meter-r-c5df2fe5-c60',
                               '-i qg-6d411f48-ec -d 10.0.0.0/24'
                               ' -j neutron-meter-l-c5df2fe5-c60',
                               wrap=False, top=False),
                 call.add_chain('neutron-meter-l-eeef45da-c60', wrap=False),
                 call.add_chain('neutron-meter-r-eeef45da-c60', wrap=False),
                 call.add_rule('neutron-meter-FORWARD', '-j '
                               'neutron-meter-r-eeef45da-c60', wrap=False),
                 call.add_rule('neutron-meter-l-eeef45da-c60',
                               '',
                               wrap=False),
                 call.add_rule('neutron-meter-r-eeef45da-c60',
                               '-i qg-7d411f48-ec -d 20.0.0.0/24 -j RETURN',
                               wrap=False, top=True),
                 call.remove_chain('neutron-meter-l-c5df2fe5-c60', wrap=False),
                 call.remove_chain('neutron-meter-r-c5df2fe5-c60', wrap=False),
                 call.add_chain('neutron-meter-l-c5df2fe5-c60', wrap=False),
                 call.add_chain('neutron-meter-r-c5df2fe5-c60', wrap=False),
                 call.add_rule('neutron-meter-FORWARD', '-j '
                               'neutron-meter-r-c5df2fe5-c60', wrap=False),
                 call.add_rule('neutron-meter-l-c5df2fe5-c60',
                               '',
                               wrap=False),
                 call.add_rule('neutron-meter-r-c5df2fe5-c60',
                               '-i qg-587b63c1-22 -d 10.0.0.0/24'
                               ' -j neutron-meter-l-c5df2fe5-c60',
                               wrap=False, top=False)]

        self.v4filter_inst.assert_has_calls(calls)
