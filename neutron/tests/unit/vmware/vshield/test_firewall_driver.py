# Copyright 2013 VMware, Inc
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

import contextlib
import mock
import webob.exc

from neutron import context
from neutron.db.firewall import firewall_db
from neutron.openstack.common import uuidutils
from neutron.plugins.vmware.vshield.common import exceptions as vcns_exc
from neutron.plugins.vmware.vshield import vcns_driver
from neutron.tests.unit.db.firewall import test_db_firewall
from neutron.tests.unit import vmware
from neutron.tests.unit.vmware.vshield import fake_vcns


_uuid = uuidutils.generate_uuid

VSE_ID = 'edge-1'
ROUTER_ID = '42f95450-5cc9-44e4-a744-1320e592a9d5'

VCNS_CONFIG_FILE = vmware.get_fake_conf("vcns.ini.test")


class VcnsDriverTestCase(test_db_firewall.FirewallPluginDbTestCase,
                         firewall_db.Firewall_db_mixin):

    def vcns_firewall_patch(self):
        instance = self.mock_vcns.start()
        instance.return_value.update_firewall.side_effect = (
            self.fc2.update_firewall)
        instance.return_value.delete_firewall.side_effect = (
            self.fc2.delete_firewall)
        instance.return_value.update_firewall_rule.side_effect = (
            self.fc2.update_firewall_rule)
        instance.return_value.delete_firewall_rule.side_effect = (
            self.fc2.delete_firewall_rule)
        instance.return_value.add_firewall_rule_above.side_effect = (
            self.fc2.add_firewall_rule_above)
        instance.return_value.add_firewall_rule.side_effect = (
            self.fc2.add_firewall_rule)
        instance.return_value.get_firewall.side_effect = (
            self.fc2.get_firewall)
        instance.return_value.get_firewall_rule.side_effect = (
            self.fc2.get_firewall_rule)

    def setUp(self):

        self.config_parse(args=['--config-file', VCNS_CONFIG_FILE])
        # mock vcns
        self.fc2 = fake_vcns.FakeVcns(unique_router_name=False)
        self.mock_vcns = mock.patch(vmware.VCNS_NAME, autospec=True)
        self.vcns_firewall_patch()

        self.driver = vcns_driver.VcnsDriver(mock.Mock())

        super(VcnsDriverTestCase, self).setUp()
        self.addCleanup(self.fc2.reset_all)
        self.addCleanup(self.mock_vcns.stop)

        self.tenant_id = _uuid()
        self.subnet_id = _uuid()


class TestEdgeFwDriver(VcnsDriverTestCase):

    def _make_firewall_dict_with_rules(self, context, firewall_id):
        fw = self.get_firewall(context, firewall_id)
        fw_policy_id = fw['firewall_policy_id']
        if fw_policy_id:
            firewall_policy_db = self._get_firewall_policy(
                context, fw_policy_id)
            fw['firewall_rule_list'] = [
                self._make_firewall_rule_dict(fw_rule_db)
                for fw_rule_db in firewall_policy_db['firewall_rules']
            ]

        return fw

    def _compare_firewall_rule_lists(self, firewall_policy_id,
                                     list1, list2):
        for r1, r2 in zip(list1, list2):
            rule = r1['firewall_rule']
            rule['firewall_policy_id'] = firewall_policy_id
            for k in rule:
                self.assertEqual(rule[k], r2[k])

    def test_create_and_get_firewall(self):
        ctx = context.get_admin_context()
        name = 'firewall'
        with contextlib.nested(self.firewall_rule(name='fwr1',
                                                  do_delete=False),
                               self.firewall_rule(name='fwr2',
                                                  do_delete=False),
                               self.firewall_rule(name='fwr3',
                                                  do_delete=False)) as fr:
            fw_rule_ids = [r['firewall_rule']['id'] for r in fr]
            with self.firewall_policy(firewall_rules=fw_rule_ids,
                                      do_delete=False) as fwp:
                fwp_id = fwp['firewall_policy']['id']
                with self.firewall(name=name,
                                   firewall_policy_id=fwp_id) as firewall:
                    fw_create = firewall['firewall']
                    fw_expect = self._make_firewall_dict_with_rules(
                        ctx, fw_create['id'])
                    self.driver.update_firewall(ctx, VSE_ID, fw_expect)
                    fw_get = self.driver.get_firewall(ctx, VSE_ID)
                    self._compare_firewall_rule_lists(
                        fwp_id, fw_get['firewall_rule_list'],
                        fw_expect['firewall_rule_list'])

    def test_update_firewall_with_rules(self):
        ctx = context.get_admin_context()
        name = 'new_firewall'
        with contextlib.nested(self.firewall_rule(name='fwr1',
                                                  do_delete=False),
                               self.firewall_rule(name='fwr2',
                                                  do_delete=False),
                               self.firewall_rule(name='fwr3',
                                                  do_delete=False)) as fr:
            fw_rule_ids = [r['firewall_rule']['id'] for r in fr]
            with self.firewall_policy(firewall_rules=fw_rule_ids,
                                      do_delete=False) as fwp:
                fwp_id = fwp['firewall_policy']['id']
                with self.firewall(name=name,
                                   firewall_policy_id=fwp_id) as firewall:
                    fw_create = firewall['firewall']
                    fw_create = self._make_firewall_dict_with_rules(
                        ctx, fw_create['id'])
                    self.driver.update_firewall(ctx, VSE_ID, fw_create)

                    data = {'firewall_rule': {'name': name,
                                              'source_port': '10:20',
                                              'destination_port': '30:40'}}
                    self.new_update_request('firewall_rules', data,
                                            fr[0]['firewall_rule']['id'])
                    fw_expect = self._make_firewall_dict_with_rules(
                        ctx, fw_create['id'])
                    self.driver.update_firewall(ctx, VSE_ID, fw_expect)

                    fw_get = self.driver.get_firewall(
                        ctx, VSE_ID)
                    self._compare_firewall_rule_lists(
                        fwp_id, fw_get['firewall_rule_list'],
                        fw_expect['firewall_rule_list'])

    def test_delete_firewall(self):
        ctx = context.get_admin_context()
        name = 'firewall'
        with contextlib.nested(self.firewall_rule(name='fwr1',
                                                  do_delete=False),
                               self.firewall_rule(name='fwr2',
                                                  do_delete=False),
                               self.firewall_rule(name='fwr3',
                                                  do_delete=False)) as fr:
            fw_rule_ids = [r['firewall_rule']['id'] for r in fr]
            with self.firewall_policy(firewall_rules=fw_rule_ids,
                                      do_delete=False) as fwp:
                fwp_id = fwp['firewall_policy']['id']
                with self.firewall(name=name,
                                   firewall_policy_id=fwp_id) as firewall:
                    fw_create = firewall['firewall']
                    fw_expect = self._make_firewall_dict_with_rules(
                        ctx, fw_create['id'])
                    self.driver.update_firewall(ctx, VSE_ID, fw_expect)
                    self.driver.delete_firewall(ctx, VSE_ID)
                    fw_get = self.driver.get_firewall(
                        ctx, VSE_ID)
                    self.assertFalse(fw_get['firewall_rule_list'])

    def test_update_firewall_rule(self):
        ctx = context.get_admin_context()
        name = 'new_firewall'
        with contextlib.nested(self.firewall_rule(name='fwr1',
                                                  do_delete=False)) as fr:
            fw_rule_ids = [r['firewall_rule']['id'] for r in fr]
            with self.firewall_policy(firewall_rules=fw_rule_ids,
                                      do_delete=False) as fwp:
                fwp_id = fwp['firewall_policy']['id']
                with self.firewall(name=name,
                                   firewall_policy_id=fwp_id) as firewall:
                    fw_create = firewall['firewall']
                    fw_create = self._make_firewall_dict_with_rules(
                        ctx, fw_create['id'])
                    self.driver.update_firewall(ctx, VSE_ID, fw_create)

                    data = {'firewall_rule': {'name': name,
                                              'source_port': '10:20',
                                              'destination_port': '30:40'}}
                    req = self.new_update_request(
                        'firewall_rules', data,
                        fr[0]['firewall_rule']['id'])
                    res = self.deserialize(self.fmt,
                                           req.get_response(self.ext_api))
                    rule_expect = res['firewall_rule']
                    rule_expect['edge_id'] = VSE_ID
                    self.driver.update_firewall_rule(
                        ctx, rule_expect['id'], VSE_ID, rule_expect)
                    rule_get = self.driver.get_firewall_rule(
                        ctx, rule_expect['id'], VSE_ID)
                    for k, v in rule_get['firewall_rule'].items():
                        self.assertEqual(rule_expect[k], v)

    def test_delete_firewall_rule(self):
        ctx = context.get_admin_context()
        name = 'new_firewall'
        with contextlib.nested(self.firewall_rule(name='fwr1',
                                                  do_delete=False),
                               self.firewall_rule(name='fwr2',
                                                  do_delete=False)) as fr:
            fw_rule_ids = [r['firewall_rule']['id'] for r in fr]
            with self.firewall_policy(firewall_rules=fw_rule_ids,
                                      do_delete=False) as fwp:
                fwp_id = fwp['firewall_policy']['id']
                with self.firewall(name=name,
                                   firewall_policy_id=fwp_id) as firewall:
                    fw_create = firewall['firewall']
                    fw_create = self._make_firewall_dict_with_rules(
                        ctx, fw_create['id'])
                    self.driver.update_firewall(ctx, VSE_ID, fw_create)

                    fr[0]['firewall_rule']['edge_id'] = VSE_ID
                    self.driver.delete_firewall_rule(
                        ctx, fr[0]['firewall_rule']['id'],
                        VSE_ID)
                    self.assertRaises(vcns_exc.VcnsNotFound,
                                      self.driver.get_firewall_rule,
                                      ctx, fr[0]['firewall_rule']['id'],
                                      VSE_ID)

    def test_insert_rule(self):
        ctx = context.get_admin_context()
        with self.firewall_policy() as fwp:
            fwp_id = fwp['firewall_policy']['id']
            with self.firewall(firewall_policy_id=fwp_id) as firewall:
                fw_create = firewall['firewall']
                fw_create = self._make_firewall_dict_with_rules(
                    ctx, fw_create['id'])
                self.driver.update_firewall(ctx, VSE_ID, fw_create)
                with contextlib.nested(self.firewall_rule(name='fwr0',
                                                          do_delete=False),
                                       self.firewall_rule(name='fwr1',
                                                          do_delete=False),
                                       self.firewall_rule(name='fwr2',
                                                          do_delete=False),
                                       self.firewall_rule(name='fwr3',
                                                          do_delete=False),
                                       self.firewall_rule(name='fwr4',
                                                          do_delete=False),
                                       self.firewall_rule(name='fwr5',
                                                          do_delete=False),
                                       self.firewall_rule(
                                           name='fwr6',
                                           do_delete=False)) as fwr:
                    # test insert when rule list is empty
                    fwr0_id = fwr[0]['firewall_rule']['id']
                    self._rule_action('insert', fwp_id, fwr0_id,
                                      insert_before=None,
                                      insert_after=None,
                                      expected_code=webob.exc.HTTPOk.code)
                    fw_update = self._make_firewall_dict_with_rules(
                        ctx, fw_create['id'])
                    self.driver.update_firewall(ctx, VSE_ID, fw_update)
                    # test insert at top of list above existing rule
                    fwr1_id = fwr[1]['firewall_rule']['id']
                    self._rule_action('insert', fwp_id, fwr1_id,
                                      insert_before=fwr0_id,
                                      insert_after=None,
                                      expected_code=webob.exc.HTTPOk.code)

                    fw_expect = self._make_firewall_dict_with_rules(
                        ctx, fw_create['id'])

                    rule_info = {'firewall_rule_id': fwr1_id,
                                 'insert_before': fwr0_id,
                                 'insert_after': None}
                    rule = fwr[1]['firewall_rule']
                    self.driver.insert_rule(ctx, rule_info, VSE_ID, rule)
                    fw_get = self.driver.get_firewall(
                        ctx, VSE_ID)
                    self._compare_firewall_rule_lists(
                        fwp_id, fw_get['firewall_rule_list'],
                        fw_expect['firewall_rule_list'])
                    # test insert at bottom of list
                    fwr2_id = fwr[2]['firewall_rule']['id']
                    self._rule_action('insert', fwp_id, fwr2_id,
                                      insert_before=None,
                                      insert_after=fwr0_id,
                                      expected_code=webob.exc.HTTPOk.code)
                    fw_expect = self._make_firewall_dict_with_rules(
                        ctx, fw_create['id'])

                    rule_info = {'firewall_rule_id': fwr2_id,
                                 'insert_before': None,
                                 'insert_after': fwr0_id}
                    rule = fwr[2]['firewall_rule']
                    self.driver.insert_rule(ctx, rule_info, VSE_ID, rule)
                    fw_get = self.driver.get_firewall(
                        ctx, VSE_ID)
                    self._compare_firewall_rule_lists(
                        fwp_id, fw_get['firewall_rule_list'],
                        fw_expect['firewall_rule_list'])
                    # test insert in the middle of the list using
                    # insert_before
                    fwr3_id = fwr[3]['firewall_rule']['id']
                    self._rule_action('insert', fwp_id, fwr3_id,
                                      insert_before=fwr2_id,
                                      insert_after=None,
                                      expected_code=webob.exc.HTTPOk.code)
                    fw_expect = self._make_firewall_dict_with_rules(
                        ctx, fw_create['id'])

                    rule_info = {'firewall_rule_id': fwr3_id,
                                 'insert_before': fwr2_id,
                                 'insert_after': None}
                    rule = fwr[3]['firewall_rule']
                    self.driver.insert_rule(ctx, rule_info, VSE_ID, rule)
                    fw_get = self.driver.get_firewall(
                        ctx, VSE_ID)
                    self._compare_firewall_rule_lists(
                        fwp_id, fw_get['firewall_rule_list'],
                        fw_expect['firewall_rule_list'])
                    # test insert in the middle of the list using
                    # insert_after
                    fwr4_id = fwr[4]['firewall_rule']['id']
                    self._rule_action('insert', fwp_id, fwr4_id,
                                      insert_before=None,
                                      insert_after=fwr3_id,
                                      expected_code=webob.exc.HTTPOk.code)
                    fw_expect = self._make_firewall_dict_with_rules(
                        ctx, fw_create['id'])

                    rule_info = {'firewall_rule_id': fwr4_id,
                                 'insert_before': None,
                                 'insert_after': fwr3_id}
                    rule = fwr[4]['firewall_rule']
                    self.driver.insert_rule(ctx, rule_info, VSE_ID, rule)
                    fw_get = self.driver.get_firewall(
                        ctx, VSE_ID)
                    self._compare_firewall_rule_lists(
                        fwp_id, fw_get['firewall_rule_list'],
                        fw_expect['firewall_rule_list'])
                    # test insert when both insert_before and
                    # insert_after are set
                    fwr5_id = fwr[5]['firewall_rule']['id']
                    self._rule_action('insert', fwp_id, fwr5_id,
                                      insert_before=fwr4_id,
                                      insert_after=fwr4_id,
                                      expected_code=webob.exc.HTTPOk.code)
                    fw_expect = self._make_firewall_dict_with_rules(
                        ctx, fw_create['id'])

                    rule_info = {'firewall_rule_id': fwr5_id,
                                 'insert_before': fwr4_id,
                                 'insert_after': fwr4_id}
                    rule = fwr[5]['firewall_rule']
                    self.driver.insert_rule(ctx, rule_info, VSE_ID, rule)
                    fw_get = self.driver.get_firewall(
                        ctx, VSE_ID)
                    self._compare_firewall_rule_lists(
                        fwp_id, fw_get['firewall_rule_list'],
                        fw_expect['firewall_rule_list'])
