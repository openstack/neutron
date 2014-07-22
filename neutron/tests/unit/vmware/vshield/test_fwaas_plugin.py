# Copyright 2013 VMware, Inc
# All Rights Reserved
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
import copy
import webob.exc

from neutron.api.v2 import attributes
from neutron import context
from neutron.extensions import firewall
from neutron import manager
from neutron.openstack.common import uuidutils
from neutron.plugins.common import constants as const
from neutron.tests.unit.db.firewall import test_db_firewall
from neutron.tests.unit.vmware.vshield import test_edge_router

_uuid = uuidutils.generate_uuid

FW_PLUGIN_CLASS = "neutron.plugins.vmware.plugin.NsxServicePlugin"


class FirewallTestExtensionManager(
        test_edge_router.ServiceRouterTestExtensionManager):

    def get_resources(self):
        # If l3 resources have been loaded and updated by main API
        # router, update the map in the l3 extension so it will load
        # the same attributes as the API router
        resources = super(FirewallTestExtensionManager, self).get_resources()
        firewall_attr_map = copy.deepcopy(firewall.RESOURCE_ATTRIBUTE_MAP)
        for res in firewall.RESOURCE_ATTRIBUTE_MAP.keys():
            attr_info = attributes.RESOURCE_ATTRIBUTE_MAP.get(res)
            if attr_info:
                firewall.RESOURCE_ATTRIBUTE_MAP[res] = attr_info
        fw_resources = firewall.Firewall.get_resources()
        # restore the original resources once the controllers are created
        firewall.RESOURCE_ATTRIBUTE_MAP = firewall_attr_map

        resources.extend(fw_resources)

        return resources

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


class FirewallPluginTestCase(test_db_firewall.FirewallPluginDbTestCase,
                             test_edge_router.ServiceRouterTest):

    def vcns_firewall_patch(self):
        self.vcns_instance.return_value.update_firewall.side_effect = (
            self.fc2.update_firewall)
        self.vcns_instance.return_value.delete_firewall.side_effect = (
            self.fc2.delete_firewall)
        self.vcns_instance.return_value.update_firewall_rule.side_effect = (
            self.fc2.update_firewall_rule)
        self.vcns_instance.return_value.delete_firewall_rule.side_effect = (
            self.fc2.delete_firewall_rule)
        self.vcns_instance.return_value.add_firewall_rule_above.side_effect = (
            self.fc2.add_firewall_rule_above)
        self.vcns_instance.return_value.add_firewall_rule.side_effect = (
            self.fc2.add_firewall_rule)
        self.vcns_instance.return_value.get_firewall.side_effect = (
            self.fc2.get_firewall)
        self.vcns_instance.return_value.get_firewall_rule.side_effect = (
            self.fc2.get_firewall_rule)

    def setUp(self):
        # Save the global RESOURCE_ATTRIBUTE_MAP
        self.saved_attr_map = {}
        for resource, attrs in attributes.RESOURCE_ATTRIBUTE_MAP.iteritems():
            self.saved_attr_map[resource] = attrs.copy()

        super(FirewallPluginTestCase, self).setUp(
            ext_mgr=FirewallTestExtensionManager(),
            fw_plugin=FW_PLUGIN_CLASS)
        self.vcns_firewall_patch()
        self.plugin = manager.NeutronManager.get_plugin()

    def tearDown(self):
        super(FirewallPluginTestCase, self).tearDown()
        # Restore the global RESOURCE_ATTRIBUTE_MAP
        attributes.RESOURCE_ATTRIBUTE_MAP = self.saved_attr_map
        self.ext_api = None
        self.plugin = None

    def _create_and_get_router(self):
        req = self._create_router(self.fmt, self._tenant_id)
        res = self.deserialize(self.fmt, req)
        return res['router']['id']

    def _create_firewall(self, fmt, name, description, firewall_policy_id,
                         admin_state_up=True, expected_res_status=None,
                         **kwargs):
        data = {'firewall': {'name': name,
                             'description': description,
                             'firewall_policy_id': firewall_policy_id,
                             'router_id': kwargs.get('router_id'),
                             'admin_state_up': admin_state_up,
                             'tenant_id': self._tenant_id}}

        firewall_req = self.new_create_request('firewalls', data, fmt)
        firewall_res = firewall_req.get_response(self.ext_api)
        if expected_res_status:
            self.assertEqual(firewall_res.status_int, expected_res_status)

        return firewall_res

    def test_create_firewall(self):
        name = "new_fw"
        attrs = self._get_test_firewall_attrs(name)

        with self.firewall_policy() as fwp:
            fwp_id = fwp['firewall_policy']['id']
            attrs['firewall_policy_id'] = fwp_id
            attrs['router_id'] = self._create_and_get_router()
            with self.firewall(name=name,
                               firewall_policy_id=fwp_id,
                               router_id=attrs['router_id'],
                               admin_state_up=
                               test_db_firewall.ADMIN_STATE_UP,
                               expected_res_status=201) as fw:
                attrs = self._replace_firewall_status(
                    attrs, const.PENDING_CREATE, const.ACTIVE)
                for k, v in attrs.iteritems():
                    self.assertEqual(fw['firewall'][k], v)

    def test_create_firewall_without_policy(self):
        name = "new_fw"
        attrs = self._get_test_firewall_attrs(name)
        attrs['router_id'] = self._create_and_get_router()

        with self.firewall(name=name,
                           router_id=attrs['router_id'],
                           admin_state_up=
                           test_db_firewall.ADMIN_STATE_UP,
                           expected_res_status=201) as fw:
            attrs = self._replace_firewall_status(
                attrs, const.PENDING_CREATE, const.ACTIVE)
            for k, v in attrs.iteritems():
                self.assertEqual(fw['firewall'][k], v)

    def test_update_firewall(self):
        name = "new_fw"
        attrs = self._get_test_firewall_attrs(name)
        attrs['router_id'] = self._create_and_get_router()

        with self.firewall_policy() as fwp:
            fwp_id = fwp['firewall_policy']['id']
            attrs['firewall_policy_id'] = fwp_id
            with self.firewall(
                firewall_policy_id=fwp_id, router_id=attrs['router_id'],
                admin_state_up=test_db_firewall.ADMIN_STATE_UP) as fw:
                fw_id = fw['firewall']['id']
                new_data = {'firewall': {'name': name}}
                req = self.new_update_request('firewalls', new_data, fw_id)
                res = req.get_response(self.ext_api)
                self.assertEqual(res.status_int, 200)
                res_json = self.deserialize(
                    self.fmt, res)
                attrs = self._replace_firewall_status(
                    attrs, const.PENDING_CREATE, const.ACTIVE)
                for k, v in attrs.iteritems():
                    self.assertEqual(res_json['firewall'][k], v)

    def test_delete_firewall(self):
        ctx = context.get_admin_context()
        with self.firewall_policy() as fwp:
            fwp_id = fwp['firewall_policy']['id']
            with self.firewall(
                firewall_policy_id=fwp_id,
                router_id=self._create_and_get_router(),
                admin_state_up=test_db_firewall.ADMIN_STATE_UP,
                do_delete=False) as fw:
                fw_id = fw['firewall']['id']
                with ctx.session.begin(subtransactions=True):
                    req = self.new_delete_request('firewalls', fw_id)
                    res = req.get_response(self.ext_api)
                    self.assertEqual(res.status_int, 204)
                    self.assertRaises(
                        firewall.FirewallNotFound,
                        self.plugin.get_firewall, ctx, fw_id)

    def test_delete_router_in_use_by_fwservice(self):
        router_id = self._create_and_get_router()
        with self.firewall_policy() as fwp:
            fwp_id = fwp['firewall_policy']['id']
            with self.firewall(name='fw',
                               firewall_policy_id=fwp_id,
                               router_id=router_id,
                               admin_state_up=
                               test_db_firewall.ADMIN_STATE_UP,
                               expected_res_status=201):
                self._delete('routers', router_id,
                             expected_code=webob.exc.HTTPConflict.code)

    def test_show_firewall(self):
        name = "firewall1"
        attrs = self._get_test_firewall_attrs(name)
        attrs['router_id'] = self._create_and_get_router()

        with self.firewall_policy() as fwp:
            fwp_id = fwp['firewall_policy']['id']
            attrs['firewall_policy_id'] = fwp_id
            with self.firewall(
                name=name,
                firewall_policy_id=fwp_id, router_id=attrs['router_id'],
                admin_state_up=test_db_firewall.ADMIN_STATE_UP) as firewall:

                req = self.new_show_request('firewalls',
                                            firewall['firewall']['id'],
                                            fmt=self.fmt)
                res = self.deserialize(self.fmt,
                                       req.get_response(self.ext_api))
                attrs = self._replace_firewall_status(
                    attrs, const.PENDING_CREATE, const.ACTIVE)
                for k, v in attrs.iteritems():
                    self.assertEqual(res['firewall'][k], v)

    def test_list_firewalls(self):
        keys_list = []
        for i in range(3):
            keys_list.append({'name': "fw" + str(i),
                              'router_id': self._create_and_get_router(),
                              'admin_state_up': True,
                              'status': "ACTIVE"})

        with contextlib.nested(
            self.firewall(
                name='fw0', router_id=keys_list[0]['router_id'],
                admin_state_up=True, description='fw'),
            self.firewall(
                name='fw1', router_id=keys_list[1]['router_id'],
                admin_state_up=True, description='fw'),
            self.firewall(
                name='fw2', router_id=keys_list[2]['router_id'],
                admin_state_up=True, description='fw'),
        ) as (fw1, fw2, fw3):
            self._test_list_resources(
                'firewall', (fw1, fw2, fw3),
                query_params='description=fw')

            req = self.new_list_request('firewalls')
            res = self.deserialize(
                self.fmt, req.get_response(self.ext_api))
            self.assertEqual(len(res['firewalls']), 3)
            for index in range(len(res['firewalls'])):
                for k, v in keys_list[index].items():
                    self.assertEqual(res['firewalls'][index][k], v)

    def test_create_firewall_with_rules(self):
        ctx = context.get_admin_context()
        with contextlib.nested(self.firewall_rule(name='fwr1'),
                               self.firewall_rule(name='fwr2'),
                               self.firewall_rule(name='fwr3')) as fr:
            with self.firewall_policy() as fwp:
                fwp_id = fwp['firewall_policy']['id']
                fw_rule_ids = [r['firewall_rule']['id'] for r in fr]
                data = {'firewall_policy':
                        {'firewall_rules': fw_rule_ids}}
                req = self.new_update_request(
                    'firewall_policies', data, fwp_id)
                req.get_response(self.ext_api)
                attrs = self._get_test_firewall_attrs()
                attrs['firewall_policy_id'] = fwp_id
                with self.firewall(
                    firewall_policy_id=fwp_id,
                    router_id=self._create_and_get_router(),
                    admin_state_up=test_db_firewall.ADMIN_STATE_UP) as fw:
                    rule_list = (
                        self.plugin._make_firewall_rule_list_by_policy_id(
                            ctx, fw['firewall']['firewall_policy_id']))
                    self._compare_firewall_rule_lists(
                        fwp_id, fr, rule_list)

    def test_update_firewall_policy_with_no_firewall(self):
        name = "new_firewall_policy1"
        attrs = self._get_test_firewall_policy_attrs(name, audited=False)

        with self.firewall_policy(shared=test_db_firewall.SHARED,
                                  firewall_rules=None,
                                  audited=test_db_firewall.AUDITED) as fwp:
            data = {'firewall_policy': {'name': name}}
            req = self.new_update_request('firewall_policies', data,
                                          fwp['firewall_policy']['id'])
            res = self.deserialize(self.fmt, req.get_response(self.ext_api))
            for k, v in attrs.iteritems():
                self.assertEqual(res['firewall_policy'][k], v)

    def test_update_firewall_policy_with_firewall(self):
        name = "new_firewall_policy1"
        attrs = self._get_test_firewall_policy_attrs(name, audited=False)

        with self.firewall_policy(shared=test_db_firewall.SHARED,
                                  firewall_rules=None,
                                  audited=test_db_firewall.AUDITED) as fwp:
            fwp_id = fwp['firewall_policy']['id']
            with self.firewall(firewall_policy_id=fwp_id,
                               router_id=self._create_and_get_router(),
                               admin_state_up=
                               test_db_firewall.ADMIN_STATE_UP):
                data = {'firewall_policy': {'name': name}}
                req = self.new_update_request(
                    'firewall_policies', data, fwp['firewall_policy']['id'])
                res = self.deserialize(
                    self.fmt, req.get_response(self.ext_api))
                for k, v in attrs.iteritems():
                    self.assertEqual(res['firewall_policy'][k], v)

    def test_update_firewall_rule_with_no_firewall(self):
        name = "new_firewall_rule1"
        attrs = self._get_test_firewall_rule_attrs(name)

        attrs['source_port'] = '10:20'
        attrs['destination_port'] = '30:40'
        with self.firewall_rule() as fwr:
            data = {'firewall_rule': {'name': name,
                                      'source_port': '10:20',
                                      'destination_port': '30:40'}}
            req = self.new_update_request(
                'firewall_rules', data, fwr['firewall_rule']['id'])
            res = self.deserialize(
                self.fmt, req.get_response(self.ext_api))
            for k, v in attrs.iteritems():
                self.assertEqual(res['firewall_rule'][k], v)

        attrs['source_port'] = '10000'
        attrs['destination_port'] = '80'
        with self.firewall_rule() as fwr:
            data = {'firewall_rule': {'name': name,
                                      'source_port': 10000,
                                      'destination_port': 80}}
            req = self.new_update_request('firewall_rules', data,
                                          fwr['firewall_rule']['id'])
            res = self.deserialize(self.fmt, req.get_response(self.ext_api))
            for k, v in attrs.iteritems():
                self.assertEqual(res['firewall_rule'][k], v)

        attrs['source_port'] = None
        attrs['destination_port'] = None
        with self.firewall_rule() as fwr:
            data = {'firewall_rule': {'name': name,
                                      'source_port': None,
                                      'destination_port': None}}
            req = self.new_update_request(
                'firewall_rules', data, fwr['firewall_rule']['id'])
            res = self.deserialize(
                self.fmt, req.get_response(self.ext_api))
            for k, v in attrs.iteritems():
                self.assertEqual(res['firewall_rule'][k], v)

    def test_update_firewall_rule_with_firewall(self):
        name = "new_firewall_rule1"
        attrs = self._get_test_firewall_rule_attrs(name)
        with self.firewall_rule() as fwr:
            with self.firewall_policy() as fwp:
                fwp_id = fwp['firewall_policy']['id']
                attrs['firewall_policy_id'] = fwp_id
                with self.firewall(firewall_policy_id=fwp_id,
                                   router_id=self._create_and_get_router(),
                                   admin_state_up=
                                   test_db_firewall.ADMIN_STATE_UP):
                    fwr_id = fwr['firewall_rule']['id']
                    data = {'firewall_policy': {'firewall_rules': [fwr_id]}}
                    req = self.new_update_request(
                        'firewall_policies', data,
                        fwp['firewall_policy']['id'])
                    req.get_response(self.ext_api)
                    data = {'firewall_rule': {'name': name}}
                    req = self.new_update_request(
                        'firewall_rules', data,
                        fwr['firewall_rule']['id'])
                    res = self.deserialize(
                        self.fmt, req.get_response(self.ext_api))
                    attrs['firewall_policy_id'] = fwp_id
                    for k, v in attrs.iteritems():
                        self.assertEqual(res['firewall_rule'][k], v)

    def test_insert_rule_with_no_firewall(self):
        attrs = self._get_test_firewall_policy_attrs()
        attrs['audited'] = False
        attrs['firewall_list'] = []
        with contextlib.nested(self.firewall_rule(name='fwr0'),
                               self.firewall_rule(name='fwr1'),
                               self.firewall_rule(name='fwr2'),
                               self.firewall_rule(name='fwr3'),
                               self.firewall_rule(name='fwr4'),
                               self.firewall_rule(name='fwr5'),
                               self.firewall_rule(name='fwr6')) as fwr:
            with self.firewall_policy() as fwp:
                fwp_id = fwp['firewall_policy']['id']
                attrs['id'] = fwp_id
                # test insert when rule list is empty
                fwr0_id = fwr[0]['firewall_rule']['id']
                attrs['firewall_rules'].insert(0, fwr0_id)
                self._rule_action('insert', fwp_id, fwr0_id,
                                  insert_before=None,
                                  insert_after=None,
                                  expected_code=webob.exc.HTTPOk.code,
                                  expected_body=attrs)
                # test insert at top of rule list, insert_before and
                # insert_after not provided
                fwr1_id = fwr[1]['firewall_rule']['id']
                attrs['firewall_rules'].insert(0, fwr1_id)
                insert_data = {'firewall_rule_id': fwr1_id}
                self._rule_action('insert', fwp_id, fwr0_id,
                                  expected_code=webob.exc.HTTPOk.code,
                                  expected_body=attrs, body_data=insert_data)
                # test insert at top of list above existing rule
                fwr2_id = fwr[2]['firewall_rule']['id']
                attrs['firewall_rules'].insert(0, fwr2_id)
                self._rule_action('insert', fwp_id, fwr2_id,
                                  insert_before=fwr1_id,
                                  insert_after=None,
                                  expected_code=webob.exc.HTTPOk.code,
                                  expected_body=attrs)
                # test insert at bottom of list
                fwr3_id = fwr[3]['firewall_rule']['id']
                attrs['firewall_rules'].append(fwr3_id)
                self._rule_action('insert', fwp_id, fwr3_id,
                                  insert_before=None,
                                  insert_after=fwr0_id,
                                  expected_code=webob.exc.HTTPOk.code,
                                  expected_body=attrs)
                # test insert in the middle of the list using
                # insert_before
                fwr4_id = fwr[4]['firewall_rule']['id']
                attrs['firewall_rules'].insert(1, fwr4_id)
                self._rule_action('insert', fwp_id, fwr4_id,
                                  insert_before=fwr1_id,
                                  insert_after=None,
                                  expected_code=webob.exc.HTTPOk.code,
                                  expected_body=attrs)
                # test insert in the middle of the list using
                # insert_after
                fwr5_id = fwr[5]['firewall_rule']['id']
                attrs['firewall_rules'].insert(1, fwr5_id)
                self._rule_action('insert', fwp_id, fwr5_id,
                                  insert_before=None,
                                  insert_after=fwr2_id,
                                  expected_code=webob.exc.HTTPOk.code,
                                  expected_body=attrs)
                # test insert when both insert_before and
                # insert_after are set
                fwr6_id = fwr[6]['firewall_rule']['id']
                attrs['firewall_rules'].insert(1, fwr6_id)
                self._rule_action('insert', fwp_id, fwr6_id,
                                  insert_before=fwr5_id,
                                  insert_after=fwr5_id,
                                  expected_code=webob.exc.HTTPOk.code,
                                  expected_body=attrs)

    def test_insert_rule_with_firewall(self):
        attrs = self._get_test_firewall_policy_attrs()
        attrs['audited'] = False
        attrs['firewall_list'] = []
        with contextlib.nested(self.firewall_rule(name='fwr0'),
                               self.firewall_rule(name='fwr1'),
                               self.firewall_rule(name='fwr2'),
                               self.firewall_rule(name='fwr3'),
                               self.firewall_rule(name='fwr4'),
                               self.firewall_rule(name='fwr5'),
                               self.firewall_rule(name='fwr6')) as fwr:
            with self.firewall_policy() as fwp:
                fwp_id = fwp['firewall_policy']['id']
                attrs['id'] = fwp_id
                with self.firewall(router_id=self._create_and_get_router(),
                                   firewall_policy_id=fwp_id) as fw:
                    # test insert when rule list is empty
                    fwr0_id = fwr[0]['firewall_rule']['id']
                    attrs['firewall_rules'].insert(0, fwr0_id)
                    attrs['firewall_list'].insert(0, fw['firewall']['id'])
                    self._rule_action('insert', fwp_id, fwr0_id,
                                      insert_before=None,
                                      insert_after=None,
                                      expected_code=webob.exc.HTTPOk.code,
                                      expected_body=attrs)
                    # test insert at top of rule list, insert_before and
                    # insert_after not provided
                    fwr1_id = fwr[1]['firewall_rule']['id']
                    attrs['firewall_rules'].insert(0, fwr1_id)
                    insert_data = {'firewall_rule_id': fwr1_id}
                    self._rule_action(
                        'insert', fwp_id, fwr0_id,
                        expected_code=webob.exc.HTTPOk.code,
                        expected_body=attrs, body_data=insert_data)
                    # test insert at top of list above existing rule
                    fwr2_id = fwr[2]['firewall_rule']['id']
                    attrs['firewall_rules'].insert(0, fwr2_id)
                    self._rule_action('insert', fwp_id, fwr2_id,
                                      insert_before=fwr1_id,
                                      insert_after=None,
                                      expected_code=webob.exc.HTTPOk.code,
                                      expected_body=attrs)
                    # test insert at bottom of list
                    fwr3_id = fwr[3]['firewall_rule']['id']
                    attrs['firewall_rules'].append(fwr3_id)
                    self._rule_action('insert', fwp_id, fwr3_id,
                                      insert_before=None,
                                      insert_after=fwr0_id,
                                      expected_code=webob.exc.HTTPOk.code,
                                      expected_body=attrs)
                    # test insert in the middle of the list using
                    # insert_before
                    fwr4_id = fwr[4]['firewall_rule']['id']
                    attrs['firewall_rules'].insert(1, fwr4_id)
                    self._rule_action('insert', fwp_id, fwr4_id,
                                      insert_before=fwr1_id,
                                      insert_after=None,
                                      expected_code=webob.exc.HTTPOk.code,
                                      expected_body=attrs)
                    # test insert in the middle of the list using
                    # insert_after
                    fwr5_id = fwr[5]['firewall_rule']['id']
                    attrs['firewall_rules'].insert(1, fwr5_id)
                    self._rule_action('insert', fwp_id, fwr5_id,
                                      insert_before=None,
                                      insert_after=fwr2_id,
                                      expected_code=webob.exc.HTTPOk.code,
                                      expected_body=attrs)
                    # test insert when both insert_before and
                    # insert_after are set
                    fwr6_id = fwr[6]['firewall_rule']['id']
                    attrs['firewall_rules'].insert(1, fwr6_id)
                    self._rule_action('insert', fwp_id, fwr6_id,
                                      insert_before=fwr5_id,
                                      insert_after=fwr5_id,
                                      expected_code=webob.exc.HTTPOk.code,
                                      expected_body=attrs)

    def test_remove_rule_with_no_firewall(self):
        attrs = self._get_test_firewall_policy_attrs()
        attrs['audited'] = False
        attrs['firewall_list'] = []
        with self.firewall_policy() as fwp:
            fwp_id = fwp['firewall_policy']['id']
            attrs['id'] = fwp_id
            with contextlib.nested(self.firewall_rule(name='fwr1'),
                                   self.firewall_rule(name='fwr2'),
                                   self.firewall_rule(name='fwr3')) as fr1:
                fw_rule_ids = [r['firewall_rule']['id'] for r in fr1]
                attrs['firewall_rules'] = fw_rule_ids[:]
                data = {'firewall_policy':
                        {'firewall_rules': fw_rule_ids}}
                req = self.new_update_request('firewall_policies', data,
                                              fwp_id)
                req.get_response(self.ext_api)
                # test removing a rule from a policy that does not exist
                self._rule_action('remove', '123', fw_rule_ids[1],
                                  expected_code=webob.exc.HTTPNotFound.code,
                                  expected_body=None)
                # test removing a rule in the middle of the list
                attrs['firewall_rules'].remove(fw_rule_ids[1])
                self._rule_action('remove', fwp_id, fw_rule_ids[1],
                                  expected_body=attrs)
                # test removing a rule at the top of the list
                attrs['firewall_rules'].remove(fw_rule_ids[0])
                self._rule_action('remove', fwp_id, fw_rule_ids[0],
                                  expected_body=attrs)
                # test removing remaining rule in the list
                attrs['firewall_rules'].remove(fw_rule_ids[2])
                self._rule_action('remove', fwp_id, fw_rule_ids[2],
                                  expected_body=attrs)
                # test removing rule that is not associated with the policy
                self._rule_action('remove', fwp_id, fw_rule_ids[2],
                                  expected_code=webob.exc.HTTPBadRequest.code,
                                  expected_body=None)

    def test_remove_rule_with_firewall(self):
        attrs = self._get_test_firewall_policy_attrs()
        attrs['audited'] = False
        attrs['firewall_list'] = []
        with self.firewall_policy() as fwp:
            fwp_id = fwp['firewall_policy']['id']
            attrs['id'] = fwp_id
            with self.firewall(router_id=self._create_and_get_router(),
                               firewall_policy_id=fwp_id) as fw:
                attrs['firewall_list'].insert(0, fw['firewall']['id'])
                with contextlib.nested(self.firewall_rule(name='fwr1'),
                                       self.firewall_rule(name='fwr2'),
                                       self.firewall_rule(name='fwr3')) as fr1:
                    fw_rule_ids = [r['firewall_rule']['id'] for r in fr1]
                    attrs['firewall_rules'] = fw_rule_ids[:]
                    data = {'firewall_policy':
                            {'firewall_rules': fw_rule_ids}}
                    req = self.new_update_request(
                        'firewall_policies', data, fwp_id)
                    req.get_response(self.ext_api)
                    # test removing a rule from a policy that does not exist
                    self._rule_action(
                        'remove', '123',
                        fw_rule_ids[1],
                        expected_code=webob.exc.HTTPNotFound.code,
                        expected_body=None)
                    # test removing a rule in the middle of the list
                    attrs['firewall_rules'].remove(fw_rule_ids[1])
                    self._rule_action('remove', fwp_id, fw_rule_ids[1],
                                      expected_body=attrs)
                    # test removing a rule at the top of the list
                    attrs['firewall_rules'].remove(fw_rule_ids[0])
                    self._rule_action('remove', fwp_id, fw_rule_ids[0],
                                      expected_body=attrs)
                    # test removing remaining rule in the list
                    attrs['firewall_rules'].remove(fw_rule_ids[2])
                    self._rule_action('remove', fwp_id, fw_rule_ids[2],
                                      expected_body=attrs)
                    # test removing rule that is not
                    #associated with the policy
                    self._rule_action(
                        'remove', fwp_id, fw_rule_ids[2],
                        expected_code=webob.exc.HTTPBadRequest.code,
                        expected_body=None)

    def test_remove_rule_with_firewalls(self):
        attrs = self._get_test_firewall_policy_attrs()
        attrs['audited'] = False
        attrs['firewall_list'] = []
        with self.firewall_policy() as fwp:
            fwp_id = fwp['firewall_policy']['id']
            attrs['id'] = fwp_id
            with contextlib.nested(
                self.firewall(router_id=self._create_and_get_router(),
                              firewall_policy_id=fwp_id),
                self.firewall(router_id=self._create_and_get_router(),
                              firewall_policy_id=fwp_id)) as (fw1, fw2):
                attrs['firewall_list'].insert(0, fw1['firewall']['id'])
                attrs['firewall_list'].insert(1, fw2['firewall']['id'])
                with contextlib.nested(self.firewall_rule(name='fwr1'),
                                       self.firewall_rule(name='fwr2'),
                                       self.firewall_rule(name='fwr3')) as fr1:
                    fw_rule_ids = [r['firewall_rule']['id'] for r in fr1]
                    attrs['firewall_rules'] = fw_rule_ids[:]
                    data = {'firewall_policy':
                            {'firewall_rules': fw_rule_ids}}
                    req = self.new_update_request(
                        'firewall_policies', data, fwp_id)
                    req.get_response(self.ext_api)
                    # test removing a rule from a policy that does not exist
                    self._rule_action(
                        'remove', '123',
                        fw_rule_ids[1],
                        expected_code=webob.exc.HTTPNotFound.code,
                        expected_body=None)
                    # test removing a rule in the middle of the list
                    attrs['firewall_rules'].remove(fw_rule_ids[1])
                    self._rule_action('remove', fwp_id, fw_rule_ids[1],
                                      expected_body=attrs)
                    # test removing a rule at the top of the list
                    attrs['firewall_rules'].remove(fw_rule_ids[0])
                    self._rule_action('remove', fwp_id, fw_rule_ids[0],
                                      expected_body=attrs)
                    # test removing remaining rule in the list
                    attrs['firewall_rules'].remove(fw_rule_ids[2])
                    self._rule_action('remove', fwp_id, fw_rule_ids[2],
                                      expected_body=attrs)
                    # test removing rule that is not
                    #associated with the policy
                    self._rule_action(
                        'remove', fwp_id, fw_rule_ids[2],
                        expected_code=webob.exc.HTTPBadRequest.code,
                        expected_body=None)
