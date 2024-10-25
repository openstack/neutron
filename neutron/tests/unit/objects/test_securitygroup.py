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

import collections
import itertools

import netaddr
from oslo_utils import uuidutils

from neutron.objects import securitygroup
from neutron.tests.unit.objects import test_base
from neutron.tests.unit.objects import test_rbac
from neutron.tests.unit import testlib_api


class SecurityGroupRBACDbObjectTestCase(test_rbac.TestRBACObjectMixin,
                                        test_base.BaseDbObjectTestCase,
                                        testlib_api.SqlTestCase):

    _test_class = securitygroup.SecurityGroupRBAC
    _parent_class = securitygroup.SecurityGroup

    def setUp(self):
        super().setUp()
        for obj in self.db_objs:
            sg_obj = securitygroup.SecurityGroup(self.context,
                                                 id=obj['object_id'],
                                                 project_id=obj['project_id'])
            sg_obj.create()

    def _create_test_security_group_rbac(self):
        self.objs[0].create()
        return self.objs[0]

    def test_object_version_degradation_1_1_to_1_0_no_shared(self):
        security_group_rbac_obj = self._create_test_security_group_rbac()
        x = security_group_rbac_obj.obj_to_primitive('1.0')
        security_group_rbac_dict = x
        self.assertNotIn('shared',
                         security_group_rbac_dict['versioned_object.data'])


class SecurityGroupRBACIfaceObjectTestCase(test_rbac.TestRBACObjectMixin,
                                           test_base.BaseObjectIfaceTestCase):
    _test_class = securitygroup.SecurityGroupRBAC


class SecurityGroupIfaceObjTestCase(test_rbac.RBACBaseObjectIfaceTestCase):

    _test_class = securitygroup.SecurityGroup


class SecurityGroupDbObjTestCase(test_base.BaseDbObjectTestCase,
                                 testlib_api.SqlTestCase):

    _test_class = securitygroup.SecurityGroup

    def setUp(self):
        super().setUp()
        # TODO(ihrachys): consider refactoring base test class to set None for
        # all nullable fields
        for db_obj in self.db_objs:
            for rule in db_obj['rules']:
                # we either make it null, or create remote groups for each rule
                # generated; we picked the former here
                rule['remote_group_id'] = None

        sg_rule = self.get_random_db_fields(securitygroup.SecurityGroupRule)
        self.model_map.update({
            self._test_class.db_model: self.db_objs,
            securitygroup.SecurityGroupRule.db_model: sg_rule})

    def _create_test_security_group(self):
        self.objs[0].create()
        return self.objs[0]

    def _create_test_security_group_with_rule(self):
        sg_obj = self._create_test_security_group()
        rule_params = {
            'project_id': sg_obj.project_id,
            'security_group_id': sg_obj.id,
            'remote_address_group_id': None,
            'remote_ip_prefix': netaddr.IPNetwork('10.0.0.120/24')}
        sg_rule = securitygroup.SecurityGroupRule(
            self.context, **rule_params)
        sg_obj.rules = [sg_rule]
        return sg_obj

    def test_object_version_degradation_1_3_to_1_2_no_remote_ag(self):
        sg_obj = self._create_test_security_group_with_rule()
        sg_obj_1_2 = sg_obj.obj_to_primitive('1.2')
        for rule in sg_obj_1_2['versioned_object.data']['rules']:
            self.assertEqual('1.0', rule['versioned_object.version'])
            self.assertNotIn('remote_address_group_id',
                             rule['versioned_object.data'])

    def test_object_version_degradation_1_4_to_1_3_no_normalized_cidr(self):
        sg_obj = self._create_test_security_group_with_rule()
        sg_obj_1_3 = sg_obj.obj_to_primitive('1.3')
        for rule in sg_obj_1_3['versioned_object.data']['rules']:
            self.assertEqual('1.1', rule['versioned_object.version'])
            self.assertNotIn('normalized_cidr', rule['versioned_object.data'])

    def test_object_version_degradation_1_6_to_1_5_no_belongs_to_default_sg(
            self):
        sg_obj = self._create_test_security_group_with_rule()
        sg_obj_1_5 = sg_obj.obj_to_primitive('1.5')
        for rule in sg_obj_1_5['versioned_object.data']['rules']:
            self.assertEqual('1.2', rule['versioned_object.version'])
            self.assertNotIn('belongs_to_default_sg',
                             rule['versioned_object.data'])

    def test_object_version_degradation_1_2_to_1_1_no_stateful(self):
        sg_stateful_obj = self._create_test_security_group()
        sg_no_stateful_obj = sg_stateful_obj.obj_to_primitive('1.1')
        self.assertNotIn('stateful',
                         sg_no_stateful_obj['versioned_object.data'])

    def test_is_default_True(self):
        fields = self.obj_fields[0].copy()
        sg_obj = self._make_object(fields)
        sg_obj.is_default = True
        sg_obj.create()

        default_sg_obj = securitygroup.DefaultSecurityGroup.get_object(
            self.context,
            project_id=sg_obj.project_id,
            security_group_id=sg_obj.id)
        self.assertIsNotNone(default_sg_obj)

        sg_obj = securitygroup.SecurityGroup.get_object(
            self.context,
            id=sg_obj.id,
            project_id=sg_obj.project_id
        )
        self.assertTrue(sg_obj.is_default)

    def test_is_default_False(self):
        fields = self.obj_fields[0].copy()
        sg_obj = self._make_object(fields)
        sg_obj.is_default = False
        sg_obj.create()

        default_sg_obj = securitygroup.DefaultSecurityGroup.get_object(
            self.context,
            project_id=sg_obj.project_id,
            security_group_id=sg_obj.id)
        self.assertIsNone(default_sg_obj)

        sg_obj = securitygroup.SecurityGroup.get_object(
            self.context,
            id=sg_obj.id,
            project_id=sg_obj.project_id
        )
        self.assertFalse(sg_obj.is_default)

    def test_get_object_filter_by_is_default(self):
        fields = self.obj_fields[0].copy()
        sg_obj = self._make_object(fields)
        sg_obj.is_default = True
        sg_obj.create()

        listed_obj = securitygroup.SecurityGroup.get_object(
            self.context,
            id=sg_obj.id,
            project_id=sg_obj.project_id,
            is_default=True
        )
        self.assertIsNotNone(listed_obj)
        self.assertEqual(sg_obj, listed_obj)

    def test_get_objects_queries_constant(self):
        # TODO(electrocucaracha) SecurityGroup is using SecurityGroupRule
        # object to reload rules, which costs extra SQL query each time
        # is_default field is loaded as part of get_object(s). SecurityGroup
        # has defined relationship for SecurityGroupRules, so it should be
        # possible to reuse side loaded values fo this. To be reworked in
        # follow-up patch.
        pass

    def test_get_object_no_synth(self):
        fields = self.obj_fields[0].copy()
        sg_obj = self._make_object(fields)
        sg_obj.is_default = True
        sg_obj.create()

        listed_obj = securitygroup.SecurityGroup.get_object(
            self.context,
            fields=['id', 'name'],
            id=sg_obj.id,
            project_id=sg_obj.project_id
        )
        self.assertIsNotNone(listed_obj)
        self.assertEqual(len(sg_obj.rules), 0)
        self.assertIsNone(listed_obj.rules)

    def test_get_objects_no_synth(self):
        fields = self.obj_fields[0].copy()
        sg_obj = self._make_object(fields)
        sg_obj.is_default = True
        sg_obj.create()

        listed_objs = securitygroup.SecurityGroup.get_objects(
            self.context,
            fields=['id', 'name'],
            id=sg_obj.id,
            project_id=sg_obj.project_id
        )
        self.assertEqual(len(listed_objs), 1)
        self.assertEqual(len(sg_obj.rules), 0)
        self.assertIsNone(listed_objs[0].rules)

    def test_get_sgs_stateful_flag(self):
        for obj in self.objs:
            obj.create()

        sg_ids = tuple(sg.id for sg in self.objs)
        sgs_stateful = securitygroup.SecurityGroup.get_sgs_stateful_flag(
            self.context, sg_ids)
        for sg_id, stateful in sgs_stateful.items():
            for obj in (obj for obj in self.objs if obj.id == sg_id):
                self.assertEqual(obj.stateful, stateful)

        sg_ids = sg_ids + ('random_id_not_present', )
        sgs_stateful = securitygroup.SecurityGroup.get_sgs_stateful_flag(
            self.context, sg_ids)
        self.assertEqual(len(self.objs), len(sgs_stateful))


class DefaultSecurityGroupIfaceObjTestCase(test_base.BaseObjectIfaceTestCase):

    _test_class = securitygroup.DefaultSecurityGroup


class DefaultSecurityGroupDbObjTestCase(test_base.BaseDbObjectTestCase,
                                        testlib_api.SqlTestCase):

    _test_class = securitygroup.DefaultSecurityGroup

    def setUp(self):
        super().setUp()
        self.update_obj_fields(
            {
                'security_group_id':
                    lambda: self._create_test_security_group_id()
            })


class SecurityGroupRuleIfaceObjTestCase(test_base.BaseObjectIfaceTestCase):

    _test_class = securitygroup.SecurityGroupRule


class SecurityGroupRuleDbObjTestCase(test_base.BaseDbObjectTestCase,
                                     testlib_api.SqlTestCase):

    _test_class = securitygroup.SecurityGroupRule

    def setUp(self):
        super().setUp()
        self.update_obj_fields(
            {
                'security_group_id':
                    lambda: self._create_test_security_group_id(),
                'remote_group_id':
                    lambda: self._create_test_security_group_id(),
                'remote_address_group_id':
                    lambda: self._create_test_address_group_id()
            })

    def _create_test_security_group_rule(self):
        self.objs[0].create()
        return self.objs[0]

    def test_get_security_group_rule_ids(self):
        """Retrieve the SG rules associated to a project (see method desc.)

        SG1 (PROJECT1)            SG2 (PROJECT2)
          rule1a (PROJECT1)         rule2a (PROJECT1)
          rule1b (PROJECT2)         rule2b (PROJECT2)

        query PROJECT1: rule1a, rule1b, rule2a
        query PROJECT2: rule1b, rule2a, rule2b
        """
        projects = [uuidutils.generate_uuid(), uuidutils.generate_uuid()]
        sgs = [
            self._create_test_security_group_id({'project_id': projects[0]}),
            self._create_test_security_group_id({'project_id': projects[1]})]

        rules_per_project = collections.defaultdict(list)
        rules_per_sg = collections.defaultdict(list)
        for project, sg in itertools.product(projects, sgs):
            sgrule_fields = self.get_random_object_fields(
                securitygroup.SecurityGroupRule)
            sgrule_fields['project_id'] = project
            sgrule_fields['security_group_id'] = sg
            rule = securitygroup.SecurityGroupRule(self.context,
                                                   **sgrule_fields)
            rule.create()
            rules_per_project[project].append(rule.id)
            rules_per_sg[sg].append(rule.id)

        for idx in range(2):
            rule_ids = securitygroup.SecurityGroupRule.\
                get_security_group_rule_ids(projects[idx])
            rule_ids_ref = set(rules_per_project[projects[idx]])
            rule_ids_ref.update(set(rules_per_sg[sgs[idx]]))
            self.assertEqual(rule_ids_ref, set(rule_ids))

    def test_check_belongs_to_default_sg(self):
        # SG1 is the project default security group, SG2 is not.
        project_id = uuidutils.generate_uuid()
        sg1 = securitygroup.SecurityGroup(self.context, project_id=project_id)
        sg1.is_default = True
        sg1.create()
        sg2 = securitygroup.SecurityGroup(self.context, project_id=project_id)
        sg2.create()

        fields = self.obj_fields[0].copy()
        fields['security_group_id'] = sg1.id
        sg1_rule = self._make_object(fields)
        sg1_rule.create()
        self.assertTrue(sg1_rule.belongs_to_default_sg)

        fields = self.obj_fields[1].copy()
        fields['security_group_id'] = sg2.id
        sg2_rule = self._make_object(fields)
        sg2_rule.create()
        self.assertFalse(sg2_rule.belongs_to_default_sg)

    def test_object_version_degradation_1_1_to_1_0_no_remote_ag(self):
        rule_remote_ag_obj = self._create_test_security_group_rule()
        rule_no_remote_ag_obj = rule_remote_ag_obj.obj_to_primitive('1.0')
        self.assertNotIn('remote_address_group_id',
                         rule_no_remote_ag_obj['versioned_object.data'])

    def test_object_version_degradation_1_2_to_1_1_no_normalized_cidr(self):
        sg_rule_obj = self._create_test_security_group_rule()
        sg_rule_10_obj = sg_rule_obj.obj_to_primitive('1.0')
        self.assertNotIn('normalized_cidr',
                         sg_rule_10_obj['versioned_object.data'])

    def test_object_version_degradation_1_3_to_1_2_no_belongs_to_def_sg(self):
        sg_rule_obj = self._create_test_security_group_rule()
        sg_rule_12_obj = sg_rule_obj.obj_to_primitive('1.2')
        self.assertNotIn('belongs_to_default_sg',
                         sg_rule_12_obj['versioned_object.data'])
