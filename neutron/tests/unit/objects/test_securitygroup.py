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

from neutron.objects import securitygroup
from neutron.tests.unit.objects import test_base
from neutron.tests.unit import testlib_api


class SecurityGroupIfaceObjTestCase(test_base.BaseObjectIfaceTestCase):

    _test_class = securitygroup.SecurityGroup


class SecurityGroupDbObjTestCase(test_base.BaseDbObjectTestCase,
                                 testlib_api.SqlTestCase):

    _test_class = securitygroup.SecurityGroup

    def setUp(self):
        super(SecurityGroupDbObjTestCase, self).setUp()
        # TODO(ihrachys): consider refactoring base test class to set None for
        # all nullable fields
        for db_obj in self.db_objs:
            for rule in db_obj['rules']:
                # we either make it null, or create remote groups for each rule
                # generated; we picked the former here
                rule['remote_group_id'] = None

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


class DefaultSecurityGroupIfaceObjTestCase(test_base.BaseObjectIfaceTestCase):

    _test_class = securitygroup.DefaultSecurityGroup


class DefaultSecurityGroupDbObjTestCase(test_base.BaseDbObjectTestCase,
                                        testlib_api.SqlTestCase):

    _test_class = securitygroup.DefaultSecurityGroup

    def setUp(self):
        super(DefaultSecurityGroupDbObjTestCase, self).setUp()
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
        super(SecurityGroupRuleDbObjTestCase, self).setUp()
        self.update_obj_fields(
            {
                'security_group_id':
                    lambda: self._create_test_security_group_id(),
                'remote_group_id':
                    lambda: self._create_test_security_group_id()
            })
