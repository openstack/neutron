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

import random
from unittest import mock

from neutron_lib import context

from neutron.db import rbac_db_models
from neutron.objects import address_group
from neutron.objects import address_scope
from neutron.objects import network
from neutron.objects.qos import policy
from neutron.objects import rbac
from neutron.objects import securitygroup
from neutron.objects import subnetpool
from neutron.tests import base as neutron_test_base
from neutron.tests.unit.objects import test_base


class TestRBACObjectMixin:

    _test_class = None
    _parent_class = None

    def get_random_object_fields(self, obj_cls=None):
        fields = (super().
                  get_random_object_fields(obj_cls))
        rnd_actions = self._test_class.db_model.get_valid_actions()
        idx = random.randint(0, len(rnd_actions) - 1)
        fields['action'] = rnd_actions[idx]
        return fields

    def _create_random_parent_object(self):
        objclass_fields = self.get_random_db_fields(self._parent_class)
        _obj = self._parent_class(self.context, **objclass_fields)
        _obj.create()
        return _obj

    def test_rbac_shared_on_parent_object(self):
        if not self._test_class or not self._parent_class:
            self.skipTest('Mixin class, skipped test')
        project_id = self.objs[0].project_id
        _obj_shared = self._create_random_parent_object()
        # Create a second object that won't be shared and thus won't be
        # retrieved by the non-admin users.
        self._create_random_parent_object()
        for idx in range(3):
            project = 'project_%s' % idx
            rbac = self._test_class(
                self.context, project_id=project_id, target_project=project,
                action=rbac_db_models.ACCESS_SHARED,
                object_id=_obj_shared.id)
            rbac.create()

        for idx in range(3):
            project = 'project_%s' % idx
            ctx_no_admin = context.Context(user_id='user', project_id=project,
                                           is_admin=False)
            objects = self._parent_class.get_objects(ctx_no_admin)
            self.assertEqual([_obj_shared.id], [_obj.id for _obj in objects])


class RBACBaseObjectTestCase(neutron_test_base.BaseTestCase):

    def test_get_type_class_map(self):
        class_map = {'address_group': address_group.AddressGroupRBAC,
                     'address_scope': address_scope.AddressScopeRBAC,
                     'qos_policy': policy.QosPolicyRBAC,
                     'network': network.NetworkRBAC,
                     'security_group': securitygroup.SecurityGroupRBAC,
                     'subnetpool': subnetpool.SubnetPoolRBAC}
        self.assertEqual(class_map, rbac.RBACBaseObject.get_type_class_map())


class RBACBaseObjectIfaceTestCase(test_base.BaseObjectIfaceTestCase):

    def test_get_object(self, context=None):
        super().test_get_object(context=mock.ANY)

    def test_get_objects(self, context=None):
        super().test_get_objects(context=mock.ANY)
