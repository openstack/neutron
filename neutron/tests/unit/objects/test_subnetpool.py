# Copyright (c) 2015 OpenStack Foundation.
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
import mock

from neutron_lib import constants
from neutron_lib.db import model_query
from oslo_utils import uuidutils

from neutron.extensions import rbac as ext_rbac
from neutron.objects.db import api as obj_db_api
from neutron.objects import subnetpool
from neutron.tests.unit.objects import test_base as obj_test_base
from neutron.tests.unit.objects import test_rbac
from neutron.tests.unit import testlib_api


class SubnetPoolTestMixin(object):
    def _create_test_subnetpool(self, snp_id=None):

        if not snp_id:
            snp_id = uuidutils.generate_uuid()

        obj = subnetpool.SubnetPool(
            self.context,
            id=snp_id,
            ip_version=constants.IP_VERSION_4,
            default_prefixlen=24,
            min_prefixlen=0,
            max_prefixlen=32,
            shared=False)
        obj.create()
        return obj


class SubnetPoolIfaceObjectTestCase(obj_test_base.BaseObjectIfaceTestCase):

    _test_class = subnetpool.SubnetPool


class SubnetPoolDbObjectTestCase(obj_test_base.BaseDbObjectTestCase,
                                 testlib_api.SqlTestCase,
                                 SubnetPoolTestMixin):

    _test_class = subnetpool.SubnetPool

    def test_subnetpool_prefixes(self):
        pool = self._create_test_subnetpool()
        prefixes = obj_test_base.get_list_of_random_networks()
        pool.prefixes = prefixes
        pool.update()

        new_pool = self._test_class.get_object(self.context, id=pool.id)
        self.assertItemsEqual(prefixes, new_pool.prefixes)

        prefixes.pop()
        pool.prefixes = prefixes
        pool.update()

        new_pool = self._test_class.get_object(self.context, id=pool.id)
        self.assertItemsEqual(prefixes, new_pool.prefixes)

    def test_get_objects_queries_constant(self):
        # TODO(korzen) SubnetPool is using SubnetPoolPrefix object to reload
        # prefixes, which costs extra SQL query each time reload_prefixes
        # are called in get_object(s). SubnetPool has defined relationship
        # for SubnetPoolPrefixes, so it should be possible to reuse side loaded
        # values fo this. To be reworked in follow-up patch.
        pass

    @mock.patch.object(model_query, 'query_with_hooks')
    @mock.patch.object(obj_db_api, 'get_object')
    def test_rbac_policy_create_no_address_scope(self, mock_get_object,
                                                 mock_query_with_hooks):
        context = mock.Mock(is_admin=False, tenant_id='db_obj_owner_id')
        payload = mock.Mock(
            context=context, request_body=dict(object_id="fake_id")
        )
        mock_get_object.return_value = dict(address_scope_id=None)

        subnetpool.SubnetPool.validate_rbac_policy_create(
            None, None, None, payload=payload
        )

        mock_query_with_hooks.assert_not_called()

    def _validate_rbac_filter_mock(self, filter_mock, project_id,
                                   address_scope_id):
        filter_mock.assert_called_once()
        self.assertEqual(
            "addressscoperbacs.target_tenant IN ('*', '%(project_id)s') "
            "AND addressscoperbacs.object_id = '%(address_scope_id)s'" % {
                "project_id": project_id,
                "address_scope_id": address_scope_id,
            },
            filter_mock.call_args[0][0].compile(
                compile_kwargs={"literal_binds": True}
            ).string
        )

    @mock.patch.object(model_query, 'query_with_hooks')
    @mock.patch.object(obj_db_api, 'get_object')
    def test_rbac_policy_create_no_matching_policies(self, mock_get_object,
                                                     mock_query_with_hooks):
        context = mock.Mock(is_admin=False, tenant_id='db_obj_owner_id')
        fake_project_id = "fake_target_tenant_id"
        payload = mock.Mock(
            context=context, request_body=dict(
                object_id="fake_id",
                target_tenant=fake_project_id
            )
        )
        fake_address_scope_id = "fake_as_id"
        mock_get_object.return_value = dict(
            address_scope_id=fake_address_scope_id
        )
        filter_mock = mock.Mock(
            return_value=mock.Mock(count=mock.Mock(return_value=0))
        )
        mock_query_with_hooks.return_value = mock.Mock(filter=filter_mock)

        self.assertRaises(
            ext_rbac.RbacPolicyInitError,
            subnetpool.SubnetPool.validate_rbac_policy_create,
            resource=None, event=None, trigger=None,
            payload=payload
        )

        self._validate_rbac_filter_mock(
            filter_mock, fake_project_id, fake_address_scope_id
        )

    @mock.patch.object(model_query, 'query_with_hooks')
    @mock.patch.object(obj_db_api, 'get_object')
    def test_rbac_policy_create_valid(self, mock_get_object,
                                      mock_query_with_hooks):
        context = mock.Mock(is_admin=False, tenant_id='db_obj_owner_id')
        fake_project_id = "fake_target_tenant_id"
        payload = mock.Mock(
            context=context, request_body=dict(
                object_id="fake_id",
                target_tenant=fake_project_id
            )
        )
        fake_address_scope_id = "fake_as_id"
        mock_get_object.return_value = dict(
            address_scope_id=fake_address_scope_id
        )
        filter_mock = mock.Mock(count=1)
        mock_query_with_hooks.return_value = mock.Mock(filter=filter_mock)

        subnetpool.SubnetPool.validate_rbac_policy_create(
            None, None, None, payload=payload
        )

        self._validate_rbac_filter_mock(
            filter_mock, fake_project_id, fake_address_scope_id
        )


class SubnetPoolPrefixIfaceObjectTestCase(
        obj_test_base.BaseObjectIfaceTestCase):

    _test_class = subnetpool.SubnetPoolPrefix


class SubnetPoolPrefixDbObjectTestCase(
        obj_test_base.BaseDbObjectTestCase,
        testlib_api.SqlTestCase,
        SubnetPoolTestMixin):

    _test_class = subnetpool.SubnetPoolPrefix

    def setUp(self):
        super(SubnetPoolPrefixDbObjectTestCase, self).setUp()
        self.update_obj_fields(
            {'subnetpool_id': lambda: self._create_test_subnetpool().id})


class SubnetPoolRBACDbObjectTestCase(test_rbac.TestRBACObjectMixin,
                                     obj_test_base.BaseDbObjectTestCase,
                                     testlib_api.SqlTestCase,
                                     SubnetPoolTestMixin):

    _test_class = subnetpool.SubnetPoolRBAC

    def setUp(self):
        super(SubnetPoolRBACDbObjectTestCase, self).setUp()
        for obj in self.db_objs:
            self._create_test_subnetpool(obj['object_id'])

    def _create_test_subnetpool_rbac(self):
        self.objs[0].create()
        return self.objs[0]


class SubnetPoolRBACIfaceObjectTestCase(test_rbac.TestRBACObjectMixin,
                                        obj_test_base.BaseObjectIfaceTestCase):
    _test_class = subnetpool.SubnetPoolRBAC
