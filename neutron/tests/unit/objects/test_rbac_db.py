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

from unittest import mock

from neutron_lib.callbacks import events
from neutron_lib import context as n_context
from neutron_lib.db import model_base
from neutron_lib import exceptions as n_exc
from neutron_lib.objects import common_types
from oslo_versionedobjects import fields as obj_fields
import sqlalchemy as sa

from neutron.db import rbac_db_models
from neutron.extensions import rbac as ext_rbac
from neutron.objects import base
from neutron.objects.db import api as obj_db_api
from neutron.objects import rbac_db
from neutron.tests.unit.objects import test_rbac
from neutron.tests.unit import testlib_api


class FakeDbModel(dict):
    pass


class FakeRbacModel(rbac_db_models.RBACColumns, model_base.BASEV2):
    object_id = sa.Column(sa.String(36), nullable=False)
    object_type = 'fake_rbac_object'

    def get_valid_actions(self):
        return (rbac_db_models.ACCESS_SHARED,)


@base.NeutronObjectRegistry.register_if(False)
class FakeNeutronRbacObject(base.NeutronDbObject):
    VERSION = '1.0'

    db_model = FakeRbacModel

    fields = {
        'object_id': obj_fields.StringField(),
        'target_tenant': obj_fields.StringField(),
        'action': obj_fields.StringField(),
    }


@base.NeutronObjectRegistry.register_if(False)
class FakeNeutronDbObject(rbac_db.NeutronRbacObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    rbac_db_cls = FakeNeutronRbacObject
    db_model = FakeDbModel

    fields = {
        'id': common_types.UUIDField(),
        'field1': obj_fields.StringField(),
        'field2': obj_fields.StringField(),
        'shared': obj_fields.BooleanField(default=False),
    }

    fields_no_update = ['id']

    synthetic_fields = ['field2']

    def get_bound_tenant_ids(cls, context, policy_id):
        pass


class RbacNeutronDbObjectTestCase(test_rbac.RBACBaseObjectIfaceTestCase,
                                  testlib_api.SqlTestCase):
    _test_class = FakeNeutronDbObject

    def setUp(self):
        super(RbacNeutronDbObjectTestCase, self).setUp()
        FakeNeutronDbObject.update_post = mock.Mock()

    @mock.patch.object(_test_class.rbac_db_cls, 'db_model')
    def test_get_tenants_with_shared_access_to_db_obj_return_tenant_ids(
            self, *mocks):
        ctx = mock.Mock()
        fake_ids = {'tenant_id_' + str(i) for i in range(10)}
        ctx.session.query.return_value.filter.return_value = [
            (fake_id,) for fake_id in fake_ids]
        ret_ids = self._test_class._get_tenants_with_shared_access_to_db_obj(
            ctx, 'fake_db_obj_id')
        self.assertEqual(fake_ids, ret_ids)

    def test_is_accessible_for_admin(self):
        ctx = mock.Mock(is_admin=True, tenant_id='we_dont_care')
        self.assertTrue(self._test_class.is_accessible(ctx, None))

    def test_is_accessible_for_db_object_owner(self):
        ctx = mock.Mock(is_admin=False, tenant_id='db_object_owner')
        db_obj = mock.Mock(tenant_id=ctx.tenant_id)

        self.assertTrue(self._test_class.is_accessible(ctx, db_obj))

    @mock.patch.object(_test_class, 'is_shared_with_tenant', return_value=True)
    def test_is_accessible_if_shared_with_tenant(self, mock_is_shared):
        ctx = mock.Mock(is_admin=False, tenant_id='db_object_shareholder')
        db_obj = mock.Mock(tenant_id='db_object_owner')

        self.assertTrue(self._test_class.is_accessible(ctx, db_obj))
        mock_is_shared.assert_called_once_with(
            mock.ANY, db_obj.id, ctx.tenant_id)

    @mock.patch.object(_test_class, 'is_shared_with_tenant',
                       return_value=False)
    def test_is_accessible_fails_for_unauthorized_tenant(self, mock_is_shared):
        ctx = mock.Mock(is_admin=False, tenant_id='Billy_the_kid')
        db_obj = mock.Mock(tenant_id='db_object_owner')

        self.assertFalse(self._test_class.is_accessible(ctx, db_obj))
        mock_is_shared.assert_called_once_with(
            mock.ANY, db_obj.id, ctx.tenant_id)

    def _rbac_policy_generate_change_events(self, resource, trigger,
                                            context, object_type, policy,
                                            event_list):
        for event in event_list:
            payload = events.DBEventPayload(
                context, states=(policy,),
                metadata={'object_type': object_type})
            if event == events.BEFORE_CREATE:
                payload.states = []
                payload.request_body = policy
            self._test_class.validate_rbac_policy_change(
                resource, event, trigger, payload=payload)

    @mock.patch.object(_test_class, 'validate_rbac_policy_update')
    def test_validate_rbac_policy_change_handles_only_object_type(
            self, mock_validate_rbac_update):
        self._rbac_policy_generate_change_events(
            resource=None, trigger='dummy_trigger', context=None,
            object_type='dummy_object_type', policy=None,
            event_list=(events.BEFORE_CREATE, events.BEFORE_UPDATE,
                        events.BEFORE_DELETE))

        mock_validate_rbac_update.assert_not_called()

    @mock.patch.object(_test_class, 'validate_rbac_policy_update')
    @mock.patch.object(obj_db_api, 'get_object',
                       return_value={'tenant_id': 'tyrion_lannister'})
    def test_validate_rbac_policy_change_allowed_for_admin_or_owner(
            self, mock_get_object, mock_validate_update):
        context = mock.Mock(is_admin=True, tenant_id='db_obj_owner_id')
        self._rbac_policy_generate_change_events(
            resource=None, trigger='dummy_trigger', context=context,
            object_type=self._test_class.rbac_db_cls.db_model.object_type,
            policy={'object_id': 'fake_object_id'},
            event_list=(events.BEFORE_CREATE, events.BEFORE_UPDATE))

        self.assertTrue(self._test_class.validate_rbac_policy_update.called)

    @mock.patch.object(_test_class, 'validate_rbac_policy_update')
    @mock.patch.object(obj_db_api, 'get_object',
                       return_value={'tenant_id': 'king_beyond_the_wall'})
    def test_validate_rbac_policy_change_forbidden_for_outsiders(
            self, mock_get_object, mock_validate_update):
        context = mock.Mock(is_admin=False, tenant_id='db_obj_owner_id')
        self.assertRaises(
            n_exc.InvalidInput,
            self._rbac_policy_generate_change_events,
            resource=mock.Mock(), trigger='dummy_trigger', context=context,
            object_type=self._test_class.rbac_db_cls.db_model.object_type,
            policy={'object_id': 'fake_object_id'},
            event_list=(events.BEFORE_CREATE, events.BEFORE_UPDATE))
        self.assertFalse(mock_validate_update.called)

    @mock.patch.object(_test_class, '_validate_rbac_policy_delete')
    def _test_validate_rbac_policy_delete_handles_policy(
            self, policy, mock_validate_delete):
        payload = events.DBEventPayload(
            n_context.get_admin_context(),
            states=(policy,),
            metadata={
                'object_type':
                    self._test_class.rbac_db_cls.db_model.object_type})
        self._test_class.validate_rbac_policy_delete(
            resource=mock.Mock(), event=events.BEFORE_DELETE,
            trigger='dummy_trigger', payload=payload)
        mock_validate_delete.assert_not_called()

    def test_validate_rbac_policy_delete_handles_shared_action(self):
        self._test_validate_rbac_policy_delete_handles_policy(
            {'action': 'unknown_action'})

    @mock.patch.object(obj_db_api, 'get_object')
    def test_validate_rbac_policy_delete_skips_db_object_owner(self,
                                                            mock_get_object):
        policy = {'action': rbac_db_models.ACCESS_SHARED,
                  'target_tenant': 'fake_tenant_id',
                  'object_id': 'fake_obj_id',
                  'tenant_id': 'fake_tenant_id'}
        mock_get_object.return_value.tenant_id = policy['target_tenant']
        self._test_validate_rbac_policy_delete_handles_policy(policy)

    @mock.patch.object(obj_db_api, 'get_object')
    @mock.patch.object(_test_class, 'get_bound_tenant_ids',
                       return_value='tenant_id_shared_with')
    def test_validate_rbac_policy_delete_fails_single_tenant_and_in_use(
            self, get_bound_tenant_ids_mock, mock_get_object):
        policy = {'action': rbac_db_models.ACCESS_SHARED,
                  'target_tenant': 'tenant_id_shared_with',
                  'tenant_id': 'object_owner_tenant_id',
                  'object_id': 'fake_obj_id'}
        context = mock.Mock()
        with mock.patch.object(
                self._test_class,
                '_get_db_obj_rbac_entries') as target_tenants_mock:
            filter_mock = target_tenants_mock.return_value.filter
            filter_mock.return_value.count.return_value = 0
            payload = events.DBEventPayload(
                context,
                states=(policy,),
                metadata={
                    'object_type':
                        self._test_class.rbac_db_cls.db_model.object_type})
            self.assertRaises(
                ext_rbac.RbacPolicyInUse,
                self._test_class.validate_rbac_policy_delete,
                resource=None,
                event=events.BEFORE_DELETE,
                trigger='dummy_trigger',
                payload=payload)

    def test_validate_rbac_policy_delete_not_bound_tenant_success(self):
        context = mock.Mock()
        with mock.patch.object(
                self._test_class, 'get_bound_tenant_ids',
                return_value={'fake_tid2', 'fake_tid3'}), \
                mock.patch.object(self._test_class,
                 '_get_db_obj_rbac_entries') as get_rbac_entries_mock, \
                mock.patch.object(
                    self._test_class,
                    '_get_tenants_with_shared_access_to_db_obj') as sh_tids:
            get_rbac_entries_mock.filter.return_value.count.return_value = 0
            self._test_class._validate_rbac_policy_delete(
                context=context,
                obj_id='fake_obj_id',
                target_tenant='fake_tid1')
            sh_tids.assert_not_called()

    @mock.patch.object(_test_class, '_get_db_obj_rbac_entries')
    @mock.patch.object(_test_class,
                       '_get_tenants_with_shared_access_to_db_obj',
                       return_value=['some_other_tenant'])
    @mock.patch.object(_test_class, 'get_bound_tenant_ids',
                       return_value={'fake_id1'})
    def test_validate_rbac_policy_delete_fails_single_used_wildcarded(
            self, get_bound_tenant_ids_mock, mock_tenants_with_shared_access,
            _get_db_obj_rbac_entries_mock):
        policy = {'action': rbac_db_models.ACCESS_SHARED,
                  'target_tenant': '*',
                  'tenant_id': 'object_owner_tenant_id',
                  'object_id': 'fake_obj_id'}
        context = mock.Mock()
        payload = events.DBEventPayload(
            context,
            states=(policy,),
            metadata={
                'object_type':
                    self._test_class.rbac_db_cls.db_model.object_type})
        with mock.patch.object(obj_db_api, 'get_object'):
            self.assertRaises(
                ext_rbac.RbacPolicyInUse,
                self._test_class.validate_rbac_policy_delete,
                resource=mock.Mock(),
                event=events.BEFORE_DELETE,
                trigger='dummy_trigger',
                payload=payload)

    @mock.patch.object(_test_class, 'attach_rbac')
    @mock.patch.object(obj_db_api, 'get_object',
                       return_value=['fake_rbac_policy'])
    @mock.patch.object(_test_class, '_validate_rbac_policy_delete')
    def test_update_shared_avoid_duplicate_update(
            self, mock_validate_delete, get_object_mock, attach_rbac_mock):
        obj_id = 'fake_obj_id'
        obj = self._test_class(mock.Mock())
        obj.update_shared(is_shared_new=True, obj_id=obj_id)
        get_object_mock.assert_called_with(
            obj.rbac_db_cls, mock.ANY, object_id=obj_id,
            target_tenant='*', action=rbac_db_models.ACCESS_SHARED)
        self.assertFalse(mock_validate_delete.called)
        self.assertFalse(attach_rbac_mock.called)

    @mock.patch.object(_test_class, 'attach_rbac')
    @mock.patch.object(obj_db_api, 'get_object', return_value=[])
    @mock.patch.object(_test_class, '_validate_rbac_policy_delete')
    def test_update_shared_wildcard(
            self, mock_validate_delete, get_object_mock, attach_rbac_mock):
        obj_id = 'fake_obj_id'

        test_neutron_obj = self._test_class(mock.Mock())
        test_neutron_obj.update_shared(is_shared_new=True, obj_id=obj_id)
        get_object_mock.assert_called_with(
            test_neutron_obj.rbac_db_cls, mock.ANY, object_id=obj_id,
            target_tenant='*', action=rbac_db_models.ACCESS_SHARED)

        attach_rbac_mock.assert_called_with(
            obj_id, test_neutron_obj.obj_context.tenant_id)

    def test_shared_field_false_without_context(self):
        test_neutron_obj = self._test_class()
        self.assertFalse(test_neutron_obj.to_dict()['shared'])

    @mock.patch.object(_test_class, 'attach_rbac')
    @mock.patch.object(obj_db_api, 'get_object',
                       return_value=['fake_rbac_policy'])
    @mock.patch.object(_test_class, '_validate_rbac_policy_delete')
    def test_update_shared_remove_wildcard_sharing(
            self, mock_validate_delete, get_object_mock, attach_rbac_mock):
        obj_id = 'fake_obj_id'
        obj = self._test_class(mock.Mock())
        obj.update_shared(is_shared_new=False, obj_id=obj_id)
        get_object_mock.assert_called_with(
            obj.rbac_db_cls, mock.ANY, object_id=obj_id,
            target_tenant='*', action=rbac_db_models.ACCESS_SHARED)

        self.assertFalse(attach_rbac_mock.attach_rbac.called)
        mock_validate_delete.assert_called_with(mock.ANY, obj_id, '*')

    @mock.patch.object(_test_class, 'create_rbac_policy')
    def test_attach_rbac_returns_type(self, create_rbac_mock):
        obj_id = 'fake_obj_id'
        tenant_id = 'fake_tenant_id'
        target_tenant = 'fake_target_tenant'
        self._test_class(mock.Mock()).attach_rbac(obj_id, tenant_id,
                                                  target_tenant)
        rbac_pol = create_rbac_mock.call_args_list[0][0][1]['rbac_policy']
        self.assertEqual(rbac_pol['object_id'], obj_id)
        self.assertEqual(rbac_pol['target_tenant'], target_tenant)
        self.assertEqual(rbac_pol['action'], rbac_db_models.ACCESS_SHARED)
        self.assertEqual(rbac_pol['object_type'],
                         self._test_class.rbac_db_cls.db_model.object_type)
