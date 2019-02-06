# Copyright 2016 Red Hat, Inc.
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
import abc
import itertools

from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import exceptions
from six import add_metaclass
from six import with_metaclass
from sqlalchemy import and_

from neutron._i18n import _
from neutron.db import _utils as db_utils
from neutron.db import rbac_db_mixin
from neutron.db import rbac_db_models as models
from neutron.extensions import rbac as ext_rbac
from neutron.objects import base
from neutron.objects.db import api as obj_db_api


@add_metaclass(abc.ABCMeta)
class RbacNeutronDbObjectMixin(rbac_db_mixin.RbacPluginMixin,
                               base.NeutronDbObject):

    rbac_db_cls = None

    @classmethod
    @abc.abstractmethod
    def get_bound_tenant_ids(cls, context, obj_id):
        """Returns ids of all tenants depending on this db object.

        Has to be implemented by classes using RbacNeutronMetaclass.
        The tenants are the ones that need the sharing or 'visibility' of the
        object to them. E.g: for QosPolicy that would be the tenants using the
        Networks and Ports with the shared QosPolicy applied to them.

        :returns: set -- a set of tenants' ids dependent on this object.
        """

    @staticmethod
    def is_network_shared(context, rbac_entries):
        # NOTE(korzen) this method is copied from db_base_plugin_common.
        # The shared attribute for a network now reflects if the network
        # is shared to the calling tenant via an RBAC entry.
        matches = ('*',) + ((context.tenant_id,) if context else ())
        for entry in rbac_entries:
            if (entry.action == models.ACCESS_SHARED and
                    entry.target_tenant in matches):
                return True
        return False

    @staticmethod
    def get_shared_with_tenant(context, rbac_db_cls, obj_id, tenant_id):
        # NOTE(korzen) This method enables to query within already started
        # session
        rbac_db_model = rbac_db_cls.db_model
        return (db_utils.model_query(context, rbac_db_model).filter(
                and_(rbac_db_model.object_id == obj_id,
                     rbac_db_model.action == models.ACCESS_SHARED,
                     rbac_db_model.target_tenant.in_(
                         ['*', tenant_id]))).count() != 0)

    @classmethod
    def is_shared_with_tenant(cls, context, obj_id, tenant_id):
        ctx = context.elevated()
        with cls.db_context_reader(ctx):
            return cls.get_shared_with_tenant(ctx, cls.rbac_db_cls,
                                              obj_id, tenant_id)

    @classmethod
    def is_accessible(cls, context, db_obj):
        return (super(
            RbacNeutronDbObjectMixin, cls).is_accessible(context, db_obj) or
                cls.is_shared_with_tenant(context, db_obj.id,
                                          context.tenant_id))

    @classmethod
    def get_object(cls, context, **kwargs):
        # We want to get the policy regardless of its tenant id. We'll make
        # sure the tenant has permission to access the policy later on.
        admin_context = context.elevated()
        with cls.db_context_reader(admin_context):
            obj = super(RbacNeutronDbObjectMixin,
                        cls).get_object(admin_context, **kwargs)
            if (not obj or not cls.is_accessible(context, obj)):
                return
            return obj

    @classmethod
    def get_objects(cls, context, _pager=None, validate_filters=True,
                    **kwargs):
        # We want to get the policy regardless of its tenant id. We'll make
        # sure the tenant has permission to access the policy later on.
        admin_context = context.elevated()
        with cls.db_context_reader(admin_context):
            objs = super(RbacNeutronDbObjectMixin,
                         cls).get_objects(admin_context, _pager,
                                          validate_filters, **kwargs)
            result = []
            for obj in objs:
                if not cls.is_accessible(context, obj):
                    continue
                result.append(obj)
            return result

    @classmethod
    def _get_db_obj_rbac_entries(cls, context, rbac_obj_id, rbac_action):
        rbac_db_model = cls.rbac_db_cls.db_model
        return db_utils.model_query(context, rbac_db_model).filter(
            and_(rbac_db_model.object_id == rbac_obj_id,
                 rbac_db_model.action == rbac_action))

    @classmethod
    def _get_tenants_with_shared_access_to_db_obj(cls, context, obj_id):
        rbac_db_model = cls.rbac_db_cls.db_model
        return set(itertools.chain.from_iterable(context.session.query(
            rbac_db_model.target_tenant).filter(
            and_(rbac_db_model.object_id == obj_id,
                 rbac_db_model.action == models.ACCESS_SHARED,
                 rbac_db_model.target_tenant != '*'))))

    @classmethod
    def _validate_rbac_policy_delete(cls, context, obj_id, target_tenant):
        ctx_admin = context.elevated()
        rb_model = cls.rbac_db_cls.db_model
        bound_tenant_ids = cls.get_bound_tenant_ids(ctx_admin, obj_id)
        db_obj_sharing_entries = cls._get_db_obj_rbac_entries(
            ctx_admin, obj_id, models.ACCESS_SHARED)

        def raise_policy_in_use():
            raise ext_rbac.RbacPolicyInUse(
                object_id=obj_id,
                details='tenant_id={}'.format(target_tenant))

        if target_tenant != '*':
            # if there is a wildcard rule, we can return early because it
            # shares the object globally
            wildcard_sharing_entries = db_obj_sharing_entries.filter(
                rb_model.target_tenant == '*')
            if wildcard_sharing_entries.count():
                return
            if target_tenant in bound_tenant_ids:
                raise_policy_in_use()
            return

        # for the wildcard we need to query all of the rbac entries to
        # see if any allow the object sharing
        other_target_tenants = cls._get_tenants_with_shared_access_to_db_obj(
                ctx_admin, obj_id)
        if not bound_tenant_ids.issubset(other_target_tenants):
            raise_policy_in_use()

    @classmethod
    def validate_rbac_policy_delete(cls, resource, event, trigger, context,
                                    object_type, policy, **kwargs):
        """Callback to handle RBAC_POLICY, BEFORE_DELETE callback.

        :raises: RbacPolicyInUse -- in case the policy is in use.
        """
        if policy['action'] != models.ACCESS_SHARED:
            return
        target_tenant = policy['target_tenant']
        db_obj = obj_db_api.get_object(
            cls, context.elevated(), id=policy['object_id'])
        if db_obj.tenant_id == target_tenant:
            return
        cls._validate_rbac_policy_delete(context=context,
                                         obj_id=policy['object_id'],
                                         target_tenant=target_tenant)

    @classmethod
    def validate_rbac_policy_update(cls, resource, event, trigger, context,
                                    object_type, policy, **kwargs):
        """Callback to handle RBAC_POLICY, BEFORE_UPDATE callback.

        :raises: RbacPolicyInUse -- in case the update is forbidden.
        """
        prev_tenant = policy['target_tenant']
        new_tenant = kwargs['policy_update']['target_tenant']
        if prev_tenant == new_tenant:
            return
        if new_tenant != '*':
            return cls.validate_rbac_policy_delete(
                resource, event, trigger, context, object_type, policy)

    @classmethod
    def validate_rbac_policy_change(cls, resource, event, trigger, context,
                                    object_type, policy, **kwargs):
        """Callback to validate RBAC_POLICY changes.

        This is the dispatching function for create, update and delete
        callbacks. On creation and update, verify that the creator is an admin
        or owns the resource being shared.
        """
        # TODO(hdaniel): As this code was shamelessly stolen from
        # NeutronDbPluginV2.validate_network_rbac_policy_change(), those pieces
        # should be synced and contain the same bugs, until Network RBAC logic
        # (hopefully) melded with this one.
        if object_type != cls.rbac_db_cls.db_model.object_type:
            return
        db_obj = obj_db_api.get_object(
            cls, context.elevated(), id=policy['object_id'])
        if event in (events.BEFORE_CREATE, events.BEFORE_UPDATE):
            if (not context.is_admin and
                    db_obj['tenant_id'] != context.tenant_id):
                msg = _("Only admins can manipulate policies on objects "
                        "they do not own")
                raise exceptions.InvalidInput(error_message=msg)
        callback_map = {events.BEFORE_UPDATE: cls.validate_rbac_policy_update,
                        events.BEFORE_DELETE: cls.validate_rbac_policy_delete}
        if event in callback_map:
            return callback_map[event](resource, event, trigger, context,
                                       object_type, policy, **kwargs)

    def attach_rbac(self, obj_id, project_id, target_tenant='*'):
        obj_type = self.rbac_db_cls.db_model.object_type
        rbac_policy = {'rbac_policy': {'object_id': obj_id,
                                       'target_tenant': target_tenant,
                                       'project_id': project_id,
                                       'object_type': obj_type,
                                       'action': models.ACCESS_SHARED}}
        return self.create_rbac_policy(self.obj_context, rbac_policy)

    def update_shared(self, is_shared_new, obj_id):
        admin_context = self.obj_context.elevated()
        shared_prev = obj_db_api.get_object(self.rbac_db_cls, admin_context,
                                            object_id=obj_id,
                                            target_tenant='*',
                                            action=models.ACCESS_SHARED)
        is_shared_prev = bool(shared_prev)
        if is_shared_prev == is_shared_new:
            return

        # 'shared' goes False -> True
        if not is_shared_prev and is_shared_new:
            self.attach_rbac(obj_id, self.obj_context.tenant_id)
            return

        # 'shared' goes True -> False is actually an attempt to delete
        # rbac rule for sharing obj_id with target_tenant = '*'
        self._validate_rbac_policy_delete(self.obj_context, obj_id, '*')
        return self.obj_context.session.delete(shared_prev)


def _update_post(self, obj_changes):
    if "shared" in obj_changes:
        self.update_shared(self.shared, self.id)


def _update_hook(self, update_orig):
    with self.db_context_writer(self.obj_context):
        # NOTE(slaweq): copy of object changes is required to pass it later to
        # _update_post method because update() will reset all those changes
        obj_changes = self.obj_get_changes()
        update_orig(self)
        _update_post(self, obj_changes)


def _create_post(self):
    if self.shared:
        self.attach_rbac(self.id, self.project_id)


def _create_hook(self, orig_create):
    with self.db_context_writer(self.obj_context):
        orig_create(self)
        _create_post(self)


def _to_dict_hook(self, to_dict_orig):
    dct = to_dict_orig(self)
    if self.obj_context:
        dct['shared'] = self.is_shared_with_tenant(self.obj_context,
                                                   self.id,
                                                   self.obj_context.tenant_id)
    else:
        # most OVO objects on an agent will not have a context set on the
        # object because they will be generated from obj_from_primitive.
        dct['shared'] = False
    return dct


class RbacNeutronMetaclass(type):
    """Adds support for RBAC in NeutronDbObjects.

    Injects code for CRUD operations and modifies existing ops to do so.
    """

    @classmethod
    def _get_attribute(cls, attribute_name, bases):
        for b in bases:
            attribute = getattr(b, attribute_name, None)
            if attribute:
                return attribute

    @classmethod
    def get_attribute(cls, attribute_name, bases, dct):
        return (dct.get(attribute_name, None) or
                cls._get_attribute(attribute_name, bases))

    @classmethod
    def update_synthetic_fields(cls, bases, dct):
        if not dct.get('synthetic_fields', None):
            synthetic_attr = cls.get_attribute('synthetic_fields', bases, dct)
            dct['synthetic_fields'] = synthetic_attr or []
        if 'shared' in dct['synthetic_fields']:
            raise exceptions.ObjectActionError(
                action=_('shared attribute switching to synthetic'),
                reason=_('already a synthetic attribute'))
        dct['synthetic_fields'].append('shared')

    @staticmethod
    def subscribe_to_rbac_events(class_instance):
        for e in (events.BEFORE_CREATE, events.BEFORE_UPDATE,
                  events.BEFORE_DELETE):
            registry.subscribe(class_instance.validate_rbac_policy_change,
                               resources.RBAC_POLICY, e)

    @staticmethod
    def validate_existing_attrs(cls_name, dct):
        if 'shared' not in dct['fields']:
            raise KeyError(_('No shared key in %s fields') % cls_name)
        if 'rbac_db_cls' not in dct:
            raise AttributeError(_('rbac_db_cls not found in %s') % cls_name)

    @staticmethod
    def get_replaced_method(orig_method, new_method):
        def func(self):
            return new_method(self, orig_method)
        return func

    @classmethod
    def replace_class_methods_with_hooks(cls, bases, dct):
        methods_replacement_map = {'create': _create_hook,
                                   'update': _update_hook,
                                   'to_dict': _to_dict_hook}
        for orig_method_name, new_method in methods_replacement_map.items():
            orig_method = cls.get_attribute(orig_method_name, bases, dct)
            hook_method = cls.get_replaced_method(orig_method,
                                                  new_method)
            dct[orig_method_name] = hook_method

    def __new__(cls, name, bases, dct):
        cls.validate_existing_attrs(name, dct)
        cls.update_synthetic_fields(bases, dct)
        cls.replace_class_methods_with_hooks(bases, dct)
        klass = type(name, (RbacNeutronDbObjectMixin,) + bases, dct)
        klass.add_extra_filter_name('shared')
        cls.subscribe_to_rbac_events(klass)

        return klass


NeutronRbacObject = with_metaclass(RbacNeutronMetaclass, base.NeutronDbObject)
