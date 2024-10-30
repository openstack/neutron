# Copyright (c) 2015 Mirantis, Inc.
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

from neutron_lib.callbacks import events
from neutron_lib.callbacks import exceptions as c_exc
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib.db import api as db_api
from neutron_lib.db import utils as db_utils
from neutron_lib import exceptions as n_exc
from neutron_lib.objects import exceptions as o_exc

from neutron.extensions import rbac as ext_rbac
from neutron.objects import base as base_obj
from neutron.objects import rbac as rbac_obj


class RbacPluginMixin:
    """Plugin mixin that implements the RBAC DB operations."""

    object_type_cache = {}
    supported_extension_aliases = ['rbac-policies']

    @db_api.retry_if_session_inactive()
    def create_rbac_policy(self, context, rbac_policy):
        e = rbac_policy['rbac_policy']
        # NOTE(ralonsoh): remove this conversion when "bp/keystone-v3" is
        # widely implemented in all OpenStack projects.
        try:
            e['target_project'] = e.pop('target_tenant')
        except KeyError:
            pass
        try:
            registry.publish(resources.RBAC_POLICY, events.BEFORE_CREATE, self,
                             payload=events.DBEventPayload(
                                 context, request_body=e,
                                 metadata={'object_type': e['object_type']}))
        except c_exc.CallbackFailure as e:
            raise n_exc.InvalidInput(error_message=e)
        rbac_class = (
            rbac_obj.RBACBaseObject.get_type_class_map()[e['object_type']])
        try:
            rbac_args = {'project_id': e['project_id'],
                         'object_id': e['object_id'],
                         'action': e['action'],
                         'target_project': e['target_project']}
            _rbac_obj = rbac_class(context, **rbac_args)
            _rbac_obj.create()
        except o_exc.NeutronDbObjectDuplicateEntry:
            raise ext_rbac.DuplicateRbacPolicy()
        return self._make_rbac_policy_dict(_rbac_obj)

    @staticmethod
    def _make_rbac_policy_dict(entry, fields=None):
        res = {f: entry[f] for f in ('id', 'project_id', 'target_project',
                                     'action', 'object_id')}
        # TODO(ralonsoh): remove once all calls refer to "target_project"
        res['target_tenant'] = res['target_project']
        res['object_type'] = entry.db_model.object_type
        return db_utils.resource_fields(res, fields)

    @db_api.retry_if_session_inactive()
    def update_rbac_policy(self, context, id, rbac_policy):
        pol = rbac_policy['rbac_policy']
        # NOTE(ralonsoh): remove this conversion when "bp/keystone-v3" is
        # widely implemented in all OpenStack projects.
        try:
            pol['target_project'] = pol.pop('target_tenant')
        except KeyError:
            pass
        entry = self._get_rbac_policy(context, id)
        object_type = entry.db_model.object_type
        try:
            registry.publish(resources.RBAC_POLICY, events.BEFORE_UPDATE, self,
                             payload=events.DBEventPayload(
                                 context, request_body=pol,
                                 states=(entry,), resource_id=id,
                                 metadata={'object_type': object_type}))
        except c_exc.CallbackFailure as ex:
            raise ext_rbac.RbacPolicyInUse(object_id=entry.object_id,
                                           details=ex)
        entry.update_fields(pol)
        entry.update()
        return self._make_rbac_policy_dict(entry)

    @db_api.retry_if_session_inactive()
    def delete_rbac_policy(self, context, id):
        entry = self._get_rbac_policy(context, id)
        object_type = entry.db_model.object_type
        try:
            registry.publish(resources.RBAC_POLICY, events.BEFORE_DELETE, self,
                             payload=events.DBEventPayload(
                                 context, states=(entry,), resource_id=id,
                                 metadata={'object_type': object_type}))
        except c_exc.CallbackFailure as ex:
            raise ext_rbac.RbacPolicyInUse(object_id=entry.object_id,
                                           details=ex)
        # make a dict copy because deleting the entry will nullify its
        # object_id link to network
        entry_dict = entry.to_dict()
        entry.delete()
        registry.publish(resources.RBAC_POLICY, events.AFTER_DELETE, self,
                         payload=events.DBEventPayload(
                             context, states=(entry_dict,), resource_id=id,
                             metadata={'object_type': object_type}))
        self.object_type_cache.pop(id, None)

    def _get_rbac_policy(self, context, id):
        object_type = self._get_object_type(context, id)
        rbac_class = rbac_obj.RBACBaseObject.get_type_class_map()[object_type]
        _rbac_obj = rbac_class.get_object(context, id=id)
        if not _rbac_obj:
            raise ext_rbac.RbacPolicyNotFound(id=id, object_type=object_type)
        return _rbac_obj

    @db_api.retry_if_session_inactive()
    def get_rbac_policy(self, context, id, fields=None):
        return self._make_rbac_policy_dict(
            self._get_rbac_policy(context, id), fields=fields)

    @db_api.retry_if_session_inactive()
    def get_rbac_policies(self, context, filters=None, fields=None,
                          sorts=None, limit=None, page_reverse=False):
        pager = base_obj.Pager(sorts, limit, page_reverse)
        filters = filters or {}
        object_types = filters.pop('object_type', None)
        # NOTE(ralonsoh): remove this conversion when "bp/keystone-v3" is
        # widely implemented in all OpenStack projects.
        try:
            filters['target_project'] = filters.pop('target_tenant')
        except KeyError:
            pass
        rbac_classes_to_query = [
            o for t, o in rbac_obj.RBACBaseObject.get_type_class_map().items()
            if not object_types or t in object_types]
        rbac_objs = []
        for rbac_class in rbac_classes_to_query:
            rbac_objs += rbac_class.get_objects(context, _pager=pager,
                                                **filters)
        return [self._make_rbac_policy_dict(_rbac_obj, fields)
                for _rbac_obj in rbac_objs]

    def _get_object_type(self, context, entry_id):
        """Scans all RBAC tables for an ID to figure out the type.

        This will be an expensive operation as the number of RBAC tables grows.
        The result is cached since object types cannot be updated for a policy.
        """
        if entry_id in self.object_type_cache:
            return self.object_type_cache[entry_id]
        for otype, rbac_class in \
                rbac_obj.RBACBaseObject.get_type_class_map().items():
            if rbac_class.count(context, id=entry_id):
                self.object_type_cache[entry_id] = otype
                return otype
        raise ext_rbac.RbacPolicyNotFound(id=entry_id, object_type='unknown')
