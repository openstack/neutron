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

from sqlalchemy.orm import exc

from neutron.callbacks import events
from neutron.callbacks import exceptions as c_exc
from neutron.callbacks import registry
from neutron.common import exceptions as n_exc
from neutron.db import common_db_mixin
from neutron.db import rbac_db_models as models
from neutron.extensions import rbac as ext_rbac

# resource name using in callbacks
RBAC_POLICY = 'rbac-policy'


class RbacPluginMixin(common_db_mixin.CommonDbMixin):
    """Plugin mixin that implements the RBAC DB operations."""

    object_type_cache = {}
    supported_extension_aliases = ['rbac-policies']

    def create_rbac_policy(self, context, rbac_policy):
        e = rbac_policy['rbac_policy']
        try:
            registry.notify(RBAC_POLICY, events.BEFORE_CREATE, self,
                            context=context, object_type=e['object_type'],
                            policy=e)
        except c_exc.CallbackFailure as e:
            raise n_exc.InvalidInput(error_message=e)
        dbmodel = models.get_type_model_map()[e['object_type']]
        with context.session.begin(subtransactions=True):
            db_entry = dbmodel(object_id=e['object_id'],
                               target_tenant=e['target_tenant'],
                               action=e['action'],
                               tenant_id=e['tenant_id'])
            context.session.add(db_entry)
        return self._make_rbac_policy_dict(db_entry)

    def _make_rbac_policy_dict(self, db_entry, fields=None):
        res = {f: db_entry[f] for f in ('id', 'tenant_id', 'target_tenant',
                                        'action', 'object_id')}
        res['object_type'] = db_entry.object_type
        return self._fields(res, fields)

    def update_rbac_policy(self, context, id, rbac_policy):
        pol = rbac_policy['rbac_policy']
        entry = self._get_rbac_policy(context, id)
        object_type = entry['object_type']
        try:
            registry.notify(RBAC_POLICY, events.BEFORE_UPDATE, self,
                            context=context, policy=entry,
                            object_type=object_type, policy_update=pol)
        except c_exc.CallbackFailure as ex:
            raise ext_rbac.RbacPolicyInUse(object_id=entry['object_id'],
                                           details=ex)
        with context.session.begin(subtransactions=True):
            entry.update(pol)
        return self._make_rbac_policy_dict(entry)

    def delete_rbac_policy(self, context, id):
        entry = self._get_rbac_policy(context, id)
        object_type = entry['object_type']
        try:
            registry.notify(RBAC_POLICY, events.BEFORE_DELETE, self,
                            context=context, object_type=object_type,
                            policy=entry)
        except c_exc.CallbackFailure as ex:
            raise ext_rbac.RbacPolicyInUse(object_id=entry['object_id'],
                                           details=ex)
        with context.session.begin(subtransactions=True):
            context.session.delete(entry)
        self.object_type_cache.pop(id, None)

    def _get_rbac_policy(self, context, id):
        object_type = self._get_object_type(context, id)
        dbmodel = models.get_type_model_map()[object_type]
        try:
            return self._model_query(context,
                                     dbmodel).filter(dbmodel.id == id).one()
        except exc.NoResultFound:
            raise ext_rbac.RbacPolicyNotFound(id=id, object_type=object_type)

    def get_rbac_policy(self, context, id, fields=None):
        return self._make_rbac_policy_dict(
            self._get_rbac_policy(context, id), fields=fields)

    def get_rbac_policies(self, context, filters=None, fields=None,
                          sorts=None, limit=None, page_reverse=False):
        model = common_db_mixin.UnionModel(
            models.get_type_model_map(), 'object_type')
        return self._get_collection(
            context, model, self._make_rbac_policy_dict, filters=filters,
            fields=fields, sorts=sorts, limit=limit, page_reverse=page_reverse)

    def _get_object_type(self, context, entry_id):
        """Scans all RBAC tables for an ID to figure out the type.

        This will be an expensive operation as the number of RBAC tables grows.
        The result is cached since object types cannot be updated for a policy.
        """
        if entry_id in self.object_type_cache:
            return self.object_type_cache[entry_id]
        for otype, model in models.get_type_model_map().items():
            if (context.session.query(model).
                    filter(model.id == entry_id).first()):
                self.object_type_cache[entry_id] = otype
                return otype
        raise ext_rbac.RbacPolicyNotFound(id=entry_id, object_type='unknown')
