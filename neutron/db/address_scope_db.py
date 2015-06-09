# Copyright (c) 2015 Huawei Technologies Co.,LTD.
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

from oslo_log import log as logging
from oslo_utils import uuidutils
import sqlalchemy as sa
from sqlalchemy.orm import exc

from neutron.db import model_base
from neutron.db import models_v2
from neutron.extensions import address_scope as ext_address_scope

LOG = logging.getLogger(__name__)


class AddressScope(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents a neutron address scope."""

    __tablename__ = "address_scopes"

    name = sa.Column(sa.String(255), nullable=False)
    shared = sa.Column(sa.Boolean, nullable=False)


class AddressScopeDbMixin(ext_address_scope.AddressScopePluginBase):
    """Mixin class to add address scope to db_base_plugin_v2."""

    __native_bulk_support = True

    def _make_address_scope_dict(self, address_scope, fields=None):
        res = {'id': address_scope['id'],
               'name': address_scope['name'],
               'tenant_id': address_scope['tenant_id'],
               'shared': address_scope['shared']}
        return self._fields(res, fields)

    def _get_address_scope(self, context, id):
        try:
            return self._get_by_id(context, AddressScope, id)
        except exc.NoResultFound:
            raise ext_address_scope.AddressScopeNotFound(address_scope_id=id)

    def create_address_scope(self, context, address_scope):
        """Create a address scope."""
        a_s = address_scope['address_scope']
        tenant_id = self._get_tenant_id_for_create(context, a_s)
        address_scope_id = a_s.get('id') or uuidutils.generate_uuid()
        with context.session.begin(subtransactions=True):
            pool_args = {'tenant_id': tenant_id,
                         'id': address_scope_id,
                         'name': a_s['name'],
                         'shared': a_s['shared']}
            address_scope = AddressScope(**pool_args)
            context.session.add(address_scope)

        return self._make_address_scope_dict(address_scope)

    def update_address_scope(self, context, id, address_scope):
        a_s = address_scope['address_scope']
        with context.session.begin(subtransactions=True):
            address_scope = self._get_address_scope(context, id)
            if address_scope.shared and not a_s.get('shared', True):
                reason = _("Shared address scope can't be unshared")
                raise ext_address_scope.AddressScopeUpdateError(
                    address_scope_id=id, reason=reason)
            address_scope.update(a_s)

        return self._make_address_scope_dict(address_scope)

    def get_address_scope(self, context, id, fields=None):
        address_scope = self._get_address_scope(context, id)
        return self._make_address_scope_dict(address_scope, fields)

    def get_address_scopes(self, context, filters=None, fields=None,
                           sorts=None, limit=None, marker=None,
                           page_reverse=False):
        marker_obj = self._get_marker_obj(context, 'addrscope', limit, marker)
        collection = self._get_collection(context, AddressScope,
                                          self._make_address_scope_dict,
                                          filters=filters, fields=fields,
                                          sorts=sorts,
                                          limit=limit,
                                          marker_obj=marker_obj,
                                          page_reverse=page_reverse)
        return collection

    def get_address_scopes_count(self, context, filters=None):
        return self._get_collection_count(context, AddressScope,
                                          filters=filters)

    def delete_address_scope(self, context, id):
        with context.session.begin(subtransactions=True):
            address_scope = self._get_address_scope(context, id)
            context.session.delete(address_scope)
