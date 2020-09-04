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

import netaddr
from neutron_lib import constants
from neutron_lib.db import resource_extend
from neutron_lib.db import utils as db_utils
from neutron_lib.exceptions import address_group as ag_exc
from oslo_utils import uuidutils

from neutron.extensions import address_group as ag_ext
from neutron.objects import address_group as ag_obj
from neutron.objects import base as base_obj


@resource_extend.has_resource_extenders
class AddressGroupDbMixin(ag_ext.AddressGroupPluginBase):
    """Mixin class to add address group to db_base_plugin_v2."""

    __native_bulk_support = True

    @staticmethod
    def _make_address_group_dict(address_group, fields=None):
        res = address_group.to_dict()
        res['addresses'] = [str(addr_assoc['address'])
                            for addr_assoc in address_group['addresses']]
        return db_utils.resource_fields(res, fields)

    def _get_address_group(self, context, id):
        obj = ag_obj.AddressGroup.get_object(context, id=id)
        if obj is None:
            raise ag_exc.AddressGroupNotFound(address_group_id=id)
        return obj

    def _dedup_and_compare_addresses(self, ag_obj, req_addrs):
        ag_addrs = set(self._make_address_group_dict(
            ag_obj, fields=['addresses'])['addresses'])
        req_addrs = set(str(netaddr.IPNetwork(addr)) for addr in req_addrs)
        addrs_in_ag = []
        addrs_not_in_ag = []
        for req_addr in req_addrs:
            if req_addr in ag_addrs:
                addrs_in_ag.append(req_addr)
            else:
                addrs_not_in_ag.append(req_addr)
        return addrs_in_ag, addrs_not_in_ag

    def add_addresses(self, context, address_group_id, addresses):
        ag = self._get_address_group(context, address_group_id)
        addrs_in_ag, addrs_not_in_ag = self._dedup_and_compare_addresses(
            ag, addresses['addresses'])
        if addrs_in_ag:
            raise ag_exc.AddressesAlreadyExist(
                addresses=addrs_in_ag, address_group_id=address_group_id)
        for addr in addrs_not_in_ag:
            addr = netaddr.IPNetwork(addr)
            args = {'address_group_id': address_group_id,
                    'address': addr}
            addr_assoc = ag_obj.AddressAssociation(context, **args)
            addr_assoc.create()
        ag.update()  # reload synthetic fields
        return {'address_group': self._make_address_group_dict(ag)}

    def remove_addresses(self, context, address_group_id, addresses):
        ag = self._get_address_group(context, address_group_id)
        addrs_in_ag, addrs_not_in_ag = self._dedup_and_compare_addresses(
            ag, addresses['addresses'])
        if addrs_not_in_ag:
            raise ag_exc.AddressesNotFound(
                addresses=addrs_not_in_ag, address_group_id=address_group_id)
        for addr in addrs_in_ag:
            ag_obj.AddressAssociation.delete_objects(
                context, address_group_id=address_group_id, address=addr)
        ag.update()  # reload synthetic fields
        return {'address_group': self._make_address_group_dict(ag)}

    def create_address_group(self, context, address_group):
        """Create an address group."""
        fields = address_group['address_group']
        args = {'project_id': fields['tenant_id'],
                'id': uuidutils.generate_uuid(),
                'name': fields['name'],
                'description': fields['description']}
        ag = ag_obj.AddressGroup(context, **args)
        ag.create()
        if fields.get('addresses') is not constants.ATTR_NOT_SPECIFIED:
            self.add_addresses(context, ag.id, fields)
        ag.update()  # reload synthetic fields
        return self._make_address_group_dict(ag)

    def update_address_group(self, context, id, address_group):
        fields = address_group['address_group']
        ag = self._get_address_group(context, id)
        ag.update_fields(fields)
        ag.update()
        return self._make_address_group_dict(ag)

    def get_address_group(self, context, id, fields=None):
        ag = self._get_address_group(context, id)
        return self._make_address_group_dict(ag, fields)

    def get_address_groups(self, context, filters=None, fields=None,
                           sorts=None, limit=None, marker=None,
                           page_reverse=False):
        pager = base_obj.Pager(sorts, limit, page_reverse, marker)
        address_groups = ag_obj.AddressGroup.get_objects(
            context, _pager=pager, **filters)
        return [
            self._make_address_group_dict(addr_group, fields)
            for addr_group in address_groups
        ]

    def delete_address_group(self, context, id):
        address_group = self._get_address_group(context, id)
        address_group.delete()
