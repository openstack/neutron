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

from neutron_lib.api.definitions import fip64
from neutron_lib.api import extensions
from neutron_lib import constants as lib_const
from neutron_lib.db import utils as lib_db_utils
from neutron_lib.plugins import directory

from neutron.extensions import floatingip_pools as fip_pools_ext
from neutron.objects import base as base_obj
from neutron.objects import network as net_obj
from neutron.objects import subnet as subnet_obj


class FloatingIPPoolsDbMixin(object):
    """Class to support floating IP pool."""

    _is_v6_supported = None

    @staticmethod
    def _make_floatingip_pool_dict(context, subnet, fields=None):
        res = {'subnet_id': subnet.id,
               'subnet_name': subnet.name,
               'tenant_id': context.tenant_id,
               'network_id': subnet.network_id,
               'cidr': str(subnet.cidr)}

        return lib_db_utils.resource_fields(res, fields)

    def get_floatingip_pools(self, context, filters=None, fields=None,
                             sorts=None, limit=None, marker=None,
                             page_reverse=False):
        """Return information for available floating IP pools"""
        pager = base_obj.Pager(sorts, limit, page_reverse, marker)
        net_ids = [n.network_id
                   for n in net_obj.ExternalNetwork.get_objects(context)]
        # NOTE(hongbin): Use elevated context to make sure we have enough
        # permission to retrieve subnets that are not in current tenant
        # but belongs to external networks shared with current tenant.
        admin_context = context.elevated()
        subnet_objs = subnet_obj.Subnet.get_objects(admin_context,
                                                    _pager=pager,
                                                    network_id=net_ids)
        return [self._make_floatingip_pool_dict(context, obj, fields)
                for obj in subnet_objs
                if (obj.ip_version == lib_const.IP_VERSION_4 or
                    self.is_v6_supported)]

    @property
    def is_v6_supported(self):
        supported = self._is_v6_supported
        if supported is None:
            supported = False
            for plugin in directory.get_plugins().values():
                if extensions.is_extension_supported(plugin, fip64.ALIAS):
                    supported = True
                    break
        self._is_v6_supported = supported

        return supported


class FloatingIPPoolsMixin(FloatingIPPoolsDbMixin,
                           fip_pools_ext.FloatingIPPoolPluginBase):
    pass
