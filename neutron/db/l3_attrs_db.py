# Copyright (c) 2014 OpenStack Foundation.  All rights reserved.
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

from neutron.common import _deprecate
from neutron.db import db_base_plugin_v2
from neutron.db.models import l3_attrs
from neutron.extensions import l3

_deprecate._moved_global('RouterExtraAttributes', new_module=l3_attrs)


class ExtraAttributesMixin(object):
    """Mixin class to enable router's extra attributes."""

    extra_attributes = []

    def _extend_extra_router_dict(self, router_res, router_db):
        extra_attrs = router_db['extra_attributes'] or {}
        for attr in self.extra_attributes:
            name = attr['name']
            default = attr['default']
            router_res[name] = (
                extra_attrs[name] if name in extra_attrs else default)

    def _get_extra_attributes(self, router, extra_attributes):
        return (dict((attr['name'],
                      router.get(attr['name'], attr['default']))
                for attr in extra_attributes))

    def _process_extra_attr_router_create(
        self, context, router_db, router_req):
        kwargs = self._get_extra_attributes(router_req, self.extra_attributes)
        # extra_attributes reference is populated via backref
        if not router_db['extra_attributes']:
            attributes_db = l3_attrs.RouterExtraAttributes(
                router_id=router_db['id'], **kwargs)
            context.session.add(attributes_db)
            router_db['extra_attributes'] = attributes_db
        else:
            # The record will exist if RouterExtraAttributes model's
            # attributes are added with db migrations over time
            router_db['extra_attributes'].update(kwargs)

    db_base_plugin_v2.NeutronDbPluginV2.register_dict_extend_funcs(
        l3.ROUTERS, ['_extend_extra_router_dict'])


_deprecate._MovedGlobals()
