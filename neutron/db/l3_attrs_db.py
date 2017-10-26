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

from neutron_lib.api.definitions import l3 as l3_apidef
from neutron_lib.api.validators import availability_zone as az_validator
from oslo_config import cfg

from neutron._i18n import _
from neutron.db import _resource_extend as resource_extend
from neutron.db.models import l3_attrs


def get_attr_info():
    """Returns api visible attr names and their default values."""
    return {'distributed': {'default': cfg.CONF.router_distributed},
            'ha': {'default': cfg.CONF.l3_ha},
            'ha_vr_id': {'default': 0},
            'availability_zone_hints': {
                'default': '[]',
                'transform_to_db': az_validator.convert_az_list_to_string,
                'transform_from_db': az_validator.convert_az_string_to_list}
            }


@resource_extend.has_resource_extenders
class ExtraAttributesMixin(object):
    """Mixin class to enable router's extra attributes."""

    @staticmethod
    @resource_extend.extends([l3_apidef.ROUTERS])
    def _extend_extra_router_dict(router_res, router_db):
        extra_attrs = router_db['extra_attributes'] or {}
        for name, info in get_attr_info().items():
            from_db = info.get('transform_from_db', lambda x: x)
            router_res[name] = from_db(extra_attrs.get(name, info['default']))

    def _ensure_extra_attr_model(self, context, router_db):
        if not router_db['extra_attributes']:
            kwargs = {k: v['default'] for k, v in get_attr_info().items()}
            kwargs['router_id'] = router_db['id']
            new = l3_attrs.RouterExtraAttributes(**kwargs)
            context.session.add(new)
            router_db['extra_attributes'] = new

    def set_extra_attr_value(self, context, router_db, key, value):
        # set a single value explicitly
        with context.session.begin(subtransactions=True):
            if key in get_attr_info():
                info = get_attr_info()[key]
                to_db = info.get('transform_to_db', lambda x: x)
                self._ensure_extra_attr_model(context, router_db)
                router_db['extra_attributes'].update({key: to_db(value)})
                return
            raise RuntimeError(_("Tried to set a key '%s' that doesn't exist "
                                 "in the extra attributes table.") % key)
