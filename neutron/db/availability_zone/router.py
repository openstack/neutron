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

from neutron.callbacks import events
from neutron.callbacks import registry
from neutron.callbacks import resources
from neutron.common import utils
from neutron.db import db_base_plugin_v2
from neutron.db import l3_attrs_db
from neutron.extensions import availability_zone as az_ext
from neutron.extensions import l3


class RouterAvailabilityZoneMixin(l3_attrs_db.ExtraAttributesMixin):
    """Mixin class to enable router's availability zone attributes."""

    def __new__(cls, *args, **kwargs):
        inst = super(RouterAvailabilityZoneMixin, cls).__new__(
            cls, *args, **kwargs)
        registry.subscribe(inst._process_az_request,
                           resources.ROUTER, events.PRECOMMIT_CREATE)
        db_base_plugin_v2.NeutronDbPluginV2.register_dict_extend_funcs(
            l3.ROUTERS, [inst._add_az_to_response])
        return inst

    def _add_az_to_response(self, plugin, router_res, router_db):
        if not utils.is_extension_supported(self, 'router_availability_zone'):
            return
        router_res['availability_zones'] = (
            self.get_router_availability_zones(router_db))

    def _process_az_request(self, resource, event, trigger, context,
                            router, router_db, **kwargs):
        if az_ext.AZ_HINTS in router:
            self.validate_availability_zones(context, 'router',
                                             router[az_ext.AZ_HINTS])
            self.set_extra_attr_value(context, router_db, az_ext.AZ_HINTS,
                                      router[az_ext.AZ_HINTS])
